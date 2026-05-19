//! Kernel-side page table construction with user-accessible mappings.
//!
//! Hyperlight's `paging::map_region` is hard-coded to `user_accessible
//! = false` — fine for kernel pages but unusable for ring-3 PVM
//! programs. We build our own page tables so the kernel can map
//! per-invocation program memory and JIT'd code with the
//! User/Supervisor bit set.
//!
//! ## Layout
//!
//! 4-level paging (PML4 → PDPT → PD → PT) for 4 KiB pages:
//!
//! ```text
//!   virt[47:39] → PML4 entry
//!   virt[38:30] → PDPT entry
//!   virt[29:21] → PD   entry
//!   virt[20:12] → PT   entry
//!   virt[11: 0] → byte offset in page
//! ```
//!
//! Each table is 4 KiB (512 × 8-byte PTEs); fresh tables are allocated
//! through the global heap (talc), which lives in Hyperlight's
//! identity-mapped low-memory region. `PageTable` owns every table it
//! allocates and frees them on drop.
//!
//! ## PA ↔ VA translation
//!
//! Three address-translation regimes (Stage F kernel relocation):
//!
//! * **Kernel half (code, PEB, heap, init-data, talc allocations)**
//!   lives at high VA `[KERNEL_HIGH_BASE, scratch_base_gva)` and is
//!   backed by low GPAs `[KERNEL_BASE_GPA, scratch_base_gpa)`. The
//!   linker (`link.x`) places the binary at `KERNEL_HIGH_BASE =
//!   0xFFFFFFFF80000000`; the host's initial PT
//!   (`rust/nub-host-kvm/src/sandbox/snapshot.rs::from_env`) installs
//!   the mapping `gva = KERNEL_HIGH_BASE + (gpa - KERNEL_BASE_GPA)`.
//! * **Scratch region (allocations from `prim_alloc::alloc_phys_pages`,
//!   TSS/IDT, the existing kernel PML4)** is mapped at high VA via a
//!   constant offset:
//!   ```text
//!     gva = scratch_base_gva + (gpa - scratch_base_gpa)
//!   ```
//! * **User half (low VA, 0..512 GiB)** is owned by the per-invocation
//!   PT we build for ring-3 PVM programs; ring-0 paging helpers below
//!   return `None` for these addresses.

#![cfg(target_os = "none")]

extern crate alloc;

use alloc::alloc::{alloc_zeroed, dealloc};
use alloc::vec::Vec;
use core::alloc::Layout;
use core::cell::RefCell;
use core::ptr::NonNull;

use hyperlight_guest::layout::{scratch_base_gpa, scratch_base_gva};

/// 4 KiB page size — the unit of alignment for page-aligned
/// allocations (page tables, JIT exec pages, etc.).
pub const PAGE_SIZE: usize = 4096;

/// Low GPA where the host loads the kernel ELF. Matches
/// `SandboxMemoryLayout::BASE_ADDRESS` in `nub-host-kvm`.
const KERNEL_BASE_GPA: u64 = 0x1000;
/// High GVA the kernel is linked at. Matches the `. =` directive in
/// [`rust/nub-arch-x86/link.x`](../link.x) and
/// `SandboxMemoryLayout::KERNEL_HIGH_BASE` in `nub-host-kvm`.
const KERNEL_HIGH_BASE: u64 = 0xFFFF_FFFF_8000_0000;

/// PTE flag bits.
pub mod flag {
    /// Present. Required for any valid mapping.
    pub const P: u64 = 1 << 0;
    /// Read/Write. Allows writes; if clear, page is read-only.
    pub const RW: u64 = 1 << 1;
    /// User/Supervisor. Set → ring 3 can access; clear → ring 0 only.
    pub const US: u64 = 1 << 2;
    /// No-Execute (bit 63). Set → instruction fetch faults.
    pub const NX: u64 = 1 << 63;
}

/// Mask covering the physical-address bits of a PTE (bits 12..51).
const PA_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Convert a kernel VA to its physical address. Three regimes:
/// scratch (high VA, offset to scratch GPA), kernel half (high VA in
/// `[KERNEL_HIGH_BASE, scratch_base_gva)`, offset to low GPA), and
/// low VA (user-half, owned by per-invocation PT — returns `None`).
pub fn va_to_pa(va: u64) -> Option<u64> {
    let scratch_gva = scratch_base_gva();
    if va >= scratch_gva {
        Some(scratch_base_gpa() + (va - scratch_gva))
    } else if va >= KERNEL_HIGH_BASE {
        Some(KERNEL_BASE_GPA + (va - KERNEL_HIGH_BASE))
    } else {
        None
    }
}

/// Convert a PA to its kernel VA. The dual of [`va_to_pa`].
pub fn pa_to_va(pa: u64) -> Option<u64> {
    let scratch_gpa = scratch_base_gpa();
    if pa >= scratch_gpa {
        Some(scratch_base_gva() + (pa - scratch_gpa))
    } else if pa >= KERNEL_BASE_GPA {
        Some(KERNEL_HIGH_BASE + (pa - KERNEL_BASE_GPA))
    } else {
        None
    }
}

/// Permission preset for a mapping.
#[derive(Clone, Copy, Debug)]
pub struct Perm {
    pub writable: bool,
    pub user: bool,
    pub executable: bool,
}

impl Perm {
    pub const fn user_rw() -> Self {
        Self {
            writable: true,
            user: true,
            executable: false,
        }
    }
    pub const fn user_rx() -> Self {
        Self {
            writable: false,
            user: true,
            executable: true,
        }
    }
    pub const fn user_ro() -> Self {
        Self {
            writable: false,
            user: true,
            executable: false,
        }
    }
    #[allow(dead_code)] // available for kernel-only mappings
    pub const fn kernel_rw() -> Self {
        Self {
            writable: true,
            user: false,
            executable: false,
        }
    }

    /// Encode as the low-bit + high-bit flags of a leaf PTE.
    fn pte_flags(&self) -> u64 {
        let mut bits = flag::P;
        if self.writable {
            bits |= flag::RW;
        }
        if self.user {
            bits |= flag::US;
        }
        if !self.executable {
            bits |= flag::NX;
        }
        bits
    }
}

/// 4 KiB page table (512 × 8-byte entries).
type Table = [u64; 512];

const TABLE_LAYOUT: Layout = unsafe { Layout::from_size_align_unchecked(PAGE_SIZE, PAGE_SIZE) };

fn alloc_table() -> Option<NonNull<Table>> {
    // SAFETY: `TABLE_LAYOUT` is a non-zero, well-formed Layout.
    let ptr = unsafe { alloc_zeroed(TABLE_LAYOUT) };
    NonNull::new(ptr as *mut Table)
}

/// Per-invocation page table. Owns its PML4 plus every intermediate
/// table allocated via [`PageTable::map`]. All backing pages are freed
/// when the `PageTable` is dropped.
pub struct PageTable {
    pml4: NonNull<Table>,
    /// All allocated tables (PML4 + intermediates). Freed in Drop.
    owned: RefCell<Vec<NonNull<Table>>>,
}

impl PageTable {
    /// Allocate a fresh PML4, copy every kernel-half PML4 entry from
    /// the current CR3 so kernel-half mappings stay valid after a CR3
    /// switch, and return the new table.
    ///
    /// Note: this *shallow-copies* PML4 entries — descendant tables
    /// are shared with the original. Per-invocation isolation only
    /// requires that *new* mappings (the user-half entries we add)
    /// don't share with the kernel's existing pages, which they don't
    /// because they live in different PML4 slots.
    pub fn new() -> Option<Self> {
        let pml4_ptr = alloc_table()?;
        let cr3_pa = read_cr3() & PA_MASK;
        let src_va = pa_to_va(cr3_pa)?;
        let src_pml4 = src_va as *const Table;
        // SAFETY: src_va is the kernel VA of the current PML4; 4 KiB
        // of bytes are valid. pml4_ptr was just allocated.
        unsafe {
            core::ptr::copy_nonoverlapping(src_pml4, pml4_ptr.as_ptr(), 1);
        }
        let mut owned = Vec::with_capacity(8);
        owned.push(pml4_ptr);
        Some(Self {
            pml4: pml4_ptr,
            owned: RefCell::new(owned),
        })
    }

    /// CR3 value to load (physical address of the PML4, low 12 bits clear).
    pub fn cr3(&self) -> Option<u64> {
        va_to_pa(self.pml4.as_ptr() as u64)
    }

    /// Map `len` bytes at virtual address `virt` to physical address
    /// `phys` with the given permissions. `virt`, `phys`, and `len`
    /// must each be 4 KiB-aligned. Allocates intermediate tables as
    /// needed; an existing mapping at the same VA is overwritten.
    pub fn map(&mut self, virt: u64, phys: u64, len: u64, perm: Perm) -> Option<()> {
        assert!(virt.is_multiple_of(PAGE_SIZE as u64));
        assert!(phys.is_multiple_of(PAGE_SIZE as u64));
        assert!(len.is_multiple_of(PAGE_SIZE as u64));

        let mut va = virt;
        let mut pa = phys;
        let end = virt + len;
        while va < end {
            self.map_one(va, pa, perm)?;
            va += PAGE_SIZE as u64;
            pa += PAGE_SIZE as u64;
        }
        Some(())
    }

    /// Map a single 4 KiB page.
    fn map_one(&self, va: u64, pa: u64, perm: Perm) -> Option<()> {
        let idx4 = ((va >> 39) & 0x1FF) as usize;
        let idx3 = ((va >> 30) & 0x1FF) as usize;
        let idx2 = ((va >> 21) & 0x1FF) as usize;
        let idx1 = ((va >> 12) & 0x1FF) as usize;

        // Inner-table PTE flags: present + writable + user (always set
        // so the leaf's flag is the decisive permission).
        let inner_flags = flag::P | flag::RW | flag::US;

        // SAFETY: self.pml4 is a valid 4 KiB-aligned table this PT owns.
        let pml4 = unsafe { &mut *self.pml4.as_ptr() };
        let pdpt = self.ensure_inner(&mut pml4[idx4], inner_flags)?;

        // SAFETY: ensure_inner returned a freshly allocated or pre-existing
        // table; the pointer is a kernel VA.
        let pdpt = unsafe { &mut *pdpt };
        let pd = self.ensure_inner(&mut pdpt[idx3], inner_flags)?;

        let pd = unsafe { &mut *pd };
        let pt = self.ensure_inner(&mut pd[idx2], inner_flags)?;

        let pt = unsafe { &mut *pt };
        pt[idx1] = (pa & PA_MASK) | perm.pte_flags();
        Some(())
    }

    /// Ensure that the inner-table entry at `entry` has a backing
    /// table. If it does, return its address (after re-asserting the
    /// requested inner flags). Otherwise, allocate a fresh table,
    /// install it in `entry`, and return its address.
    ///
    /// Returns `None` if `entry` is a leaf (large-page) mapping — we
    /// can't split it without losing the existing mapping. Callers
    /// must pick a VA whose ancestors aren't already large-page
    /// leaves.
    fn ensure_inner(&self, entry: &mut u64, inner_flags: u64) -> Option<*mut Table> {
        const PS: u64 = 1 << 7;
        if *entry & flag::P != 0 {
            if *entry & PS != 0 {
                return None;
            }
            let pa = *entry & PA_MASK;
            *entry |= inner_flags;
            let va = pa_to_va(pa)?;
            return Some(va as *mut Table);
        }
        let new_table = alloc_table()?;
        self.owned.borrow_mut().push(new_table);
        let va = new_table.as_ptr() as u64;
        let pa = va_to_pa(va)?;
        *entry = (pa & PA_MASK) | inner_flags;
        Some(new_table.as_ptr())
    }
}

impl Drop for PageTable {
    fn drop(&mut self) {
        for table in self.owned.borrow_mut().drain(..) {
            // SAFETY: every entry in `owned` came from `alloc_table`
            // (same Layout); we hand it back exactly once.
            unsafe {
                dealloc(table.as_ptr() as *mut u8, TABLE_LAYOUT);
            }
        }
    }
}

/// Install a kernel-mode (no USER bit) page-table mapping in the
/// **currently active** PML4. The mapping persists across
/// per-invocation [`PageTable::new`] calls because that constructor
/// shallow-copies the active PML4 — any descendant tables we install
/// here are then shared with every per-invocation PT.
///
/// Used at guest boot to map the host-installed state cache region
/// into the kernel half of the address space (so the guest's
/// kernel-mode RPC dispatcher can read cache memory). The 4 KiB-page
/// granularity wastes ~2 MiB on intermediate tables for a 1 GiB
/// mapping, but the cost is paid once at boot.
///
/// `virt`, `phys`, and `len` must be 4 KiB-aligned. Intermediate
/// tables are talc-allocated and never freed (intentional — the
/// mapping is permanent).
///
/// # Safety
///
/// The current CR3 must point at a writable PML4 in talc memory
/// (the kernel's boot PML4). The mapped GPA range must point at
/// host-installed physical memory.
pub unsafe fn install_persistent_kernel_mapping(
    virt: u64,
    phys: u64,
    len: u64,
    perm: Perm,
) -> Option<()> {
    assert!(virt.is_multiple_of(PAGE_SIZE as u64));
    assert!(phys.is_multiple_of(PAGE_SIZE as u64));
    assert!(len.is_multiple_of(PAGE_SIZE as u64));

    let cr3_pa = read_cr3() & PA_MASK;
    let pml4_va = pa_to_va(cr3_pa)?;
    let pml4 = pml4_va as *mut Table;

    let mut va = virt;
    let mut pa = phys;
    let end = virt + len;
    while va < end {
        unsafe {
            map_one_in_pml4(pml4, va, pa, perm)?;
        }
        va += PAGE_SIZE as u64;
        pa += PAGE_SIZE as u64;
    }
    Some(())
}

/// Walk + extend a foreign PML4 to install one 4 KiB-page mapping.
/// Allocates intermediate tables via [`alloc_table`]; never frees
/// them (caller's responsibility — for [`install_persistent_kernel_mapping`]
/// they're intentionally leaked into the kernel's page-table tree).
unsafe fn map_one_in_pml4(pml4: *mut Table, va: u64, pa: u64, perm: Perm) -> Option<()> {
    let idx4 = ((va >> 39) & 0x1FF) as usize;
    let idx3 = ((va >> 30) & 0x1FF) as usize;
    let idx2 = ((va >> 21) & 0x1FF) as usize;
    let idx1 = ((va >> 12) & 0x1FF) as usize;
    let inner_flags = flag::P | flag::RW | flag::US;

    let pdpt = unsafe { ensure_inner_foreign(&mut (*pml4)[idx4], inner_flags)? };
    let pd = unsafe { ensure_inner_foreign(&mut (*pdpt)[idx3], inner_flags) }?;
    let pt = unsafe { ensure_inner_foreign(&mut (*pd)[idx2], inner_flags) }?;
    unsafe {
        (*pt)[idx1] = (pa & PA_MASK) | perm.pte_flags();
    }
    Some(())
}

unsafe fn ensure_inner_foreign(entry: &mut u64, inner_flags: u64) -> Option<*mut Table> {
    const PS: u64 = 1 << 7;
    if *entry & flag::P != 0 {
        if *entry & PS != 0 {
            return None;
        }
        let pa = *entry & PA_MASK;
        *entry |= inner_flags;
        let va = pa_to_va(pa)?;
        return Some(va as *mut Table);
    }
    let new_table = alloc_table()?;
    let va = new_table.as_ptr() as u64;
    let pa = va_to_pa(va)?;
    *entry = (pa & PA_MASK) | inner_flags;
    Some(new_table.as_ptr())
}

/// Read CR3. Returns the physical address of the current PML4 (low
/// 12 bits are PCID flags).
pub fn read_cr3() -> u64 {
    let cr3: u64;
    // SAFETY: reading CR3 is a privileged but harmless operation at ring 0.
    unsafe {
        core::arch::asm!("mov {0}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    cr3
}

/// Write CR3. Loads `value` as the new page-table pointer + flushes
/// the TLB for non-global entries.
///
/// # Safety
/// `value` must be the physical address of a valid PML4 whose kernel-
/// half PML4 entries cover the kernel's current code/stack/heap VAs;
/// otherwise the next instruction fetch / stack access will fault.
pub unsafe fn write_cr3(value: u64) {
    // SAFETY: caller asserted preconditions.
    unsafe {
        core::arch::asm!("mov cr3, {0}", in(reg) value, options(nostack, preserves_flags));
    }
}

/// TLB flush via CR3 self-swap (full flush of non-global entries).
#[allow(dead_code)]
pub fn flush_tlb() {
    // SAFETY: rewriting CR3 with its current value is observably a
    // TLB flush.
    unsafe {
        let cr3 = read_cr3();
        write_cr3(cr3);
    }
}
