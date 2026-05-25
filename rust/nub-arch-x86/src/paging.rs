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
//! Four address-translation regimes (Stage F kernel relocation):
//!
//! * **Kernel half (code, PEB, heap, init-data, talc allocations)**
//!   lives at high VA `[kernel_base_va(), scratch_base_gva)` and is
//!   backed by low GPAs `[KERNEL_BASE_GPA, scratch_base_gpa)`. The
//!   binary is PIE; `kernel_base_va()` reads the linker symbol
//!   `_kernel_start` (PIE-relocated by the host at load time to
//!   `guest_va_base() + KERNEL_OFFSET`) — host and guest both derive
//!   the same value, so `gva = kernel_base_va() + (gpa - KERNEL_BASE_GPA)`.
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

unsafe extern "C" {
    /// Linker-provided symbol marking the start of the kernel image.
    /// Defined by `_kernel_start = .;` in [`link.x`](../link.x). With
    /// PIE output, this resolves at runtime to the actual GVA the
    /// host loaded the kernel at — `kernel_base_va() + KERNEL_OFFSET`
    /// in host parlance — making the kernel half VA-relocatable.
    safe static _kernel_start: u8;
}

/// Runtime GVA at which the kernel image was loaded. Equivalent to
/// `guest_va_base() + KERNEL_OFFSET` on the host side. Lazily reads
/// the linker symbol; PIE relocation makes this the actual base.
#[inline]
fn kernel_base_va() -> u64 {
    &_kernel_start as *const u8 as u64
}

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

/// Convert a kernel VA to its physical address. Three regimes (see
/// module doc): scratch (high VA), kernel half (low VA past
/// `kernel_base_va()`), user half (returns `None`).
pub fn va_to_pa(va: u64) -> Option<u64> {
    let scratch_gva = scratch_base_gva();
    let kernel_base = kernel_base_va();
    if va >= scratch_gva {
        Some(scratch_base_gpa() + (va - scratch_gva))
    } else if va >= kernel_base {
        Some(KERNEL_BASE_GPA + (va - kernel_base))
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
        Some(kernel_base_va() + (pa - KERNEL_BASE_GPA))
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

/// Per-Image template page-directory subtree. Owns a single PD page
/// covering 1 GiB of VA space and all PT pages it references, with
/// leaf PTEs prefilled to point at the Image's arena pages.
///
/// Multiple per-call [`PageTable`]s install this template via
/// [`PageTable::install_borrowed_pd`], which writes the template's PD
/// physical address into one PDPT entry of the per-call PT. The
/// per-call PT does NOT own the template's pages — they live for as
/// long as the parent `CompiledImage` (effectively `'static` in V1).
///
/// The PD covers a 1 GiB-aligned VA range; leaf PTEs are addressed by
/// the offset within that range (`0..1 GiB`).
pub struct TemplatePT {
    pd: NonNull<Table>,
    /// PD page + every PT page allocated under it. Freed in Drop.
    owned: Vec<NonNull<Table>>,
}

impl TemplatePT {
    /// Allocate a fresh PD page. The PD starts empty; populate it with
    /// [`TemplatePT::map_leaf`] before installing the template.
    pub fn new() -> Option<Self> {
        let pd = alloc_table()?;
        let mut owned = Vec::with_capacity(4);
        owned.push(pd);
        Some(Self { pd, owned })
    }

    /// Add a leaf PTE for a single 4 KiB page at `offset` bytes into
    /// the 1 GiB region this PD covers. `offset` must be 4 KiB-aligned
    /// and strictly less than 1 GiB.
    pub fn map_leaf(&mut self, offset: u64, pa: u64, perm: Perm) -> Option<()> {
        assert!(offset.is_multiple_of(PAGE_SIZE as u64));
        assert!(offset < (1u64 << 30));
        let idx2 = ((offset >> 21) & 0x1FF) as usize;
        let idx1 = ((offset >> 12) & 0x1FF) as usize;
        // SAFETY: self.pd is a fresh table this template owns.
        let pd = unsafe { &mut *self.pd.as_ptr() };
        let inner_flags = flag::P | flag::RW | flag::US;
        let pt_ptr = if pd[idx2] & flag::P != 0 {
            let pa = pd[idx2] & PA_MASK;
            pa_to_va(pa)? as *mut Table
        } else {
            let new_pt = alloc_table()?;
            self.owned.push(new_pt);
            let va = new_pt.as_ptr() as u64;
            let pa = va_to_pa(va)?;
            pd[idx2] = (pa & PA_MASK) | inner_flags;
            new_pt.as_ptr()
        };
        // SAFETY: pt_ptr is a table allocated by us (either fresh or
        // recovered from a present PDE); 512 entries are writable.
        let pt = unsafe { &mut *pt_ptr };
        pt[idx1] = (pa & PA_MASK) | perm.pte_flags();
        Some(())
    }

    /// Physical address of the PD page — what per-call PTs install.
    pub fn pd_pa(&self) -> Option<u64> {
        va_to_pa(self.pd.as_ptr() as u64)
    }
}

impl Drop for TemplatePT {
    fn drop(&mut self) {
        for table in self.owned.drain(..) {
            // SAFETY: every entry came from `alloc_table` with TABLE_LAYOUT.
            unsafe {
                dealloc(table.as_ptr() as *mut u8, TABLE_LAYOUT);
            }
        }
    }
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

    /// Install a borrowed PD pointer (from a [`TemplatePT`]) at the
    /// PDPT entry covering `va`. The PDPT is auto-allocated and owned
    /// by this `PageTable` (freed on Drop); the PD (and the PT pages
    /// it references) belong to the template and survive `Drop`.
    ///
    /// `va` must be 1 GiB-aligned — it identifies which PDPT entry
    /// receives the template's PD. Any existing entry at that PDPT
    /// slot is overwritten (intended: caller has not mapped anything
    /// in this 1 GiB range yet).
    pub fn install_borrowed_pd(&mut self, va: u64, pd_pa: u64) -> Option<()> {
        assert!(va.is_multiple_of(1u64 << 30));
        let idx4 = ((va >> 39) & 0x1FF) as usize;
        let idx3 = ((va >> 30) & 0x1FF) as usize;
        let inner_flags = flag::P | flag::RW | flag::US;
        // SAFETY: self.pml4 is owned by this PT.
        let pml4 = unsafe { &mut *self.pml4.as_ptr() };
        let pdpt = self.ensure_inner(&mut pml4[idx4], inner_flags)?;
        // SAFETY: pdpt is a table this PT owns (just allocated or
        // shallow-copied from the active CR3).
        let pdpt = unsafe { &mut *pdpt };
        pdpt[idx3] = (pd_pa & PA_MASK) | inner_flags;
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

impl PageTable {
    /// Kernel VA of this page table's PML4. Stashed in a static at
    /// `enter_frame` time so the #PF handler can rewrite leaf PTEs
    /// without needing access to the [`PageTable`] itself.
    pub fn pml4_kva(&self) -> u64 {
        self.pml4.as_ptr() as u64
    }
}

/// Look up the physical address of the 4 KiB page covering `virt`
/// in the page table rooted at `pml4_va`. Returns `None` if any
/// table on the walk is non-present or marks a large-page leaf.
///
/// # Safety
///
/// `pml4_va` must be the kernel VA of a live 4-level page table
/// (whose intermediate tables are reachable via [`pa_to_va`]).
pub unsafe fn pt_lookup_leaf(pml4_va: u64, virt: u64) -> Option<u64> {
    const PS: u64 = 1 << 7;
    let idx4 = ((virt >> 39) & 0x1FF) as usize;
    let idx3 = ((virt >> 30) & 0x1FF) as usize;
    let idx2 = ((virt >> 21) & 0x1FF) as usize;
    let idx1 = ((virt >> 12) & 0x1FF) as usize;

    // SAFETY: pml4_va owned by caller, page-aligned, kernel-readable.
    let pml4 = unsafe { &*(pml4_va as *const Table) };
    if pml4[idx4] & flag::P == 0 {
        return None;
    }
    let pdpt = unsafe { &*(pa_to_va(pml4[idx4] & PA_MASK)? as *const Table) };
    if pdpt[idx3] & flag::P == 0 || pdpt[idx3] & PS != 0 {
        return None;
    }
    let pd = unsafe { &*(pa_to_va(pdpt[idx3] & PA_MASK)? as *const Table) };
    if pd[idx2] & flag::P == 0 || pd[idx2] & PS != 0 {
        return None;
    }
    let pt = unsafe { &*(pa_to_va(pd[idx2] & PA_MASK)? as *const Table) };
    if pt[idx1] & flag::P == 0 {
        return None;
    }
    Some(pt[idx1] & PA_MASK)
}

/// Overwrite an existing leaf PTE in the page table rooted at
/// `pml4_va` so the 4 KiB page covering `virt` now maps to `phys`
/// with `perm`. Returns `None` if any intermediate is missing —
/// i.e., the page wasn't previously mapped. Does not invalidate the
/// TLB; the caller must [`invlpg`].
///
/// # Safety
///
/// Same as [`pt_lookup_leaf`], plus the caller must hold the only
/// reference to the table during the rewrite (we currently have a
/// single-threaded guest).
pub unsafe fn pt_remap_leaf(pml4_va: u64, virt: u64, phys: u64, perm: Perm) -> Option<()> {
    const PS: u64 = 1 << 7;
    let idx4 = ((virt >> 39) & 0x1FF) as usize;
    let idx3 = ((virt >> 30) & 0x1FF) as usize;
    let idx2 = ((virt >> 21) & 0x1FF) as usize;
    let idx1 = ((virt >> 12) & 0x1FF) as usize;

    // SAFETY: as above.
    let pml4 = unsafe { &mut *(pml4_va as *mut Table) };
    if pml4[idx4] & flag::P == 0 {
        return None;
    }
    let pdpt = unsafe { &mut *(pa_to_va(pml4[idx4] & PA_MASK)? as *mut Table) };
    if pdpt[idx3] & flag::P == 0 || pdpt[idx3] & PS != 0 {
        return None;
    }
    let pd = unsafe { &mut *(pa_to_va(pdpt[idx3] & PA_MASK)? as *mut Table) };
    if pd[idx2] & flag::P == 0 || pd[idx2] & PS != 0 {
        return None;
    }
    let pt = unsafe { &mut *(pa_to_va(pd[idx2] & PA_MASK)? as *mut Table) };
    pt[idx1] = (phys & PA_MASK) | perm.pte_flags();
    Some(())
}

/// Flush the TLB entry for `virt` on the current CPU. No-op when the
/// caller is about to switch CR3 (which flushes every non-global
/// entry), but cheap enough to always call after a PTE rewrite.
#[inline]
pub fn invlpg(virt: u64) {
    // SAFETY: `invlpg` is a no-fault instruction on any address.
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) virt, options(nostack, preserves_flags));
    }
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

