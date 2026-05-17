//! Kernel-side page table construction with user-accessible mappings.
//!
//! Hyperlight's `paging::map_region` is hard-coded to `user_accessible
//! = false` — fine for kernel pages but unusable for ring-3 PVM
//! programs. We build our own page tables in the bump arena so the
//! kernel can map per-invocation program memory and JIT'd code with
//! the User/Supervisor bit set.
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
//! Each table is 4 KiB (512 × 8-byte PTEs); tables are allocated
//! page-aligned from the bump arena.
//!
//! ## PA ↔ VA translation
//!
//! Hyperlight's guest layout has two address-translation modes for
//! kernel-mode pages:
//!
//! * **Low memory (kernel code, heap, host I/O buffers)** is
//!   identity-mapped: `VA == PA`.
//! * **Scratch region (page tables, TSS, IDT)** is mapped at a high
//!   VA via a constant offset:
//!   ```text
//!     gva = scratch_base_gva + (gpa - scratch_base_gpa)
//!   ```
//!   Scratch PAs sit near the top of the 36-bit GPA range; scratch
//!   VAs sit near the top of the 48-bit canonical VA range.
//!
//! [`va_to_pa`] / [`pa_to_va`] handle both modes: addresses in the
//! scratch range use the offset translation, everything else is
//! treated as identity-mapped. The boundary check uses
//! [`hyperlight_guest::layout::scratch_base_gpa`] /
//! [`scratch_base_gva`].

#![cfg(target_os = "none")]

use crate::bump::{BumpArena, PAGE_SIZE};
use core::ptr::NonNull;

use hyperlight_guest::layout::{scratch_base_gpa, scratch_base_gva};

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

/// Convert a scratch VA to its physical address. Returns `None` if
/// `va` is outside the scratch GVA range — i.e. it isn't a scratch
/// address that the kernel itself allocated via `alloc_phys_pages`.
pub fn va_to_pa(va: u64) -> Option<u64> {
    let gva = scratch_base_gva();
    if va >= gva {
        Some(scratch_base_gpa() + (va - gva))
    } else {
        None
    }
}

/// Convert a scratch PA to its kernel VA. Returns `None` if `pa` is
/// outside the scratch GPA range (i.e. it points at kernel code, the
/// host-mapped low memory region, or an unrecognised area).
pub fn pa_to_va(pa: u64) -> Option<u64> {
    let gpa = scratch_base_gpa();
    if pa >= gpa {
        Some(scratch_base_gva() + (pa - gpa))
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
    #[allow(dead_code)] // used by Stage C1 (JIT exec pages)
    pub const fn user_rx() -> Self {
        Self {
            writable: false,
            user: true,
            executable: true,
        }
    }
    #[allow(dead_code)] // used by Stage A4 (kernel-only ctx pages)
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

/// In-kernel page table holding a fresh PML4 allocated from the bump
/// arena. Lifetime is tied to the arena (via Rust borrow).
pub struct PageTable<'a> {
    pml4: NonNull<Table>,
    arena: &'a BumpArena,
}

impl<'a> PageTable<'a> {
    /// Allocate a fresh PML4 (zero-initialised) in `arena`, then copy
    /// every PML4 entry from the current CR3 so kernel-half mappings
    /// stay valid after a CR3 switch.
    ///
    /// Note: this *shallow-copies* PML4 entries — descendant tables
    /// are shared with the original. Per-invocation isolation only
    /// requires that *new* mappings (the user-half entries we add)
    /// don't share with the kernel's existing pages, which they don't
    /// because they live in different PML4 slots.
    pub fn new_in(arena: &'a BumpArena) -> Option<Self> {
        let pml4_ptr = arena.alloc_pages(1)?.cast::<Table>();
        // SAFETY: arena returned a fresh 4 KiB page-aligned region.
        unsafe {
            core::ptr::write_bytes(pml4_ptr.as_ptr() as *mut u8, 0, PAGE_SIZE);
        }
        let cr3_pa = read_cr3() & PA_MASK;
        let src_va = pa_to_va(cr3_pa)?;
        let src_pml4 = src_va as *const Table;
        // SAFETY: src_va is the scratch-mapped VA of the current PML4;
        // 4 KiB of bytes are valid.
        unsafe {
            core::ptr::copy_nonoverlapping(src_pml4, pml4_ptr.as_ptr(), 1);
        }
        Some(Self {
            pml4: pml4_ptr,
            arena,
        })
    }

    /// CR3 value to load (physical address of the PML4, low 12 bits clear).
    pub fn cr3(&self) -> Option<u64> {
        va_to_pa(self.pml4.as_ptr() as u64)
    }

    /// Map `len` bytes at virtual address `virt` to physical address
    /// `phys` with the given permissions. `virt`, `phys`, and `len`
    /// must each be 4 KiB-aligned. Allocates intermediate tables from
    /// the bump arena as needed; an existing mapping at the same VA
    /// is overwritten.
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
    fn map_one(&mut self, va: u64, pa: u64, perm: Perm) -> Option<()> {
        let idx4 = ((va >> 39) & 0x1FF) as usize;
        let idx3 = ((va >> 30) & 0x1FF) as usize;
        let idx2 = ((va >> 21) & 0x1FF) as usize;
        let idx1 = ((va >> 12) & 0x1FF) as usize;

        // Inner-table PTE flags: present + writable + user (always set
        // so the leaf's flag is the decisive permission).
        let inner_flags = flag::P | flag::RW | flag::US;

        // SAFETY: self.pml4 is a valid 4 KiB-aligned table in the arena.
        let pml4 = unsafe { &mut *self.pml4.as_ptr() };
        let pdpt = self.ensure_inner(&mut pml4[idx4], inner_flags)?;

        // SAFETY: ensure_inner returned a freshly allocated or pre-existing
        // table; the pointer is a kernel VA in the scratch region.
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
    /// requested inner flags). Otherwise, allocate a fresh table in
    /// the arena, install it in `entry`, return its address.
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
        let new_va_ptr = self.arena.alloc_pages(1)?.cast::<Table>();
        // SAFETY: arena returned a fresh page-aligned 4 KiB block; zero it.
        unsafe {
            core::ptr::write_bytes(new_va_ptr.as_ptr() as *mut u8, 0, PAGE_SIZE);
        }
        let pa = va_to_pa(new_va_ptr.as_ptr() as u64)?;
        *entry = (pa & PA_MASK) | inner_flags;
        Some(new_va_ptr.as_ptr())
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
#[allow(dead_code)] // used by Stage A4
pub fn flush_tlb() {
    // SAFETY: rewriting CR3 with its current value is observably a
    // TLB flush.
    unsafe {
        let cr3 = read_cr3();
        write_cr3(cr3);
    }
}
