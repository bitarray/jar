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
    /// Global TLB entry. When CR4.PGE is set, CR3 reloads do not flush
    /// leaf entries carrying this bit.
    pub const G: u64 = 1 << 8;
    /// No-Execute (bit 63). Set → instruction fetch faults.
    pub const NX: u64 = 1 << 63;
}

/// Mask covering the physical-address bits of a PTE (bits 12..51).
const PA_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Convert a kernel VA to its physical address. Three regimes (see
/// module doc): scratch (high VA), kernel half (low VA past
/// `kernel_base_va()`), user half (returns `None`).
#[inline]
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
#[inline]
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
    pub global: bool,
}

impl Perm {
    #[inline]
    pub const fn user_rw() -> Self {
        Self {
            writable: true,
            user: true,
            executable: false,
            global: false,
        }
    }
    #[inline]
    pub const fn user_rx() -> Self {
        Self {
            writable: false,
            user: true,
            executable: true,
            global: false,
        }
    }
    #[inline]
    pub const fn user_ro() -> Self {
        Self {
            writable: false,
            user: true,
            executable: false,
            global: false,
        }
    }
    #[inline]
    pub const fn user_rx_global() -> Self {
        Self {
            writable: false,
            user: true,
            executable: true,
            global: true,
        }
    }
    #[inline]
    pub const fn user_ro_global() -> Self {
        Self {
            writable: false,
            user: true,
            executable: false,
            global: true,
        }
    }
    /// Encode as the low-bit + high-bit flags of a leaf PTE.
    #[inline]
    fn pte_flags(&self) -> u64 {
        let mut bits = flag::P;
        if self.writable {
            bits |= flag::RW;
        }
        if self.user {
            bits |= flag::US;
        }
        if self.global {
            bits |= flag::G;
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
/// This PD is borrowed as the META entry (PDPT[1]) of the Image's
/// [`Pml4SlotTemplate`], which a per-call [`PageTable`] installs whole via
/// [`PageTable::install_borrowed_pdpt`]. The per-call PT does NOT own the
/// template's pages — they live for as long as the parent `CompiledImage`
/// (effectively `'static` in V1).
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

/// Per-Image template for the entire PML4 slot-1 subtree — the PDPT covering
/// one 512 GiB PML4 slot, prefilled with its three 1 GiB-PDPT-slot entries:
/// CTX, META (the Image arena PD), and STACK. All three are **borrowed** PDs:
/// CTX/STACK point at the *process-global* CTX/STACK PD subtrees (the identical
/// PD→PT→global-page chain, built once for all Images — one frame runs in ring
/// 3 at a time, so they need no per-call copy); META at the Image's own arena
/// PD (a separate [`TemplatePT`] owned by the same `CompiledImage`).
///
/// So this template owns only the PDPT page itself — one table per Image — and
/// per-call [`PageTable`]s install the whole subtree with one borrowed PML4
/// write ([`PageTable::install_borrowed_pdpt`]) instead of allocating per-frame
/// PDPT + CTX/STACK PD/PT tables (≈5 tables / 20 KiB saved per frame). The
/// per-call PT does NOT own any of it — the PDPT lives as long as the parent
/// `CompiledImage` (effectively `'static` in V1), the CTX/STACK PDs forever.
pub struct Pml4SlotTemplate {
    /// The PDPT page (512 entries, indexed by `va[38:30]`). Freed in `Drop`;
    /// the borrowed PDs it points at are owned elsewhere.
    pdpt: NonNull<Table>,
}

impl Pml4SlotTemplate {
    /// Build the PDPT, planting three borrowed PD PAs at the PDPT slots of
    /// `ctx_va` / `meta_va` / `stack_va` (distinct, same-PML4-slot VAs):
    /// `ctx_pd_pa` / `stack_pd_pa` are the global CTX/STACK PD subtrees,
    /// `meta_pd_pa` the Image arena PD. Returns `None` on allocation failure.
    pub fn new(
        ctx_va: u64,
        ctx_pd_pa: u64,
        meta_va: u64,
        meta_pd_pa: u64,
        stack_va: u64,
        stack_pd_pa: u64,
    ) -> Option<Self> {
        let pdpt = alloc_table()?;
        let inner_flags = flag::P | flag::RW | flag::US;
        // SAFETY: `pdpt` is a fresh 512-entry table we just allocated and own.
        let entries = unsafe { &mut *pdpt.as_ptr() };
        entries[((ctx_va >> 30) & 0x1FF) as usize] = (ctx_pd_pa & PA_MASK) | inner_flags;
        entries[((meta_va >> 30) & 0x1FF) as usize] = (meta_pd_pa & PA_MASK) | inner_flags;
        entries[((stack_va >> 30) & 0x1FF) as usize] = (stack_pd_pa & PA_MASK) | inner_flags;

        Some(Self { pdpt })
    }

    /// Build a global, leak-once CTX/STACK PD subtree (PD + PT) mapping a single
    /// page `page_pa` read-write at offset 0 of its 1 GiB slot (`va`), and
    /// return its PD physical address. The subtree is intentionally **leaked**
    /// (it lives for the kernel's lifetime), so its PD can be borrowed as a
    /// PDPT entry by every Image's `Pml4SlotTemplate` without per-Image
    /// duplication. Returns `None` on allocation failure.
    pub fn leak_global_pd(va: u64, page_pa: u64) -> Option<u64> {
        let mut pd = TemplatePT::new()?;
        pd.map_leaf(va & ((1u64 << 30) - 1), page_pa, Perm::user_rw())?;
        let pd_pa = pd.pd_pa()?;
        core::mem::forget(pd); // leak: lives for the kernel's lifetime
        Some(pd_pa)
    }

    /// Physical address of the PDPT page — what per-call PTs install into PML4.
    #[inline]
    pub fn pdpt_pa(&self) -> Option<u64> {
        va_to_pa(self.pdpt.as_ptr() as u64)
    }
}

impl Drop for Pml4SlotTemplate {
    fn drop(&mut self) {
        // SAFETY: `pdpt` came from `alloc_table` with TABLE_LAYOUT. The borrowed
        // CTX/STACK/META PDs are owned elsewhere (globals / the Image template).
        unsafe {
            dealloc(self.pdpt.as_ptr() as *mut u8, TABLE_LAYOUT);
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
        // The guest's whole low VA range (PML4 slot 0) MUST be exclusively
        // the per-invocation guest's — the kernel lives at slot 511 after
        // Stage-F relocation. Zero-setup demand paging depends on this: the
        // #PF handler builds fresh frame-private intermediates under slot 0,
        // and would corrupt kernel-shared tables if the source PML4[0] were
        // present. Make that invariant loud.
        // SAFETY: pml4_ptr is a valid 4 KiB table we just populated.
        debug_assert_eq!(
            unsafe { (*pml4_ptr.as_ptr())[0] } & flag::P,
            0,
            "PML4[0] must be empty (guest-exclusive) for zero-setup demand paging",
        );
        let mut owned = Vec::with_capacity(8);
        owned.push(pml4_ptr);
        Some(Self {
            pml4: pml4_ptr,
            owned: RefCell::new(owned),
        })
    }

    /// CR3 value to load (physical address of the PML4, low 12 bits clear).
    #[inline]
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

    /// Install a borrowed PDPT pointer (from a [`Pml4SlotTemplate`]) at the
    /// PML4 entry covering `va` — the whole-PML4-slot analogue of how that
    /// template borrows the Image arena PD as its META entry.
    /// The PML4 entry is overwritten with `pdpt_pa`; the entire subtree beneath
    /// it (the PDPT, the CTX/STACK PD/PT, and the borrowed META PD) belongs to
    /// the template and survives this `PageTable`'s `Drop`.
    ///
    /// `va` must be 512 GiB-aligned — it identifies which PML4 slot receives the
    /// template's PDPT. The target slot must be empty (it is in a fresh PT: the
    /// kernel lives in slot 511, the guest mem in slot 0, and slot 1 — the
    /// CTX/META/STACK region — is built only here).
    #[inline]
    pub fn install_borrowed_pdpt(&mut self, va: u64, pdpt_pa: u64) -> Option<()> {
        assert!(va.is_multiple_of(1u64 << 39));
        let idx4 = ((va >> 39) & 0x1FF) as usize;
        let inner_flags = flag::P | flag::RW | flag::US;
        // SAFETY: self.pml4 is owned by this PT.
        let pml4 = unsafe { &mut *self.pml4.as_ptr() };
        // The target PML4 slot must be empty before we plant a borrowed PDPT —
        // overwriting a present entry would orphan (leak) the subtree under it
        // and, for the guest slot, corrupt kernel-shared tables.
        debug_assert_eq!(
            pml4[idx4] & flag::P,
            0,
            "PML4 slot must be empty before installing a borrowed PDPT",
        );
        pml4[idx4] = (pdpt_pa & PA_MASK) | inner_flags;
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
    #[inline]
    pub fn pml4_kva(&self) -> u64 {
        self.pml4.as_ptr() as u64
    }

    /// Raw pointer (type-erased as `u64`) to this PT's `owned` table list,
    /// for the #PF handler to record fault-allocated intermediate tables
    /// into via [`pt_map_leaf`] (so they are freed at `Drop`). The guest
    /// is single-threaded (the main thread is suspended in ring 3 while
    /// the handler runs), so there is no concurrent borrow of `owned`.
    #[inline]
    pub fn owned_vec_ptr(&self) -> u64 {
        self.owned.as_ptr() as u64
    }
}

/// Build the PML4→PDPT→PD→PT path for `virt` (allocating any missing
/// intermediate tables and recording them in the `owned` list pointed at
/// by `owned_vec`, so they are freed at the [`PageTable`]'s `Drop`), then
/// install a **present** leaf PTE mapping `virt → phys` with `perm`.
///
/// This powers true zero-setup demand paging: the guest's low VA range
/// starts with NO page-table entries, and the #PF handler calls this on
/// the first fault to each page. It is idempotent over the path: a page
/// whose intermediates already exist (e.g. a CoW remap of a page paged in
/// earlier) reuses them and just rewrites the leaf. Does not invalidate
/// the TLB; the caller must [`invlpg`]. Returns `None` if an ancestor is a
/// large-page leaf or a table allocation fails.
///
/// # Safety
/// `pml4_va` must be the kernel VA of a live 4-level page table (this
/// `PageTable`'s); `owned_vec` must be [`PageTable::owned_vec_ptr`] of the
/// same table. The caller must be the only writer (single-threaded guest).
#[inline]
pub unsafe fn pt_map_leaf(
    pml4_va: u64,
    virt: u64,
    phys: u64,
    perm: Perm,
    owned_vec: u64,
) -> Option<()> {
    let owned = owned_vec as *mut Vec<NonNull<Table>>;
    let idx4 = ((virt >> 39) & 0x1FF) as usize;
    let idx3 = ((virt >> 30) & 0x1FF) as usize;
    let idx2 = ((virt >> 21) & 0x1FF) as usize;
    let idx1 = ((virt >> 12) & 0x1FF) as usize;
    let inner_flags = flag::P | flag::RW | flag::US;

    // SAFETY: pml4_va is a live 4 KiB-aligned table owned by the caller.
    let pml4 = unsafe { &mut *(pml4_va as *mut Table) };
    let pdpt = unsafe { ensure_inner_recorded(&mut pml4[idx4], inner_flags, owned)? };
    let pdpt = unsafe { &mut *pdpt };
    let pd = unsafe { ensure_inner_recorded(&mut pdpt[idx3], inner_flags, owned)? };
    let pd = unsafe { &mut *pd };
    let pt = unsafe { ensure_inner_recorded(&mut pd[idx2], inner_flags, owned)? };
    let pt = unsafe { &mut *pt };
    pt[idx1] = (phys & PA_MASK) | perm.pte_flags();
    Some(())
}

/// Set (`writable = true`) or clear (`writable = false`) the Writable bit
/// on an **existing** leaf PTE for `virt`, without allocating any
/// intermediate tables. Walks PML4→PDPT→PD→PT and returns `false` if any
/// level — or the leaf itself — is not present (nothing to toggle), so the
/// caller can fall back to a full map.
///
/// This powers page-table **reuse** across CALLs of a resident instance:
/// - the HALT re-arm clears W on every privately-CoW'd leaf, so the next
///   CALL re-faults on first write and re-charges its CoW (the page itself
///   is reused — only the W bit toggles, gas-neutral);
/// - the #PF handler sets W back when an already-private (overlay) page is
///   written again, flipping the bit instead of re-allocating + re-copying.
///
/// Does **not** invalidate the TLB. The handler must [`invlpg`] after a
/// clear→RW flip (the RO translation may be cached by the faulting write);
/// the re-arm needs none (a CR3 reload at the next `enter_frame` flushes
/// every non-global entry).
///
/// # Safety
/// `pml4_va` must be the kernel VA of a live 4-level page table; the caller
/// must be the only writer (single-threaded guest).
#[inline]
pub unsafe fn pt_set_leaf_w(pml4_va: u64, virt: u64, writable: bool) -> bool {
    const PS: u64 = 1 << 7;
    let idx4 = ((virt >> 39) & 0x1FF) as usize;
    let idx3 = ((virt >> 30) & 0x1FF) as usize;
    let idx2 = ((virt >> 21) & 0x1FF) as usize;
    let idx1 = ((virt >> 12) & 0x1FF) as usize;

    // Descend one present, non-large-page level at a time; bail to `false`
    // the moment the path is absent (the caller then does a full map).
    let descend = |table_va: u64, idx: usize| -> Option<u64> {
        // SAFETY: table_va is a live 4 KiB-aligned table (the PML4 or a
        // recovered inner table); 512 entries are readable.
        let entry = unsafe { (*(table_va as *const Table)).get(idx).copied()? };
        if entry & flag::P == 0 || entry & PS != 0 {
            return None;
        }
        pa_to_va(entry & PA_MASK)
    };

    let pdpt_va = match descend(pml4_va, idx4) {
        Some(v) => v,
        None => return false,
    };
    let pd_va = match descend(pdpt_va, idx3) {
        Some(v) => v,
        None => return false,
    };
    let pt_va = match descend(pd_va, idx2) {
        Some(v) => v,
        None => return false,
    };
    // SAFETY: pt_va is a live PT this caller owns; idx1 < 512.
    let leaf = unsafe { &mut (*(pt_va as *mut Table))[idx1] };
    if *leaf & flag::P == 0 {
        return false;
    }
    if writable {
        *leaf |= flag::RW;
    } else {
        *leaf &= !flag::RW;
    }
    true
}

/// Like [`PageTable::ensure_inner`] but records a freshly-allocated table
/// into the raw `owned` Vec pointer (for the #PF handler, which has no
/// `&PageTable`). Returns the inner table's KVA, or `None` on large-page
/// ancestor / allocation failure.
///
/// # Safety
/// `owned` must point at a live `Vec<NonNull<Table>>` (the PageTable's
/// `owned`); single-threaded access.
#[inline]
unsafe fn ensure_inner_recorded(
    entry: &mut u64,
    inner_flags: u64,
    owned: *mut Vec<NonNull<Table>>,
) -> Option<*mut Table> {
    const PS: u64 = 1 << 7;
    if *entry & flag::P != 0 {
        if *entry & PS != 0 {
            return None; // large-page leaf — cannot descend
        }
        let pa = *entry & PA_MASK;
        *entry |= inner_flags;
        return Some(pa_to_va(pa)? as *mut Table);
    }
    let new_table = alloc_table()?;
    let va = new_table.as_ptr() as u64;
    let pa = va_to_pa(va)?;
    // SAFETY: owned is the live PageTable.owned Vec; single writer.
    unsafe {
        (*owned).push(new_table);
    }
    *entry = (pa & PA_MASK) | inner_flags;
    Some(new_table.as_ptr())
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
#[inline]
pub fn read_cr3() -> u64 {
    let cr3: u64;
    // SAFETY: reading CR3 is a privileged but harmless operation at ring 0.
    unsafe {
        core::arch::asm!("mov {0}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    cr3
}

/// Enable CR4.PGE so leaf PTEs with [`flag::G`] survive CR3 reloads.
///
/// Idempotent: callers can run this on the hot path before ring-3 entry.
#[inline]
pub fn enable_global_pages() {
    const CR4_PGE: u64 = 1 << 7;
    let mut cr4: u64;
    // SAFETY: reading/writing CR4 is privileged and valid in the guest kernel.
    // We only set PGE, preserving all other control bits installed by
    // Hyperlight/boot code.
    unsafe {
        core::arch::asm!("mov {0}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        if cr4 & CR4_PGE == 0 {
            cr4 |= CR4_PGE;
            core::arch::asm!("mov cr4, {0}", in(reg) cr4, options(nomem, nostack, preserves_flags));
        }
    }
}
