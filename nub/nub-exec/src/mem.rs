//! Flat-buffer memory model + the [`Memory`] trait that abstracts
//! over different memory backends (software-copy here, hardware-paged
//! in the bare-metal Hyperlight guest).
//!
//! Matches v2 javm's `flat_mem` layout for perf parity: a single
//! contiguous `Vec<u8>` indexed by 32-bit address. Reads/writes are
//! bounds-checked against `flat_mem.len()`; on out-of-range the
//! caller gets `false`/`None` and translates to `ExitReason::PageFault`.
//!
//! Per-page permissions are tracked separately in `flat_perms` (one
//! byte per page) so the JIT signal handler can detect ro-write
//! faults without involving the interpreter. The interpreter itself
//! relies on the page-protected hardware mapping for read-only
//! enforcement; this layer just bounds-checks.
//!
//! The fast-path read/write helpers use `read_unaligned` /
//! `write_unaligned` via raw pointers — single MOV on x86.

use alloc::vec::Vec;

use crate::gas::GasCounter;

/// PVM page size: 4 KiB.
pub const PAGE_SIZE: u32 = 1 << 12;

/// Per-page permission byte (matches v2's `flat_perms` semantics).
pub mod perm {
    /// Page is inaccessible (read or write faults).
    pub const NONE: u8 = 0;
    /// Page is readable; writes fault.
    pub const RO: u8 = 1;
    /// Page is readable + writable.
    pub const RW: u8 = 2;
}

/// Mapping permission for [`Memory::map_region`]. RO regions back
/// `perm::RO` pages; RW regions back `perm::RW` pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    ReadOnly,
    ReadWrite,
}

/// Outcome of a memory access (slow path; the fast inline helpers
/// return raw `Option` / `bool`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemAccess {
    Ok,
    /// Page not mapped at the page-aligned address.
    PageFault(u32),
    /// Page is read-only and the access is a write.
    WriteProtected(u32),
}

/// A category-#3 first-touch (`touch_read`/`touch_write`) that cannot be
/// satisfied: a write to a read-only (pinned) page, or a data access
/// straddling outside the declared region. The caller must `PageFault`,
/// charging nothing — the touch is all-or-nothing. (Accesses whose base
/// page is *not* a declared data page — a code-region PIC load or a
/// fully-unmapped address — are skipped, not faulted: they return `Ok`
/// so the caller's normal load/store path resolves them.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TouchFault;

/// Setup-time error for [`Memory::map_region`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    /// `start` is not page-aligned.
    UnalignedStart(u64),
    /// `size` is not a multiple of [`PAGE_SIZE`].
    UnalignedSize(u64),
    /// `start + size` overflows `usize` on this platform, or exceeds
    /// the addressable range supported by `Mem`.
    Overflow,
}

/// Memory backend abstraction.
///
/// The interpreter is generic over `M: Memory` so the same source
/// compiles for two substrates:
///
/// - **Software-copy**: [`CopyingMemory`] (this module) — an owning
///   `Vec<u8>` with per-page permissions. Runs in-process.
/// - **Hardware-paged**: a future bare-metal impl in
///   `nub-arch-x86` that maps PVM pages onto real CPU pages
///   via the in-guest IDT + page tables.
///
/// Hot-path methods (`read_u*`/`write_u*`) return `Option<T>` or
/// `bool` to keep the interpreter loop branch-free. Implementations
/// should mark these `#[inline]` (or `#[inline(always)]`) — the
/// interpreter calls them through trait dispatch, and we want
/// monomorphisation to collapse to direct function calls.
pub trait Memory {
    // ---- Hot-path width-typed reads. ----
    fn read_u8(&self, addr: u32) -> Option<u8>;
    fn read_u16_le(&self, addr: u32) -> Option<u16>;
    fn read_u32_le(&self, addr: u32) -> Option<u32>;
    fn read_u64_le(&self, addr: u32) -> Option<u64>;

    // ---- Hot-path width-typed writes. ----
    fn write_u8(&mut self, addr: u32, val: u8) -> bool;
    fn write_u16_le(&mut self, addr: u32, val: u16) -> bool;
    fn write_u32_le(&mut self, addr: u32, val: u32) -> bool;
    fn write_u64_le(&mut self, addr: u32, val: u64) -> bool;

    // ---- Setup-time + cold-path. ----

    /// Declare a mapped region. See [`CopyingMemory::map_region`] for
    /// the canonical semantics.
    fn map_region(
        &mut self,
        start: u64,
        size: u64,
        access: Access,
        init: Option<&[u8]>,
    ) -> Result<(), MapError>;

    /// Per-page permission byte for the page containing `addr`.
    /// Returns [`perm::NONE`] if `addr` is out of range.
    fn perm_of(&self, addr: u32) -> u8;

    /// Read `dst.len()` bytes starting at `addr` into `dst`.
    fn read(&self, addr: u32, len: usize) -> Result<Vec<u8>, MemAccess>;

    /// Write `data.len()` bytes starting at `addr`. Per-page perm
    /// checks apply; out-of-range or RO-page writes return `Err`.
    fn write(&mut self, addr: u32, data: &[u8]) -> Result<(), MemAccess>;

    // ---- Category-#3 lazy-materialization accounting. ----

    /// Charge category-#3 first-touch gas for a `width`-byte **read** at
    /// `addr` (page-in on the first read of a page), advancing the
    /// per-page materialization state. See [`CopyingMemory::touch_read`]
    /// for the canonical semantics. The default is a no-op (`Ok`) for
    /// backends that don't model lazy materialization.
    fn touch_read(
        &mut self,
        addr: u32,
        width: u32,
        gas: &mut GasCounter,
    ) -> Result<(), TouchFault> {
        let _ = (addr, width, gas);
        Ok(())
    }

    /// Charge category-#3 first-touch gas for a `width`-byte **write** at
    /// `addr` (page-in + copy-on-write on the first write of a page),
    /// advancing the per-page materialization state. See
    /// [`CopyingMemory::touch_write`] for the canonical semantics. The
    /// default is a no-op (`Ok`).
    fn touch_write(
        &mut self,
        addr: u32,
        width: u32,
        gas: &mut GasCounter,
    ) -> Result<(), TouchFault> {
        let _ = (addr, width, gas);
        Ok(())
    }
}

/// Address-space mapping for one execution context.
///
/// Flat-buffer layout matching v2 javm. The buffer's length defines
/// the upper bound of valid addresses; per-page permissions live in
/// `perms`. Implements [`Memory`] via inherent-method delegation so
/// concrete callers don't need to import the trait.
#[derive(Clone, Debug)]
pub struct CopyingMemory {
    /// Base guest address `flat_mem[0]` corresponds to. Guest address
    /// `addr` indexes `flat_mem[addr - base]`; accesses below `base` (or
    /// past the buffer) fault. Lets the buffer cover only the high data
    /// region `[DATA_BASE, …)` without allocating the `[0, DATA_BASE)`
    /// null-guard hole — matching the recompiler's page table, which
    /// leaves that range unmapped. `0` for the addr-0-based memories used
    /// in unit tests.
    pub base: u32,
    /// Contiguous byte buffer covering `[base, base + flat_mem.len())`.
    pub flat_mem: Vec<u8>,
    /// One permission byte per `PAGE_SIZE`-page in `flat_mem`.
    /// `perms.len() == flat_mem.len() / PAGE_SIZE` (rounded up). Indexed
    /// by page *relative to `base`*.
    pub perms: Vec<u8>,
    /// Category-#3 per-page materialization state ([`crate::mat::PageState`]
    /// as a `u8`), one byte per page, kept the same length as `perms`.
    /// Software first-touch accounting: a never-touched page is
    /// `NotPresent`; the first read pages it in, the first write CoWs it.
    /// The interpreter's #3 charge is kind-independent (the only
    /// kind-sensitive case — a write to a pinned page — is already gated
    /// by the `perm::RW` write check), so no per-page `PageKind` is kept;
    /// the recompiler tracks kinds itself for page sourcing.
    pub mat_state: Vec<u8>,
    /// Guest VA base of the read-only CODE region (`PinnedCapRo`). Guest
    /// data loads (PIC `auipc`+load) of the program's own bytecode page it
    /// in on first read (read-only page-in is charged eagerly at the CALL,
    /// not at this fault, but a PIC read still records residency), identical
    /// to the recompiler. `code_top == code_base` (the default) means no code
    /// region is declared — code reads then skip #3 (unit tests).
    pub code_base: u32,
    /// Exclusive top of the code region, **page-rounded**:
    /// `code_base + round_up(code_len)`. The last code page's zero-padded
    /// tail is readable (matching the recompiler, which maps whole pages).
    pub code_top: u32,
    /// Heap base address (for sbrk).
    pub heap_base: u32,
    /// Current heap top.
    pub heap_top: u32,
    /// Maximum heap pages (sbrk refuses beyond this).
    pub max_heap_pages: u32,
}

impl Default for CopyingMemory {
    fn default() -> Self {
        Self::new()
    }
}

/// Compatibility alias for the pre-trait name. Consumers can keep
/// writing `Mem`; new code should prefer `CopyingMemory` (when the
/// concrete impl is wanted) or be generic over `M: Memory`.
pub type Mem = CopyingMemory;

impl CopyingMemory {
    /// Empty memory; no pages allocated. `base = 0` (addr-0-based).
    pub fn new() -> Self {
        Self {
            base: 0,
            flat_mem: Vec::new(),
            perms: Vec::new(),
            mat_state: Vec::new(),
            code_base: 0,
            code_top: 0,
            heap_base: 0,
            heap_top: 0,
            max_heap_pages: 0,
        }
    }

    /// Byte offset into `flat_mem` for guest address `addr`. Wraps for
    /// `addr < base` so the subsequent `… < flat_mem.len()` bounds check
    /// rejects sub-`base` accesses (the null-guard / code region) as a
    /// fault — no separate check needed.
    #[inline(always)]
    fn off(&self, addr: u32) -> usize {
        addr.wrapping_sub(self.base) as usize
    }

    /// Construct with a pre-sized flat buffer (zero-initialized).
    /// `n_pages` is the number of `PAGE_SIZE`-pages. `base = 0`.
    pub fn with_pages(n_pages: u32, default_perm: u8) -> Self {
        let bytes = (n_pages as usize) * (PAGE_SIZE as usize);
        Self {
            base: 0,
            flat_mem: vec![0u8; bytes],
            perms: vec![default_perm; n_pages as usize],
            mat_state: vec![crate::mat::PageState::NotPresent.as_u8(); n_pages as usize],
            code_base: 0,
            code_top: 0,
            heap_base: 0,
            heap_top: 0,
            max_heap_pages: 0,
        }
    }

    /// Declare the read-only CODE region for category-#3 accounting:
    /// `[code_base, code_base + round_up(code_len))`. Guest data loads of
    /// the program's own bytecode (PIC) then read each touched code page
    /// with no per-fault charge (read-only page-in is accounted eagerly at
    /// the CALL) and hard-fault on any write — matching the recompiler,
    /// which lazily materializes code pages too. `code_len` is the exact
    /// byte length; the region is page-rounded.
    pub fn set_code_region(&mut self, code_base: u32, code_len: u32) {
        let rounded = code_len.next_multiple_of(PAGE_SIZE);
        self.code_base = code_base;
        self.code_top = code_base.saturating_add(rounded);
    }

    /// Whether the page-aligned address `page_addr` lies inside the declared
    /// read-only code region.
    #[inline]
    fn is_code_page(&self, page_addr: u32) -> bool {
        self.code_top > self.code_base && page_addr >= self.code_base && page_addr < self.code_top
    }

    /// Per-page permission for the page containing `addr`. Returns
    /// `perm::NONE` if the address is out of range (incl. below `base`).
    pub fn perm_of(&self, addr: u32) -> u8 {
        let page = self.off(addr) / (PAGE_SIZE as usize);
        self.perms.get(page).copied().unwrap_or(perm::NONE)
    }

    /// Page index into `perms` / `mat_state` for the page-aligned address
    /// `page_addr`, or `None` if it lies outside the flat buffer (below
    /// `base` or past its end). `perms`/`mat_state` always cover every
    /// page of `flat_mem`, so a `Some(i)` is always a valid index.
    #[inline]
    fn page_index(&self, page_addr: u32) -> Option<usize> {
        let o = self.off(page_addr);
        if o < self.flat_mem.len() {
            Some(o / PAGE_SIZE as usize)
        } else {
            None
        }
    }

    /// Category-#3 first-touch accounting for a `width`-byte access at
    /// `addr` (`width` in `1..=8`).
    ///
    /// Charges page-in / copy-on-write for each declared data page the
    /// access touches, advancing its [`crate::mat::PageState`]. The set
    /// of touched pages (≤ 2, the base page plus a straddle page) is
    /// [`crate::mat::access_pages`] — the *same* rule the recompiler's
    /// fault handler uses, so the charged page set and total match
    /// bit-for-bit.
    ///
    /// **All-or-nothing.** Accessibility is checked over the whole page
    /// set *before* any charge: a write to a read-only (pinned) page, or
    /// a straddle leaving the declared region, charges nothing and
    /// returns [`TouchFault`] (the caller `PageFault`s).
    ///
    /// **Code / unmapped accesses are skipped** (`Ok`, no charge): if the
    /// base page is not a declared data page (a code-region PIC load, the
    /// null guard, or a fully-unmapped address), `#3` does not apply and
    /// the caller's normal load/store path resolves it — the code-region
    /// fallback succeeds; a truly unmapped address `PageFault`s there.
    ///
    /// The charge is kind-independent: the only kind-sensitive rule (a
    /// write to a pinned page) is excluded by the `perm::RW` gate below,
    /// so [`crate::mat::charge_for`] is driven with a fixed CoW kind. The
    /// block reserve guarantees `gas` covers the worst case, so the final
    /// charge cannot underflow — mirroring the recompiler, which
    /// decrements its gas register in the fault handler without an OOG
    /// check.
    fn touch(
        &mut self,
        addr: u32,
        width: u32,
        is_write: bool,
        gas: &mut GasCounter,
    ) -> Result<(), TouchFault> {
        let set = crate::mat::access_pages(addr, width);
        let pages = set.as_slice();

        // Region dispatch by the base page. CODE and DATA are far apart
        // (CODE_BASE=4 MiB, DATA_BASE=256 MiB), so a single ≤8-byte access
        // lies wholly in one region — the base page decides which.
        if self
            .page_index(pages[0])
            .is_some_and(|i| self.perms[i] != perm::NONE)
        {
            self.touch_data(pages, is_write, gas)
        } else if self.is_code_page(pages[0]) {
            self.touch_code(pages, is_write)
        } else {
            // Null guard / inter-region gap / fully-unmapped: `#3` does not
            // apply — the caller's normal load/store path resolves it (the
            // code fallback or a `PageFault`).
            Ok(())
        }
    }

    /// `#3` for a DATA-region access (ephemeral / CoW). Accessibility-all
    /// then materialize-all; see [`touch`](CopyingMemory::touch).
    fn touch_data(
        &mut self,
        pages: &[u32],
        is_write: bool,
        gas: &mut GasCounter,
    ) -> Result<(), TouchFault> {
        // Accessibility-all (before any charge): every page must be a
        // declared data page; a write additionally needs it writable.
        for &p in pages {
            match self.page_index(p) {
                Some(i) => {
                    let pm = self.perms[i];
                    if pm == perm::NONE || (is_write && pm != perm::RW) {
                        return Err(TouchFault);
                    }
                }
                None => return Err(TouchFault),
            }
        }

        // Materialize-all. Read-only (pinned-cap) pages charge no per-fault
        // #3 — read-only page-in is accounted eagerly at the CALL; only their
        // residency is implicit. Copy-on-write (writable) pages stay per-page:
        // a write copies one page and charges `COW_COST`. A write to a
        // read-only page was excluded by the perm gate above.
        let mut total: u64 = 0;
        for &p in pages {
            let i = self.page_index(p).expect("checked accessible above");
            if self.perms[i] != perm::RO {
                let state = crate::mat::PageState::from_u8(self.mat_state[i]);
                let (charge, next) =
                    crate::mat::charge_for(state, crate::mat::PageKind::UnpinnedCapCow, is_write)
                        .expect("non-pinned access pre-checked accessible");
                total += charge;
                self.mat_state[i] = next.as_u8();
            }
        }
        gas.charge(total)
            .expect("#3 materialization charge within block reserve");
        Ok(())
    }

    /// `#3` for a CODE-region access: `PinnedCapRo`, read-only. A read
    /// charges nothing (read-only page-in is accounted eagerly at the CALL),
    /// a write hard-faults, and a read straddling out of the region faults
    /// charging nothing (all-or-nothing). Mirrors the recompiler's lazy code
    /// materialization (which likewise maps code pages without a per-fault
    /// charge).
    fn touch_code(&self, pages: &[u32], is_write: bool) -> Result<(), TouchFault> {
        // Code is read-only: any write hard-faults (charging nothing).
        if is_write {
            return Err(TouchFault);
        }
        // Accessibility-all: every page in the set must be a code page. A
        // read charges no #3 (read-only page-in is accounted at the CALL).
        for &p in pages {
            if !self.is_code_page(p) {
                return Err(TouchFault);
            }
        }
        Ok(())
    }

    /// Category-#3 first-touch for a `width`-byte **read**. See `touch`.
    #[inline]
    pub fn touch_read(
        &mut self,
        addr: u32,
        width: u32,
        gas: &mut GasCounter,
    ) -> Result<(), TouchFault> {
        self.touch(addr, width, false, gas)
    }

    /// Category-#3 first-touch for a `width`-byte **write**. See `touch`.
    #[inline]
    pub fn touch_write(
        &mut self,
        addr: u32,
        width: u32,
        gas: &mut GasCounter,
    ) -> Result<(), TouchFault> {
        self.touch(addr, width, true, gas)
    }

    // ---- Fast-path read helpers (inline; single bounds check + raw pointer load). ----

    #[inline(always)]
    pub fn read_u8(&self, addr: u32) -> Option<u8> {
        let a = self.off(addr);
        if a < self.flat_mem.len() {
            // SAFETY: bounds-checked.
            Some(unsafe { *self.flat_mem.get_unchecked(a) })
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn read_u16_le(&self, addr: u32) -> Option<u16> {
        let a = self.off(addr);
        if a + 2 <= self.flat_mem.len() {
            Some(unsafe { self.flat_mem.as_ptr().add(a).cast::<u16>().read_unaligned() })
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn read_u32_le(&self, addr: u32) -> Option<u32> {
        let a = self.off(addr);
        if a + 4 <= self.flat_mem.len() {
            Some(unsafe { self.flat_mem.as_ptr().add(a).cast::<u32>().read_unaligned() })
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn read_u64_le(&self, addr: u32) -> Option<u64> {
        let a = self.off(addr);
        if a + 8 <= self.flat_mem.len() {
            Some(unsafe { self.flat_mem.as_ptr().add(a).cast::<u64>().read_unaligned() })
        } else {
            None
        }
    }

    // ---- Fast-path write helpers. ----

    #[inline(always)]
    pub fn write_u8(&mut self, addr: u32, val: u8) -> bool {
        let a = self.off(addr);
        if a < self.flat_mem.len() {
            unsafe {
                *self.flat_mem.get_unchecked_mut(a) = val;
            }
            true
        } else {
            false
        }
    }

    #[inline(always)]
    pub fn write_u16_le(&mut self, addr: u32, val: u16) -> bool {
        let a = self.off(addr);
        if a + 2 <= self.flat_mem.len() {
            unsafe {
                self.flat_mem
                    .as_mut_ptr()
                    .add(a)
                    .cast::<u16>()
                    .write_unaligned(val);
            }
            true
        } else {
            false
        }
    }

    #[inline(always)]
    pub fn write_u32_le(&mut self, addr: u32, val: u32) -> bool {
        let a = self.off(addr);
        if a + 4 <= self.flat_mem.len() {
            unsafe {
                self.flat_mem
                    .as_mut_ptr()
                    .add(a)
                    .cast::<u32>()
                    .write_unaligned(val);
            }
            true
        } else {
            false
        }
    }

    #[inline(always)]
    pub fn write_u64_le(&mut self, addr: u32, val: u64) -> bool {
        let a = self.off(addr);
        if a + 8 <= self.flat_mem.len() {
            unsafe {
                self.flat_mem
                    .as_mut_ptr()
                    .add(a)
                    .cast::<u64>()
                    .write_unaligned(val);
            }
            true
        } else {
            false
        }
    }

    /// Declare a mapped region at `[start, start + size)` with
    /// per-page permissions `access` and optional initial bytes.
    ///
    /// - `start` and `size` must each be multiples of [`PAGE_SIZE`].
    /// - Grows `flat_mem` to cover `start + size` if necessary
    ///   (newly-grown bytes are zero-initialized; their pages
    ///   default to [`perm::NONE`] before this call sets them).
    /// - Sets pages in `[start / PAGE_SIZE, (start + size) /
    ///   PAGE_SIZE)` to the permission byte for `access`.
    /// - If `init` is `Some(bytes)`, copies `bytes[..bytes.len()
    ///   .min(size)]` into `flat_mem[start..]`; the rest of the
    ///   region remains zero-filled (matches the DataCap canonical
    ///   form: trailing zeros are stripped from `content`, but the
    ///   logical `size` may be larger).
    pub fn map_region(
        &mut self,
        start: u64,
        size: u64,
        access: Access,
        init: Option<&[u8]>,
    ) -> Result<(), MapError> {
        let page = PAGE_SIZE as u64;
        if !start.is_multiple_of(page) {
            return Err(MapError::UnalignedStart(start));
        }
        if !size.is_multiple_of(page) {
            return Err(MapError::UnalignedSize(size));
        }
        if start < u64::from(self.base) {
            return Err(MapError::UnalignedStart(start));
        }
        // Work in offsets relative to `base` (the buffer covers
        // `[base, base + flat_mem.len())`).
        let rel_start = start - u64::from(self.base);
        let rel_end = rel_start.checked_add(size).ok_or(MapError::Overflow)?;
        let rel_end_usize: usize = rel_end.try_into().map_err(|_| MapError::Overflow)?;

        // Grow flat_mem + perms (+ mat_state) to cover [0, rel_end)
        // (relative to base). New pages default to NONE perm and the
        // `NotPresent` materialization state (tag 0).
        if rel_end_usize > self.flat_mem.len() {
            self.flat_mem.resize(rel_end_usize, 0);
            let needed_pages = rel_end_usize.div_ceil(PAGE_SIZE as usize);
            if self.perms.len() < needed_pages {
                self.perms.resize(needed_pages, perm::NONE);
            }
            if self.mat_state.len() < needed_pages {
                self.mat_state
                    .resize(needed_pages, crate::mat::PageState::NotPresent.as_u8());
            }
        }

        // Set permissions on the affected pages.
        let perm_byte = match access {
            Access::ReadOnly => perm::RO,
            Access::ReadWrite => perm::RW,
        };
        let first_page = (rel_start / page) as usize;
        let last_page = ((rel_end / page) as usize).saturating_sub(1);
        if size > 0 {
            for p in first_page..=last_page {
                self.perms[p] = perm_byte;
            }
        }

        // Copy initial bytes if any. The destination starts as zero
        // either from initial allocation or the grow above, so any
        // trailing region beyond `init` is implicitly zero.
        if let Some(bytes) = init {
            let n = bytes.len().min(size as usize);
            let s = rel_start as usize;
            self.flat_mem[s..s + n].copy_from_slice(&bytes[..n]);
        }

        Ok(())
    }

    // ---- Slow-path helpers (for tests / non-hot paths). ----

    /// Read `len` bytes from `addr`. Returns `Err` on out-of-range.
    pub fn read(&self, addr: u32, len: usize) -> Result<Vec<u8>, MemAccess> {
        let a = self.off(addr);
        let end = a
            .checked_add(len)
            .ok_or(MemAccess::PageFault(addr & !(PAGE_SIZE - 1)))?;
        if end > self.flat_mem.len() {
            return Err(MemAccess::PageFault(addr & !(PAGE_SIZE - 1)));
        }
        Ok(self.flat_mem[a..end].to_vec())
    }

    /// Write `data` starting at `addr`. Returns `Err` on out-of-range
    /// or write-protected page. Writes are NOT rolled back on partial
    /// failure (test-only API).
    pub fn write(&mut self, addr: u32, data: &[u8]) -> Result<(), MemAccess> {
        let a = self.off(addr);
        let end = a
            .checked_add(data.len())
            .ok_or(MemAccess::PageFault(addr & !(PAGE_SIZE - 1)))?;
        if end > self.flat_mem.len() {
            return Err(MemAccess::PageFault(addr & !(PAGE_SIZE - 1)));
        }
        // Check perms per page touched.
        let start_page = a / (PAGE_SIZE as usize);
        let last_page = (end - 1) / (PAGE_SIZE as usize);
        for p in start_page..=last_page {
            if self.perms.get(p).copied().unwrap_or(perm::NONE) != perm::RW {
                return Err(MemAccess::WriteProtected((p as u32) * PAGE_SIZE));
            }
        }
        self.flat_mem[a..end].copy_from_slice(data);
        Ok(())
    }
}

// `Memory` impl delegates to inherent methods via UFCS (no name
// clash, no recursion). All bodies are `#[inline(always)]` so trait
// dispatch is zero-cost after monomorphisation.
impl Memory for CopyingMemory {
    #[inline(always)]
    fn read_u8(&self, addr: u32) -> Option<u8> {
        CopyingMemory::read_u8(self, addr)
    }
    #[inline(always)]
    fn read_u16_le(&self, addr: u32) -> Option<u16> {
        CopyingMemory::read_u16_le(self, addr)
    }
    #[inline(always)]
    fn read_u32_le(&self, addr: u32) -> Option<u32> {
        CopyingMemory::read_u32_le(self, addr)
    }
    #[inline(always)]
    fn read_u64_le(&self, addr: u32) -> Option<u64> {
        CopyingMemory::read_u64_le(self, addr)
    }
    #[inline(always)]
    fn write_u8(&mut self, addr: u32, val: u8) -> bool {
        CopyingMemory::write_u8(self, addr, val)
    }
    #[inline(always)]
    fn write_u16_le(&mut self, addr: u32, val: u16) -> bool {
        CopyingMemory::write_u16_le(self, addr, val)
    }
    #[inline(always)]
    fn write_u32_le(&mut self, addr: u32, val: u32) -> bool {
        CopyingMemory::write_u32_le(self, addr, val)
    }
    #[inline(always)]
    fn write_u64_le(&mut self, addr: u32, val: u64) -> bool {
        CopyingMemory::write_u64_le(self, addr, val)
    }
    #[inline]
    fn map_region(
        &mut self,
        start: u64,
        size: u64,
        access: Access,
        init: Option<&[u8]>,
    ) -> Result<(), MapError> {
        CopyingMemory::map_region(self, start, size, access, init)
    }
    #[inline]
    fn perm_of(&self, addr: u32) -> u8 {
        CopyingMemory::perm_of(self, addr)
    }
    #[inline]
    fn read(&self, addr: u32, len: usize) -> Result<Vec<u8>, MemAccess> {
        CopyingMemory::read(self, addr, len)
    }
    #[inline]
    fn write(&mut self, addr: u32, data: &[u8]) -> Result<(), MemAccess> {
        CopyingMemory::write(self, addr, data)
    }
    #[inline]
    fn touch_read(
        &mut self,
        addr: u32,
        width: u32,
        gas: &mut GasCounter,
    ) -> Result<(), TouchFault> {
        CopyingMemory::touch_read(self, addr, width, gas)
    }
    #[inline]
    fn touch_write(
        &mut self,
        addr: u32,
        width: u32,
        gas: &mut GasCounter,
    ) -> Result<(), TouchFault> {
        CopyingMemory::touch_write(self, addr, width, gas)
    }
}
