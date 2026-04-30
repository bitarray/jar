//! Capability types for the capability-based JAVM v2 execution model.
//!
//! Five program capability types:
//! - UNTYPED: bump allocator page pool (copyable)
//! - DATA: physical pages with exclusive mapping (move-only)
//! - CODE: compiled PVM code with 4GB virtual window (copyable)
//! - HANDLE: VM owner — unique, not copyable (CALL + management)
//! - CALLABLE: VM entry point — copyable (CALL only)

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

/// Memory access mode, set at MAP time (not at RETYPE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    RO,
    RW,
}

/// Bump allocator for physical page allocation. Copyable (via Arc).
///
/// All copies share the same atomic offset — allocation from any copy
/// advances the same bump pointer. Safe under cooperative scheduling.
#[derive(Debug)]
pub struct UntypedCap {
    /// Current bump offset (in pages). Atomic for Arc sharing.
    offset: AtomicU32,
    /// Total pages available.
    pub total: u32,
}

impl UntypedCap {
    pub fn new(total: u32) -> Self {
        Self {
            offset: AtomicU32::new(0),
            total,
        }
    }

    /// Allocate `n` pages from the bump allocator.
    /// Returns the backing offset (in pages) or None if exhausted.
    pub fn retype(&self, n: u32) -> Option<u32> {
        let old = self.offset.load(Ordering::Relaxed);
        let new = old.checked_add(n)?;
        if new > self.total {
            return None;
        }
        self.offset.store(new, Ordering::Relaxed);
        Some(old)
    }

    /// Remaining pages.
    pub fn remaining(&self) -> u32 {
        self.total - self.offset.load(Ordering::Relaxed)
    }
}

/// Physical pages with exclusive mapping. Move-only (not copyable).
///
/// Each DataCap carries per-VM mapping memory: `mappings` records where the
/// cap should be mapped if/when it lands in a given VM's persistent Frame.
/// `active_in` tracks the VM the cap is currently mapped in (None when
/// sitting in the ephemeral table or simply unmapped). `mapped_bitmap`
/// tracks per-page presence in `active_in`'s window.
///
/// On cross-frame MOVE, the kernel:
/// - unmaps from `active_in` (if any) using the recorded mapping.
/// - clears `active_in`, but **preserves `mappings`** so the cap remembers
///   where it should go if it later returns to that VM.
///
/// On arrival in a destination VM's persistent Frame, the kernel checks
/// `mappings[dst_vm]` — if recorded, auto-remaps at the saved
/// `(base, access)`; otherwise the cap stays unmapped (callee can MAP at
/// a fresh address, which writes a new `mappings[dst_vm]` entry).
#[derive(Debug, Clone, Copy)]
pub struct VmMapping {
    pub vm_id: crate::vm_pool::VmId,
    pub base: u32,
    pub access: Access,
}

#[derive(Debug)]
pub struct DataCap {
    /// Offset into the backing memfd (in pages).
    pub backing_offset: u32,
    /// Number of pages.
    pub page_count: u32,
    /// Per-VM mapping memory. Insertion-order; small (typically 1-3 entries).
    pub mappings: Vec<VmMapping>,
    /// VM the cap is currently mapped in. None when in ephemeral table or
    /// fully unmapped.
    pub active_in: Option<crate::vm_pool::VmId>,
    /// Per-page presence in `active_in`'s window. All zeros when
    /// `active_in.is_none()`.
    pub mapped_bitmap: Vec<u8>,
}

impl DataCap {
    pub fn new(backing_offset: u32, page_count: u32) -> Self {
        let bitmap_len = (page_count as usize).div_ceil(8);
        Self {
            backing_offset,
            page_count,
            mappings: Vec::new(),
            active_in: None,
            mapped_bitmap: vec![0u8; bitmap_len],
        }
    }

    /// Look up the recorded mapping for a VM, if any.
    pub fn mapping_for(&self, vm_id: crate::vm_pool::VmId) -> Option<(u32, Access)> {
        self.mappings
            .iter()
            .find(|m| m.vm_id == vm_id)
            .map(|m| (m.base, m.access))
    }

    /// Convenience: the active VM's recorded mapping.
    pub fn active_mapping(&self) -> Option<(u32, Access)> {
        self.active_in.and_then(|vm| self.mapping_for(vm))
    }

    /// Check if a specific page is mapped (in the active VM's window).
    pub fn is_page_mapped(&self, page_idx: u32) -> bool {
        if page_idx >= self.page_count {
            return false;
        }
        let byte_idx = page_idx as usize / 8;
        let bit_idx = page_idx as usize % 8;
        self.mapped_bitmap
            .get(byte_idx)
            .is_some_and(|b| b & (1 << bit_idx) != 0)
    }

    /// Count of mapped pages (in the active VM).
    pub fn mapped_page_count(&self) -> u32 {
        self.mapped_bitmap.iter().map(|b| b.count_ones()).sum()
    }

    /// Check if any page is mapped (in the active VM).
    pub fn has_any_mapped(&self) -> bool {
        self.mapped_bitmap.iter().any(|&b| b != 0)
    }

    /// Insert or assert a (base, access) mapping for `vm_id`.
    /// Returns false if `vm_id` already has a different mapping recorded.
    fn record_mapping(&mut self, vm_id: crate::vm_pool::VmId, base: u32, access: Access) -> bool {
        if let Some(existing) = self.mappings.iter().find(|m| m.vm_id == vm_id) {
            existing.base == base && existing.access == access
        } else {
            self.mappings.push(VmMapping {
                vm_id,
                base,
                access,
            });
            true
        }
    }

    /// Forget a recorded mapping (without touching bitmap or active_in).
    pub fn forget_mapping(&mut self, vm_id: crate::vm_pool::VmId) {
        self.mappings.retain(|m| m.vm_id != vm_id);
    }

    fn set_bits(&mut self, page_offset: u32, page_count: u32) {
        for i in page_offset..page_offset + page_count {
            let byte_idx = i as usize / 8;
            let bit_idx = i as usize % 8;
            if byte_idx < self.mapped_bitmap.len() {
                self.mapped_bitmap[byte_idx] |= 1 << bit_idx;
            }
        }
    }

    fn clear_bits(&mut self, page_offset: u32, page_count: u32) {
        for i in page_offset..page_offset.saturating_add(page_count).min(self.page_count) {
            let byte_idx = i as usize / 8;
            let bit_idx = i as usize % 8;
            if byte_idx < self.mapped_bitmap.len() {
                self.mapped_bitmap[byte_idx] &= !(1 << bit_idx);
            }
        }
    }

    /// MAP pages [page_offset..page_offset+page_count) in `vm_id`'s window.
    /// First MAP for a (cap, vm_id) pair records the `(base, access)`;
    /// subsequent MAPs in the same VM assert match. Sets `active_in` to
    /// `vm_id`. Returns false on bound violation, conflicting mapping, or
    /// active-in-different-VM violation.
    pub fn map_pages(
        &mut self,
        vm_id: crate::vm_pool::VmId,
        base: u32,
        access: Access,
        page_offset: u32,
        page_count: u32,
    ) -> bool {
        if page_offset + page_count > self.page_count {
            return false;
        }
        if let Some(other) = self.active_in
            && other != vm_id
        {
            // Cap is currently mapped in another VM — must unmap first.
            return false;
        }
        if !self.record_mapping(vm_id, base, access) {
            return false;
        }
        self.active_in = Some(vm_id);
        self.set_bits(page_offset, page_count);
        true
    }

    /// UNMAP pages in the active VM. Bitmap cleared for the range. Mapping
    /// memory preserved (so a future re-MAP at the same address asserts
    /// consistency, and a future re-arrival in this VM auto-remaps). When
    /// no pages remain mapped, `active_in` clears.
    pub fn unmap_pages(&mut self, page_offset: u32, page_count: u32) {
        self.clear_bits(page_offset, page_count);
        if !self.has_any_mapped() {
            self.active_in = None;
        }
    }

    /// Clear every page from the bitmap and the active VM. Mapping memory
    /// is preserved. Returns the (vm_id, base, access) the cap was active in,
    /// for the caller to pass to `BackingStore::unmap_pages`.
    pub fn unmap_all(&mut self) -> Option<(crate::vm_pool::VmId, u32, Access)> {
        let result = self
            .active_in
            .and_then(|vm| self.mapping_for(vm).map(|(b, a)| (vm, b, a)));
        for b in &mut self.mapped_bitmap {
            *b = 0;
        }
        self.active_in = None;
        result
    }

    /// On arrival in `vm_id`'s persistent Frame: if a mapping is recorded,
    /// mark all pages mapped and return `(base, access)` for the kernel to
    /// call `BackingStore::map_pages`. Otherwise returns None (cap stays
    /// unmapped; callee can explicitly MAP).
    pub fn auto_remap_for(&mut self, vm_id: crate::vm_pool::VmId) -> Option<(u32, Access)> {
        let (base, access) = self.mapping_for(vm_id)?;
        // Mark every page bit (caller does the actual mmap).
        for b in &mut self.mapped_bitmap {
            *b = 0xFF;
        }
        let bits_in_last = (self.page_count as usize) % 8;
        if bits_in_last != 0
            && let Some(last) = self.mapped_bitmap.last_mut()
        {
            *last &= (1u8 << bits_in_last) - 1;
        }
        self.active_in = Some(vm_id);
        Some((base, access))
    }

    /// Legacy compat: map all pages at once (used by kernel init for blob
    /// DATA caps and `handle_reply`'s auto-return). Records mapping for
    /// `vm_id`, marks all pages. Returns the prior active mapping if any.
    pub fn map(
        &mut self,
        vm_id: crate::vm_pool::VmId,
        base: u32,
        access: Access,
    ) -> Option<(crate::vm_pool::VmId, u32, Access)> {
        let prev = if self.has_any_mapped() {
            self.active_in
                .and_then(|vm| self.mapping_for(vm).map(|(b, a)| (vm, b, a)))
        } else {
            None
        };
        // Clear bitmap, then re-set after recording new mapping.
        for b in &mut self.mapped_bitmap {
            *b = 0;
        }
        self.active_in = None;
        if !self.record_mapping(vm_id, base, access) {
            // Conflicting prior mapping for this VM — refuse.
            return prev;
        }
        self.active_in = Some(vm_id);
        let pc = self.page_count;
        self.set_bits(0, pc);
        prev
    }

    /// Split into two sub-ranges at `page_offset`. Must be fully unmapped.
    /// Returns `(lo, hi)` where `lo` covers `[0, page_offset)` and `hi`
    /// covers `[page_offset, page_count)`. Mapping memory is dropped — the
    /// new caps start fresh.
    pub fn split(self, page_offset: u32) -> Option<(DataCap, DataCap)> {
        if self.has_any_mapped() || page_offset == 0 || page_offset >= self.page_count {
            return None;
        }
        let lo = DataCap::new(self.backing_offset, page_offset);
        let hi = DataCap::new(
            self.backing_offset + page_offset,
            self.page_count - page_offset,
        );
        Some((lo, hi))
    }
}

/// Compiled PVM code. Copyable (via Arc).
///
/// Windows are managed by the kernel's WindowPool, not by CODE caps.
/// Multiple VMs can share the same CODE cap (same compiled native code).
pub struct CodeCap {
    /// Identifier for this CODE cap (unique within invocation).
    pub id: u16,
    /// Compiled program — interpreter or recompiler backend.
    pub compiled: crate::backend::CompiledProgram,
    /// PVM jump table (for dynamic jump resolution).
    pub jump_table: Vec<u32>,
    /// PVM bitmask (basic block starts).
    pub bitmask: Vec<u8>,
}

impl core::fmt::Debug for CodeCap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CodeCap")
            .field("id", &self.id)
            .field("compiled", &self.compiled)
            .finish()
    }
}

/// VM owner handle. Unique per VM, not copyable. Provides CALL + management ops.
///
/// There is no `max_gas` ceiling — gas is shared across the whole
/// invocation via the `Capability::Gas` cap at ephemeral sub-slot 3.
/// Per-call gas restriction is achieved with the **park pattern**:
/// `MGMT_GAS_DERIVE` splits a portion off the live Gas cap into a
/// parked slot in the caller's Frame, the callee runs against the
/// reduced shared budget, and `MGMT_GAS_MERGE` recombines on return.
#[derive(Debug)]
pub struct HandleCap {
    /// VM ID in the kernel's arena (index + generation for stale detection).
    pub vm_id: crate::vm_pool::VmId,
}

/// VM entry point. Copyable. Provides CALL only (no management ops).
#[derive(Debug, Clone)]
pub struct CallableCap {
    /// VM ID in the kernel's arena (index + generation for stale detection).
    pub vm_id: crate::vm_pool::VmId,
}

/// Handle to the per-invocation ephemeral table — a 256-slot cap-table
/// shared by every VM in the call tree. Slot 0 of every VM's persistent
/// Frame holds an `EphemeralTable` cap. Not copyable (single shared
/// table per invocation), not movable (lifetime owned by the kernel).
#[derive(Debug, Clone)]
pub struct EphemeralTableCap {
    pub table_id: crate::vm_pool::EphemeralTableId,
}

/// Per-variant policy for `Cap::Protocol(P)` payloads.
///
/// javm consults these methods when handling cap-table mutation
/// management ecallis (COPY / MOVE / DROP). The default impls allow
/// every operation; consumers that want stricter rules (e.g. jar-kernel
/// rejecting copy of pinned caps) override the relevant method.
///
/// ## Foreign frames
///
/// Beyond the per-VM persistent Frame and the per-invocation ephemeral
/// table, hosts may expose a third frame kind: a "foreign" cap-table
/// the host (jar-kernel) backs with its own σ-resident structure
/// (Vault CNodes). A protocol cap can announce itself as a handle into
/// such a foreign frame by overriding [`ProtocolCapT::as_foreign_frame`];
/// when javm's resolve walk crosses through that cap, the resulting
/// `FrameId::Foreign(id)` is fed to a host-provided
/// [`ForeignCnode`] implementation for slot-level operations.
pub trait ProtocolCapT: Clone + core::fmt::Debug {
    /// Identifier the host uses to address one of its foreign frames.
    /// Implementors with no foreign frames use `()`.
    type ForeignFrameId: Copy + Eq + core::fmt::Debug;
    /// Operation-rights bag carried alongside a foreign-frame handle.
    /// The host adapter's slot-level methods consult this for policy
    /// (e.g. VaultRef rights). Implementors with no foreign frames
    /// use `()`.
    type FinalStepRights: Copy + Eq + core::fmt::Debug + Default;

    /// May the guest COPY this cap to another cap-table slot?
    fn is_copyable(&self) -> bool {
        true
    }
    /// May the guest MOVE this cap between cap-table slots?
    fn is_movable(&self) -> bool {
        true
    }
    /// May the guest DROP this cap?
    fn is_droppable(&self) -> bool {
        true
    }
    /// Derive a child Gas cap with `amount` units split off. Returns
    /// `None` if `self` is not a Gas-shaped cap or has insufficient
    /// `remaining`. The payload type decides what counts as Gas; default
    /// is "no Gas cap of this shape."
    fn gas_derive(&mut self, _amount: u64) -> Option<Self> {
        None
    }
    /// Merge `donor`'s gas into `self`. Returns `true` if both are
    /// Gas-shaped and the merge succeeded. On success, the caller
    /// should drop `donor`.
    fn gas_merge(&mut self, _donor: &Self) -> bool {
        false
    }
    /// If this cap is a handle into a foreign cap-table (e.g. a Vault
    /// CNode in jar-kernel), return the host's id for that frame plus
    /// the operation-rights bag the resolve walk should record at this
    /// step. javm's `cross_through` consults this on its fall-through
    /// arm so that hosts can extend the resolve walk without javm
    /// learning about Vaults / CNodes / etc.
    #[inline]
    fn as_foreign_frame(&self) -> Option<(Self::ForeignFrameId, Self::FinalStepRights)> {
        None
    }
}

/// `u8` is the default protocol-cap payload type used by tests, benches,
/// and javm-bench guests. The byte typically encodes the host-call
/// selector (1..=N), and `ecalli N` on slot N yields
/// `KernelResult::ProtocolCall { slot: N }`.
impl ProtocolCapT for u8 {
    type ForeignFrameId = ();
    type FinalStepRights = ();
}

// =============================================================================
// Foreign cnode trait — host-side hook for slot-level operations on a frame
// kind javm doesn't own (e.g. jar-kernel Vault CNodes).
// =============================================================================

/// Host adapter for foreign cap-tables. A type implementing this trait
/// translates between javm's `Cap<P>` value model and the host's own
/// slot storage (which may indirect through a registry, enforce rights,
/// etc.). javm calls these methods from `MGMT_MOVE` / `MGMT_COPY` /
/// `MGMT_DROP` ecallis when the resolve walk lands on a
/// `FrameId::Foreign`.
///
/// `id` identifies the host frame; `rights` carries the
/// operation-rights bag captured at the final crossing step, so the
/// host can enforce op-specific authority (e.g. VaultRef Grant /
/// Revoke / Derive). All methods may fail (return `None` / `Err`) and
/// javm reports `RESULT_WHAT` to the guest when they do.
pub trait ForeignCnode<P: ProtocolCapT> {
    /// Take the cap at `(id, slot)`. Empty slots return `None`. On
    /// `Some(_)` the host must have removed the cap from its frame
    /// (and updated any registry bookkeeping).
    fn fc_take(
        &mut self,
        id: P::ForeignFrameId,
        slot: u8,
        rights: P::FinalStepRights,
    ) -> Option<Cap<P>>;

    /// Place `cap` at `(id, slot)`. Returns `Err(cap)` if the host
    /// rejects placement (slot occupied, pinning violation, missing
    /// rights, non-persistable cap shape) — javm uses the returned
    /// cap to roll back the source slot.
    fn fc_set(
        &mut self,
        id: P::ForeignFrameId,
        slot: u8,
        rights: P::FinalStepRights,
        cap: Cap<P>,
    ) -> Result<(), Cap<P>>;

    /// Produce a copy (host-side derive) of the cap at `(id, slot)`.
    /// Empty slots / non-copyable caps return `None`.
    fn fc_clone(
        &mut self,
        id: P::ForeignFrameId,
        slot: u8,
        rights: P::FinalStepRights,
    ) -> Option<Cap<P>>;

    /// Drop the cap at `(id, slot)` (host-side revoke). Returns
    /// `false` if the slot is empty or the host refused (pinning,
    /// rights). Used for `MGMT_DROP` against a foreign slot, where
    /// the cap is destroyed rather than handed back to the guest.
    fn fc_drop(&mut self, id: P::ForeignFrameId, slot: u8, rights: P::FinalStepRights) -> bool;

    /// Whether the slot is empty (no cap held).
    fn fc_is_empty(&self, id: P::ForeignFrameId, slot: u8) -> bool;
}

/// Zero-sized default `ForeignCnode` for hosts (and tests / benches)
/// that don't expose any foreign frames. All methods fail silently —
/// `MGMT_MOVE` / etc. against a `FrameId::Foreign` simply report
/// `RESULT_WHAT` to the guest, since `as_foreign_frame()` defaults to
/// `None` and so no `Foreign` ref will ever be produced.
pub struct NoForeignCnode;

impl<P> ForeignCnode<P> for NoForeignCnode
where
    P: ProtocolCapT<ForeignFrameId = (), FinalStepRights = ()>,
{
    fn fc_take(&mut self, _id: (), _slot: u8, _rights: ()) -> Option<Cap<P>> {
        None
    }
    fn fc_set(&mut self, _id: (), _slot: u8, _rights: (), cap: Cap<P>) -> Result<(), Cap<P>> {
        Err(cap)
    }
    fn fc_clone(&mut self, _id: (), _slot: u8, _rights: ()) -> Option<Cap<P>> {
        None
    }
    fn fc_drop(&mut self, _id: (), _slot: u8, _rights: ()) -> bool {
        false
    }
    fn fc_is_empty(&self, _id: (), _slot: u8) -> bool {
        true
    }
}

/// A capability in the cap table.
///
/// Generic over the protocol-cap payload type `P`. The default `P = u8`
/// matches the legacy "protocol cap is just an id" shape; jar-kernel
/// substitutes a richer type that wraps both host-call selectors and
/// kernel cap data.
#[derive(Debug)]
pub enum Cap<P: ProtocolCapT = u8> {
    Untyped(Arc<UntypedCap>),
    Data(DataCap),
    Code(Arc<CodeCap>),
    Handle(HandleCap),
    Callable(CallableCap),
    EphemeralTable(EphemeralTableCap),
    Protocol(P),
}

impl<P: ProtocolCapT> Cap<P> {
    /// Whether this cap type supports COPY. Protocol caps consult `P`'s
    /// `is_copyable` hook.
    pub fn is_copyable(&self) -> bool {
        match self {
            Cap::Untyped(_) | Cap::Code(_) | Cap::Callable(_) => true,
            Cap::Data(_) | Cap::Handle(_) | Cap::EphemeralTable(_) => false,
            Cap::Protocol(p) => p.is_copyable(),
        }
    }

    /// Create a copy of this cap (only for copyable types). Protocol
    /// caps clone `P` only when `p.is_copyable()` is true.
    pub fn try_copy(&self) -> Option<Cap<P>> {
        match self {
            Cap::Untyped(u) => Some(Cap::Untyped(Arc::clone(u))),
            Cap::Code(c) => Some(Cap::Code(Arc::clone(c))),
            Cap::Callable(c) => Some(Cap::Callable(c.clone())),
            Cap::Protocol(p) if p.is_copyable() => Some(Cap::Protocol(p.clone())),
            Cap::Data(_) | Cap::Handle(_) | Cap::EphemeralTable(_) | Cap::Protocol(_) => None,
        }
    }
}

/// Slot 0 of every VM's persistent Frame is reserved for the
/// per-invocation `Cap::EphemeralTable` handle. `ecalli 0` (CALL on
/// slot 0) is REPLY by convention — the kernel never actually invokes
/// the EphemeralTable cap.
pub const EPHEMERAL_TABLE_SLOT: u8 = 0;

/// Maximum cap table size (u8 index).
pub const CAP_TABLE_SIZE: usize = 256;

/// Number of protocol cap slots (1-28). Slots 0-28 are checked by the original bitmap.
pub const PROTOCOL_SLOT_COUNT: usize = 29;

/// Capability table (CNode): 256 slots indexed by u8.
///
/// The `original_bitmap` tracks which protocol cap slots (0-28) hold their
/// original kernel-populated protocol cap. The compiler uses this for
/// fast-path inlining of ecalli on protocol caps.
#[derive(Debug)]
pub struct CapTable<P: ProtocolCapT = u8> {
    slots: [Option<Cap<P>>; CAP_TABLE_SIZE],
    /// Per-slot original bitmap (32 bytes = 256 bits). True = slot holds original
    /// kernel-populated protocol cap. Only meaningful for slots < PROTOCOL_SLOT_COUNT.
    /// Set to false on DROP, MOVE-in, COPY-in, or MOVE-out. Never goes back to true.
    original_bitmap: [u8; 32],
}

impl<P: ProtocolCapT> Default for CapTable<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: ProtocolCapT> CapTable<P> {
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| None),
            original_bitmap: [0u8; 32],
        }
    }

    /// Mark a slot as original (kernel-populated protocol cap).
    pub fn mark_original(&mut self, index: u8) {
        let byte_idx = index as usize / 8;
        let bit_idx = index as usize % 8;
        if byte_idx < 32 {
            self.original_bitmap[byte_idx] |= 1 << bit_idx;
        }
    }

    /// Clear the original bit for a slot.
    fn clear_original(&mut self, index: u8) {
        let byte_idx = index as usize / 8;
        let bit_idx = index as usize % 8;
        if byte_idx < 32 {
            self.original_bitmap[byte_idx] &= !(1 << bit_idx);
        }
    }

    /// Check if a slot is marked as original (unmodified protocol cap).
    pub fn is_original(&self, index: u8) -> bool {
        let byte_idx = index as usize / 8;
        let bit_idx = index as usize % 8;
        if byte_idx < 32 {
            self.original_bitmap[byte_idx] & (1 << bit_idx) != 0
        } else {
            false
        }
    }

    /// Get a reference to the original bitmap (for JitContext).
    pub fn original_bitmap(&self) -> &[u8; 32] {
        &self.original_bitmap
    }

    /// Get a reference to the cap at `index`.
    pub fn get(&self, index: u8) -> Option<&Cap<P>> {
        self.slots[index as usize].as_ref()
    }

    /// Get a mutable reference to the cap at `index`.
    pub fn get_mut(&mut self, index: u8) -> Option<&mut Cap<P>> {
        self.slots[index as usize].as_mut()
    }

    /// Set a cap at `index`, returning any previous cap.
    /// Clears the original bit for the slot.
    pub fn set(&mut self, index: u8, cap: Cap<P>) -> Option<Cap<P>> {
        self.clear_original(index);
        self.slots[index as usize].replace(cap)
    }

    /// Set a cap at `index` and mark it as original (for kernel init of protocol caps).
    pub fn set_original(&mut self, index: u8, cap: Cap<P>) -> Option<Cap<P>> {
        self.mark_original(index);
        self.slots[index as usize].replace(cap)
    }

    /// Take (remove) the cap at `index`. Clears the original bit.
    pub fn take(&mut self, index: u8) -> Option<Cap<P>> {
        self.clear_original(index);
        self.slots[index as usize].take()
    }

    /// Move cap from `src` to `dst`. Returns error if src is empty or dst is occupied.
    /// Clears original bits for both slots.
    pub fn move_cap(&mut self, src: u8, dst: u8) -> Result<(), CapError> {
        if src == dst {
            return Ok(());
        }
        let cap = self.slots[src as usize].take().ok_or(CapError::EmptySlot)?;
        if self.slots[dst as usize].is_some() {
            // Put it back
            self.slots[src as usize] = Some(cap);
            return Err(CapError::SlotOccupied);
        }
        self.clear_original(src);
        self.clear_original(dst);
        self.slots[dst as usize] = Some(cap);
        Ok(())
    }

    /// Copy cap from `src` to `dst`. Only for copyable types.
    /// Clears original bit for dst.
    pub fn copy_cap(&mut self, src: u8, dst: u8) -> Result<(), CapError> {
        let cap = self.slots[src as usize]
            .as_ref()
            .ok_or(CapError::EmptySlot)?;
        let copy = cap.try_copy().ok_or(CapError::NotCopyable)?;
        if self.slots[dst as usize].is_some() {
            return Err(CapError::SlotOccupied);
        }
        self.clear_original(dst);
        self.slots[dst as usize] = Some(copy);
        Ok(())
    }

    /// Drop the cap at `index`. Returns the dropped cap (caller handles cleanup).
    /// Clears the original bit.
    pub fn drop_cap(&mut self, index: u8) -> Option<Cap<P>> {
        self.clear_original(index);
        self.slots[index as usize].take()
    }

    /// Check if a slot is empty.
    pub fn is_empty(&self, index: u8) -> bool {
        self.slots[index as usize].is_none()
    }
}

/// Errors from cap table operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapError {
    /// Source slot is empty.
    EmptySlot,
    /// Destination slot is already occupied.
    SlotOccupied,
    /// Cap type does not support this operation.
    NotCopyable,
    /// Cap type mismatch for operation.
    TypeMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_untyped_retype() {
        let untyped = UntypedCap::new(100);
        assert_eq!(untyped.remaining(), 100);

        let offset = untyped.retype(10).unwrap();
        assert_eq!(offset, 0);
        assert_eq!(untyped.remaining(), 90);

        let offset = untyped.retype(90).unwrap();
        assert_eq!(offset, 10);
        assert_eq!(untyped.remaining(), 0);

        assert!(untyped.retype(1).is_none());
    }

    #[test]
    fn test_untyped_shared() {
        let untyped = Arc::new(UntypedCap::new(100));
        let copy = Arc::clone(&untyped);

        let o1 = untyped.retype(30).unwrap();
        assert_eq!(o1, 0);

        let o2 = copy.retype(30).unwrap();
        assert_eq!(o2, 30);

        assert_eq!(untyped.remaining(), 40);
        assert_eq!(copy.remaining(), 40);
    }

    #[test]
    fn test_data_cap_partial_map() {
        let vm = crate::vm_pool::VmId::ROOT;
        let mut data = DataCap::new(0, 10);
        assert!(!data.has_any_mapped());
        assert_eq!(data.mapped_page_count(), 0);

        // Map pages 2-4
        assert!(data.map_pages(vm, 0x1000, Access::RW, 2, 3));
        assert_eq!(data.mapping_for(vm), Some((0x1000, Access::RW)));
        assert_eq!(data.active_in, Some(vm));
        assert!(!data.is_page_mapped(0));
        assert!(!data.is_page_mapped(1));
        assert!(data.is_page_mapped(2));
        assert!(data.is_page_mapped(3));
        assert!(data.is_page_mapped(4));
        assert!(!data.is_page_mapped(5));
        assert_eq!(data.mapped_page_count(), 3);

        // Map more pages (same base) in the same VM
        assert!(data.map_pages(vm, 0x1000, Access::RW, 7, 2));
        assert!(data.is_page_mapped(7));
        assert!(data.is_page_mapped(8));
        assert_eq!(data.mapped_page_count(), 5);

        // Different base fails (assert match on existing mapping for vm)
        assert!(!data.map_pages(vm, 0x2000, Access::RW, 0, 1));

        // Unmap specific pages
        data.unmap_pages(3, 2); // unmap pages 3-4
        assert!(data.is_page_mapped(2));
        assert!(!data.is_page_mapped(3));
        assert!(!data.is_page_mapped(4));
        assert_eq!(data.mapped_page_count(), 3);
    }

    #[test]
    fn test_data_cap_legacy_map_unmap() {
        let vm = crate::vm_pool::VmId::ROOT;
        let mut data = DataCap::new(0, 10);
        assert!(!data.has_any_mapped());

        let prev = data.map(vm, 0x5, Access::RW);
        assert!(prev.is_none());
        assert!(data.has_any_mapped());
        assert_eq!(data.mapped_page_count(), 10);

        let prev = data.unmap_all();
        assert!(prev.is_some());
        assert!(!data.has_any_mapped());
    }

    #[test]
    fn test_data_cap_split() {
        let data = DataCap::new(100, 10);

        let (lo, hi) = data.split(4).unwrap();
        assert_eq!(lo.backing_offset, 100);
        assert_eq!(lo.page_count, 4);
        assert_eq!(hi.backing_offset, 104);
        assert_eq!(hi.page_count, 6);
    }

    #[test]
    fn test_data_cap_split_mapped_fails() {
        let vm = crate::vm_pool::VmId::ROOT;
        let mut data = DataCap::new(0, 10);
        data.map(vm, 0, Access::RW);
        assert!(data.split(5).is_none());
    }

    #[test]
    fn test_data_cap_split_boundary_fails() {
        let data = DataCap::new(0, 10);
        assert!(data.split(0).is_none());
        let data = DataCap::new(0, 10);
        assert!(data.split(10).is_none());
    }

    #[test]
    fn test_cap_table_original_bitmap() {
        let mut table: CapTable = CapTable::new();
        assert!(!table.is_original(3));

        // Mark as original (kernel init)
        table.set_original(3, Cap::Protocol(3u8));
        assert!(table.is_original(3));

        // Regular set clears original
        table.set(3, Cap::Protocol(3u8));
        assert!(!table.is_original(3));

        // Mark again, then take clears it
        table.set_original(5, Cap::Protocol(5u8));
        assert!(table.is_original(5));
        table.take(5);
        assert!(!table.is_original(5));
    }

    #[test]
    fn test_cap_copyability() {
        let untyped: Cap = Cap::Untyped(Arc::new(UntypedCap::new(10)));
        assert!(untyped.is_copyable());
        assert!(untyped.try_copy().is_some());

        let data: Cap = Cap::Data(DataCap::new(0, 1));
        assert!(!data.is_copyable());
        assert!(data.try_copy().is_none());

        // CodeCap copyability is tested via the Cap::Code branch in is_copyable/try_copy.
        // CodeCap construction requires std (CompiledCode).
        #[cfg(feature = "std")]
        {
            // Verified by type: Cap::Code(_) => true in is_copyable
        }

        let handle: Cap = Cap::Handle(HandleCap {
            vm_id: crate::vm_pool::VmId::new(0, 0),
        });
        assert!(!handle.is_copyable());
        assert!(handle.try_copy().is_none());

        let callable: Cap = Cap::Callable(CallableCap {
            vm_id: crate::vm_pool::VmId::new(0, 0),
        });
        assert!(callable.is_copyable());
        assert!(callable.try_copy().is_some());

        let proto: Cap = Cap::Protocol(0u8);
        assert!(proto.is_copyable());
    }

    #[test]
    fn test_cap_table_move() {
        let mut table: CapTable = CapTable::new();
        table.set(10, Cap::Data(DataCap::new(0, 5)));

        assert!(table.move_cap(10, 20).is_ok());
        assert!(table.is_empty(10));
        assert!(!table.is_empty(20));

        // Move to occupied slot fails
        table.set(30, Cap::Data(DataCap::new(5, 5)));
        assert_eq!(table.move_cap(20, 30), Err(CapError::SlotOccupied));
        // Original still in place
        assert!(!table.is_empty(20));
    }

    #[test]
    fn test_cap_table_copy() {
        let mut table: CapTable = CapTable::new();
        table.set(
            10,
            Cap::Callable(CallableCap {
                vm_id: crate::vm_pool::VmId::new(1, 0),
            }),
        );

        assert!(table.copy_cap(10, 20).is_ok());
        assert!(!table.is_empty(10)); // Original still there
        assert!(!table.is_empty(20)); // Copy placed

        // Copy non-copyable fails
        table.set(30, Cap::Data(DataCap::new(0, 1)));
        assert_eq!(table.copy_cap(30, 40), Err(CapError::NotCopyable));
    }

    #[test]
    fn test_cap_table_copy_occupied_fails() {
        let mut table: CapTable = CapTable::new();
        table.set(
            10,
            Cap::Callable(CallableCap {
                vm_id: crate::vm_pool::VmId::new(1, 0),
            }),
        );
        table.set(20, Cap::Data(DataCap::new(0, 1)));
        assert_eq!(table.copy_cap(10, 20), Err(CapError::SlotOccupied));
    }
}
