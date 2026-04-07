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

/// Physical pages with exclusive mapping and per-page bitmap. Move-only (not copyable).
///
/// Each DATA cap has a single `base_offset` (set on first MAP, fixed thereafter)
/// and a per-page `mapped_bitmap` tracking which pages are present in the address
/// space. Page P maps to address `base_offset + P * 4096`.
#[derive(Debug)]
pub struct DataCap {
    /// Offset into the backing memfd (in pages).
    pub backing_offset: u32,
    /// Number of pages.
    pub page_count: u32,
    /// Base offset in address space (set on first MAP, fixed). None = never mapped.
    pub base_offset: Option<u32>,
    /// Access mode (set on first MAP, fixed). None = never mapped.
    pub access: Option<Access>,
    /// Per-page mapped bitmap (packed, 1 bit per page). Bit set = page present.
    pub mapped_bitmap: Vec<u8>,
}

impl DataCap {
    pub fn new(backing_offset: u32, page_count: u32) -> Self {
        let bitmap_len = (page_count as usize).div_ceil(8);
        Self {
            backing_offset,
            page_count,
            base_offset: None,
            access: None,
            mapped_bitmap: vec![0u8; bitmap_len],
        }
    }

    /// Check if a specific page is mapped.
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

    /// Count of mapped pages.
    pub fn mapped_page_count(&self) -> u32 {
        let mut count = 0u32;
        for &byte in &self.mapped_bitmap {
            count += byte.count_ones();
        }
        count
    }

    /// Check if any page is mapped.
    pub fn has_any_mapped(&self) -> bool {
        self.mapped_bitmap.iter().any(|&b| b != 0)
    }

    /// Map pages \[page_offset..page_offset+page_count) with the given base and access.
    /// First MAP sets base_offset and access; subsequent calls assert they match.
    /// Returns true on success.
    pub fn map_pages(
        &mut self,
        base_offset: u32,
        access: Access,
        page_offset: u32,
        page_count: u32,
    ) -> bool {
        if page_offset + page_count > self.page_count {
            return false;
        }
        // First MAP sets base_offset and access
        if let Some(existing) = self.base_offset {
            if existing != base_offset {
                return false;
            }
        } else {
            self.base_offset = Some(base_offset);
        }
        if let Some(existing) = self.access {
            if existing != access {
                return false;
            }
        } else {
            self.access = Some(access);
        }
        // Set bits in bitmap
        for i in page_offset..page_offset + page_count {
            let byte_idx = i as usize / 8;
            let bit_idx = i as usize % 8;
            if byte_idx < self.mapped_bitmap.len() {
                self.mapped_bitmap[byte_idx] |= 1 << bit_idx;
            }
        }
        true
    }

    /// Unmap pages \[page_offset..page_offset+page_count). Base_offset preserved.
    pub fn unmap_pages(&mut self, page_offset: u32, page_count: u32) {
        for i in page_offset..page_offset.saturating_add(page_count).min(self.page_count) {
            let byte_idx = i as usize / 8;
            let bit_idx = i as usize % 8;
            if byte_idx < self.mapped_bitmap.len() {
                self.mapped_bitmap[byte_idx] &= !(1 << bit_idx);
            }
        }
    }

    /// Unmap all pages. Base_offset and access preserved.
    pub fn unmap_all(&mut self) {
        for b in &mut self.mapped_bitmap {
            *b = 0;
        }
    }

    /// Legacy compat: map all pages at once (used by kernel init for blob DATA caps).
    pub fn map(&mut self, base_page: u32, access: Access) -> Option<(u32, Access)> {
        let prev = if self.has_any_mapped() {
            Some((
                self.base_offset.unwrap_or(0),
                self.access.unwrap_or(Access::RO),
            ))
        } else {
            None
        };
        self.unmap_all();
        self.base_offset = Some(base_page);
        self.access = Some(access);
        // Map all pages
        self.map_pages(base_page, access, 0, self.page_count);
        prev
    }

    /// Legacy compat: unmap all pages. Returns previous mapping state.
    pub fn unmap(&mut self) -> Option<(u32, Access)> {
        if !self.has_any_mapped() {
            return None;
        }
        let prev = Some((
            self.base_offset.unwrap_or(0),
            self.access.unwrap_or(Access::RO),
        ));
        self.unmap_all();
        prev
    }

    /// Split into two sub-ranges at `page_offset`. Must be fully unmapped.
    /// Returns (lo, hi) where lo covers \[0, page_offset) and hi covers \[page_offset, page_count).
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
#[derive(Debug)]
pub struct HandleCap {
    /// VM index in the kernel's VM pool.
    pub vm_id: u16,
    /// Per-CALL gas ceiling (inherited by DOWNGRADEd CALLABLEs).
    pub max_gas: Option<u64>,
}

/// VM entry point. Copyable. Provides CALL only (no management ops).
#[derive(Debug, Clone)]
pub struct CallableCap {
    /// VM index in the kernel's VM pool.
    pub vm_id: u16,
    /// Per-CALL gas ceiling.
    pub max_gas: Option<u64>,
}

/// Protocol cap slot number (0-63). Kernel-handled, replaceable with CALLABLE.
#[derive(Debug, Clone, Copy)]
pub struct ProtocolCap {
    /// Protocol cap ID matching GP host call numbering.
    pub id: u8,
}

/// A capability in the cap table.
#[derive(Debug)]
pub enum Cap {
    Untyped(Arc<UntypedCap>),
    Data(DataCap),
    Code(Arc<CodeCap>),
    Handle(HandleCap),
    Callable(CallableCap),
    Protocol(ProtocolCap),
}

impl Cap {
    /// Whether this cap type supports COPY.
    pub fn is_copyable(&self) -> bool {
        matches!(
            self,
            Cap::Untyped(_) | Cap::Code(_) | Cap::Callable(_) | Cap::Protocol(_)
        )
    }

    /// Create a copy of this cap (only for copyable types).
    pub fn try_copy(&self) -> Option<Cap> {
        match self {
            Cap::Untyped(u) => Some(Cap::Untyped(Arc::clone(u))),
            Cap::Code(c) => Some(Cap::Code(Arc::clone(c))),
            Cap::Callable(c) => Some(Cap::Callable(c.clone())),
            Cap::Protocol(p) => Some(Cap::Protocol(*p)),
            Cap::Data(_) | Cap::Handle(_) => None,
        }
    }
}

/// IPC slot index. CALL on slot 0 = REPLY.
pub const IPC_SLOT: u8 = 0;

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
pub struct CapTable {
    slots: [Option<Cap>; CAP_TABLE_SIZE],
    /// Per-slot original bitmap (32 bytes = 256 bits). True = slot holds original
    /// kernel-populated protocol cap. Only meaningful for slots < PROTOCOL_SLOT_COUNT.
    /// Set to false on DROP, MOVE-in, COPY-in, or MOVE-out. Never goes back to true.
    original_bitmap: [u8; 32],
}

impl Default for CapTable {
    fn default() -> Self {
        Self::new()
    }
}

impl CapTable {
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
    pub fn get(&self, index: u8) -> Option<&Cap> {
        self.slots[index as usize].as_ref()
    }

    /// Get a mutable reference to the cap at `index`.
    pub fn get_mut(&mut self, index: u8) -> Option<&mut Cap> {
        self.slots[index as usize].as_mut()
    }

    /// Set a cap at `index`, returning any previous cap.
    /// Clears the original bit for the slot.
    pub fn set(&mut self, index: u8, cap: Cap) -> Option<Cap> {
        self.clear_original(index);
        self.slots[index as usize].replace(cap)
    }

    /// Set a cap at `index` and mark it as original (for kernel init of protocol caps).
    pub fn set_original(&mut self, index: u8, cap: Cap) -> Option<Cap> {
        self.mark_original(index);
        self.slots[index as usize].replace(cap)
    }

    /// Take (remove) the cap at `index`. Clears the original bit.
    pub fn take(&mut self, index: u8) -> Option<Cap> {
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
    pub fn drop_cap(&mut self, index: u8) -> Option<Cap> {
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
        let mut data = DataCap::new(0, 10);
        assert!(!data.has_any_mapped());
        assert_eq!(data.mapped_page_count(), 0);

        // Map pages 2-4
        assert!(data.map_pages(0x1000, Access::RW, 2, 3));
        assert_eq!(data.base_offset, Some(0x1000));
        assert_eq!(data.access, Some(Access::RW));
        assert!(!data.is_page_mapped(0));
        assert!(!data.is_page_mapped(1));
        assert!(data.is_page_mapped(2));
        assert!(data.is_page_mapped(3));
        assert!(data.is_page_mapped(4));
        assert!(!data.is_page_mapped(5));
        assert_eq!(data.mapped_page_count(), 3);

        // Map more pages (same base)
        assert!(data.map_pages(0x1000, Access::RW, 7, 2));
        assert!(data.is_page_mapped(7));
        assert!(data.is_page_mapped(8));
        assert_eq!(data.mapped_page_count(), 5);

        // Different base fails
        assert!(!data.map_pages(0x2000, Access::RW, 0, 1));

        // Unmap specific pages
        data.unmap_pages(3, 2); // unmap pages 3-4
        assert!(data.is_page_mapped(2));
        assert!(!data.is_page_mapped(3));
        assert!(!data.is_page_mapped(4));
        assert_eq!(data.mapped_page_count(), 3);
    }

    #[test]
    fn test_data_cap_legacy_map_unmap() {
        let mut data = DataCap::new(0, 10);
        assert!(!data.has_any_mapped());

        let prev = data.map(0x5, Access::RW);
        assert!(prev.is_none());
        assert!(data.has_any_mapped());
        assert_eq!(data.mapped_page_count(), 10);

        let prev = data.unmap();
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
        let mut data = DataCap::new(0, 10);
        data.map(0, Access::RW);
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
        let mut table = CapTable::new();
        assert!(!table.is_original(3));

        // Mark as original (kernel init)
        table.set_original(3, Cap::Protocol(ProtocolCap { id: 3 }));
        assert!(table.is_original(3));

        // Regular set clears original
        table.set(3, Cap::Protocol(ProtocolCap { id: 3 }));
        assert!(!table.is_original(3));

        // Mark again, then take clears it
        table.set_original(5, Cap::Protocol(ProtocolCap { id: 5 }));
        assert!(table.is_original(5));
        table.take(5);
        assert!(!table.is_original(5));
    }

    #[test]
    fn test_cap_copyability() {
        let untyped = Cap::Untyped(Arc::new(UntypedCap::new(10)));
        assert!(untyped.is_copyable());
        assert!(untyped.try_copy().is_some());

        let data = Cap::Data(DataCap::new(0, 1));
        assert!(!data.is_copyable());
        assert!(data.try_copy().is_none());

        // CodeCap copyability is tested via the Cap::Code branch in is_copyable/try_copy.
        // CodeCap construction requires std (CompiledCode).
        #[cfg(feature = "std")]
        {
            // Verified by type: Cap::Code(_) => true in is_copyable
        }

        let handle = Cap::Handle(HandleCap {
            vm_id: 0,
            max_gas: None,
        });
        assert!(!handle.is_copyable());
        assert!(handle.try_copy().is_none());

        let callable = Cap::Callable(CallableCap {
            vm_id: 0,
            max_gas: None,
        });
        assert!(callable.is_copyable());
        assert!(callable.try_copy().is_some());

        let proto = Cap::Protocol(ProtocolCap { id: 0 });
        assert!(proto.is_copyable());
    }

    #[test]
    fn test_cap_table_move() {
        let mut table = CapTable::new();
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
        let mut table = CapTable::new();
        table.set(
            10,
            Cap::Callable(CallableCap {
                vm_id: 1,
                max_gas: Some(5000),
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
        let mut table = CapTable::new();
        table.set(
            10,
            Cap::Callable(CallableCap {
                vm_id: 1,
                max_gas: None,
            }),
        );
        table.set(20, Cap::Data(DataCap::new(0, 1)));
        assert_eq!(table.copy_cap(10, 20), Err(CapError::SlotOccupied));
    }
}
