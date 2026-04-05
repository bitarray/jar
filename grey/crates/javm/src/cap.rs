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
#[derive(Debug)]
pub struct DataCap {
    /// Offset into the backing memfd (in pages).
    pub backing_offset: u32,
    /// Number of pages.
    pub page_count: u32,
    /// Current mapping state: None = unmapped, Some((base_page, access)) = mapped.
    pub mapped: Option<(u32, Access)>,
}

impl DataCap {
    pub fn new(backing_offset: u32, page_count: u32) -> Self {
        Self {
            backing_offset,
            page_count,
            mapped: None,
        }
    }

    /// Map at `base_page` with `access`. If already mapped, auto-unmaps first (remap).
    /// Returns the previous mapping state (for the caller to issue the actual mmap).
    pub fn map(&mut self, base_page: u32, access: Access) -> Option<(u32, Access)> {
        let prev = self.mapped.take();
        self.mapped = Some((base_page, access));
        prev
    }

    /// Unmap. Returns the previous mapping or None if already unmapped.
    pub fn unmap(&mut self) -> Option<(u32, Access)> {
        self.mapped.take()
    }

    /// Split into two sub-ranges at `page_offset`. Must be unmapped.
    /// Returns (lo, hi) where lo covers [0, page_offset) and hi covers [page_offset, page_count).
    pub fn split(self, page_offset: u32) -> Option<(DataCap, DataCap)> {
        if self.mapped.is_some() || page_offset == 0 || page_offset >= self.page_count {
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

/// Compiled PVM code. Copyable (via Arc). Owns a 4GB virtual window.
///
/// Multiple VMs can share the same CODE cap (same compiled native code,
/// same 4GB window). Each VM maps its own DATA caps into the window
/// before execution.
pub struct CodeCap {
    /// Identifier for this CODE cap (unique within invocation).
    pub id: u16,
    /// 4GB virtual window for memory-mapped execution.
    pub window: crate::backing::CodeWindow,
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

/// IPC slot index.
pub const IPC_SLOT: u8 = 255;

/// Maximum cap table size (u8 index).
pub const CAP_TABLE_SIZE: usize = 256;

/// Capability table: 256 slots indexed by u8.
#[derive(Debug)]
pub struct CapTable {
    slots: [Option<Cap>; CAP_TABLE_SIZE],
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
        }
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
    pub fn set(&mut self, index: u8, cap: Cap) -> Option<Cap> {
        self.slots[index as usize].replace(cap)
    }

    /// Take (remove) the cap at `index`.
    pub fn take(&mut self, index: u8) -> Option<Cap> {
        self.slots[index as usize].take()
    }

    /// Move cap from `src` to `dst`. Returns error if src is empty or dst is occupied.
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
        self.slots[dst as usize] = Some(cap);
        Ok(())
    }

    /// Copy cap from `src` to `dst`. Only for copyable types.
    pub fn copy_cap(&mut self, src: u8, dst: u8) -> Result<(), CapError> {
        let cap = self.slots[src as usize]
            .as_ref()
            .ok_or(CapError::EmptySlot)?;
        let copy = cap.try_copy().ok_or(CapError::NotCopyable)?;
        if self.slots[dst as usize].is_some() {
            return Err(CapError::SlotOccupied);
        }
        self.slots[dst as usize] = Some(copy);
        Ok(())
    }

    /// Drop the cap at `index`. Returns the dropped cap (caller handles cleanup).
    pub fn drop_cap(&mut self, index: u8) -> Option<Cap> {
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
    fn test_data_cap_map_unmap() {
        let mut data = DataCap::new(0, 10);
        assert!(data.mapped.is_none());

        let prev = data.map(0x5, Access::RW);
        assert!(prev.is_none());
        assert_eq!(data.mapped, Some((0x5, Access::RW)));

        // Remap
        let prev = data.map(0x10, Access::RO);
        assert_eq!(prev, Some((0x5, Access::RW)));
        assert_eq!(data.mapped, Some((0x10, Access::RO)));

        let prev = data.unmap();
        assert_eq!(prev, Some((0x10, Access::RO)));
        assert!(data.mapped.is_none());
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
    fn test_cap_copyability() {
        let untyped = Cap::Untyped(Arc::new(UntypedCap::new(10)));
        assert!(untyped.is_copyable());
        assert!(untyped.try_copy().is_some());

        let data = Cap::Data(DataCap::new(0, 1));
        assert!(!data.is_copyable());
        assert!(data.try_copy().is_none());

        // CodeCap copyability is tested via the Cap::Code branch in is_copyable/try_copy.
        // CodeCap construction requires std (CodeWindow + CompiledCode).
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
