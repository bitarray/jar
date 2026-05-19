//! Guest-readable directory of cache-resident Cap::Instance state.
//!
//! Lives at [`super::INSTANCE_INDEX_OFFSET`] in the cache region.
//! Host writes entries when publishing a Cap; guest scans linearly
//! when resolving an invocation packet's `instance_hash` into VAs.
//!
//! V0 design: fixed-size flat array of [`MAX_INDEX_SLOTS`] (16)
//! slots, scanned linearly. Each slot is `#[repr(C)]` so the byte
//! layout is identical on both host (std) and guest (no_std). When
//! the index hits the slot limit, the host's publish path returns
//! a `CacheFull` error.

use core::sync::atomic::{AtomicU8, Ordering};

/// Offset within the cache region where [`InstanceIndex`] starts.
pub const INSTANCE_INDEX_OFFSET: usize = 0x1000;

/// Maximum number of Cap::Instance entries the V0 cache can hold
/// simultaneously. Linear scan; trivially fast at this size.
pub const MAX_INDEX_SLOTS: usize = 16;

/// Maximum number of endpoints per Image the V0 cache stores
/// entry-PC for. `0` is the canonical "endpoint not defined" sentinel.
pub const MAX_ENDPOINTS: usize = 64;

/// Number of PVM general-purpose registers (φ[0]..φ[12]).
pub const NUM_REGS: usize = 13;

/// State for a single published Cap::Instance in the cache.
///
/// All `*_off` fields are byte offsets from the start of the cache
/// region. Each party (host or guest) reads the index and computes a
/// usable pointer as `cache_base_va + off`, where `cache_base_va` is
/// whatever VA *that party* mapped the region at. This sidesteps
/// any same-VA constraint between host and guest.
///
/// Slot status:
/// - `instance_hash == [0; 32]` → empty slot.
/// - All-zero hash is reserved as the empty sentinel; the chance of a
///   real Blake2b256-derived CapHash colliding with zero is
///   astronomically small and the spec treats the all-zero hash as an
///   invalid identity anyway.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IndexSlot {
    pub instance_hash: [u8; 32],

    pub code_off: u32,
    pub code_len: u32,
    pub bitmask_off: u32,
    pub bitmask_len: u32,
    pub jump_table_off: u32,
    pub jump_table_entries: u32,

    pub mem_size: u32,
    pub ro_off: u32,
    pub ro_len: u32,
    pub ro_start: u32,
    pub rw_off: u32,
    pub rw_len: u32,
    pub rw_start: u32,
    pub arg_off: u32,
    pub arg_len: u32,
    pub arg_start: u32,

    /// Dense table: `entry_pcs[i]` = PC for endpoint `i`. A value of
    /// `0` means endpoint not defined (real entry-PCs are never 0
    /// because PC 0 is reserved as "fallback PC" in our convention).
    pub entry_pcs: [u64; MAX_ENDPOINTS],

    /// Baseline regs to seed at endpoint entry (from
    /// `EndpointDef.initial_regs`). Caller-supplied register args
    /// overlay these for φ[7..=10].
    pub initial_regs: [u64; NUM_REGS],
}

impl IndexSlot {
    /// Size of a single slot in bytes.
    pub const SIZE: usize = core::mem::size_of::<IndexSlot>();
}

/// The directory at offset [`INSTANCE_INDEX_OFFSET`].
///
/// `#[repr(C)]` so the in-memory layout matches between host and
/// guest. The `_align` field bumps the alignment to 8 so all `u64`
/// fields inside slots are naturally aligned.
#[repr(C, align(8))]
pub struct InstanceIndex {
    /// Number of currently-populated slots (informational; the
    /// canonical "is slot occupied" check is `instance_hash != 0`).
    pub count: AtomicU8,
    _pad: [u8; 7],
    pub slots: [IndexSlot; MAX_INDEX_SLOTS],
}

impl InstanceIndex {
    /// Size of the index in bytes.
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Initialize an InstanceIndex at the given pointer. Zeroes the
    /// entire region.
    ///
    /// # Safety
    ///
    /// `ptr` must point at a writable region of at least [`SIZE`]
    /// bytes, suitably aligned for `InstanceIndex` (align 8).
    pub unsafe fn init_at(ptr: *mut InstanceIndex) {
        unsafe {
            core::ptr::write_bytes(ptr, 0, 1);
        }
    }

    /// Get a pointer to the slot at `idx`. Caller manages
    /// initialization / occupancy.
    ///
    /// # Safety
    ///
    /// `self` must be a valid live `InstanceIndex`; `idx` must be
    /// `< MAX_INDEX_SLOTS`.
    pub unsafe fn slot_ptr(this: *mut InstanceIndex, idx: usize) -> *mut IndexSlot {
        debug_assert!(idx < MAX_INDEX_SLOTS);
        unsafe { core::ptr::addr_of_mut!((*this).slots[idx]) }
    }

    /// Linear scan for a slot matching `instance_hash`. Returns the
    /// slot index and a pointer to it on hit.
    ///
    /// # Safety
    ///
    /// `this` must be a valid live `InstanceIndex`.
    pub unsafe fn find(
        this: *const InstanceIndex,
        instance_hash: &[u8; 32],
    ) -> Option<(usize, *const IndexSlot)> {
        for idx in 0..MAX_INDEX_SLOTS {
            let slot_ptr = unsafe { core::ptr::addr_of!((*this).slots[idx]) };
            let slot_hash = unsafe { &(*slot_ptr).instance_hash };
            if slot_hash == instance_hash {
                return Some((idx, slot_ptr));
            }
        }
        None
    }

    /// Find the first empty slot. Used by host publish.
    ///
    /// # Safety
    ///
    /// `this` must be a valid live `InstanceIndex`.
    pub unsafe fn first_empty(this: *const InstanceIndex) -> Option<usize> {
        for idx in 0..MAX_INDEX_SLOTS {
            let slot_ptr = unsafe { core::ptr::addr_of!((*this).slots[idx]) };
            let slot_hash = unsafe { &(*slot_ptr).instance_hash };
            if slot_hash == &[0u8; 32] {
                return Some(idx);
            }
        }
        None
    }

    /// Increment the populated-slot counter. Atomic so it's safe to
    /// publish a slot's contents first, then bump count last, giving
    /// the guest a release-acquire fence on top of the phase fence.
    #[inline]
    pub fn count_incr(&self) {
        self.count.fetch_add(1, Ordering::Release);
    }
}
