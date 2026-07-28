//! A bump allocator with an explicit reset.
//!
//! Programs that need `alloc` on a freestanding target need a
//! `#[global_allocator]`, and a bump arena is the cheapest thing that
//! works: allocation is a pointer add, and a program that runs once and
//! exits never needs to free.
//!
//! [`BumpAlloc::reset`] is what makes the arena re-usable. Without it a
//! program is single-shot per instance — the second invocation walks
//! off the end of the arena and the allocation fails, which surfaces as
//! a guest panic rather than anything legible. That matters for any
//! caller that invokes the same instance twice, benchmark harnesses
//! very much included: measuring steady-state execution means running
//! the same instance repeatedly.
//!
//! Resetting is not free of consequences: it invalidates every live
//! allocation at once. It is only sound at a point where nothing from
//! the previous invocation is still borrowed — i.e. at an entry point,
//! before any work begins. [`bump_allocator!`](crate::bump_allocator)
//! generates a `reset_heap()` for exactly that use.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;

/// A fixed-size bump arena of `N` bytes.
///
/// `dealloc` is a no-op; space is reclaimed only by [`reset`](Self::reset).
pub struct BumpAlloc<const N: usize> {
    heap: UnsafeCell<[u8; N]>,
    pos: UnsafeCell<usize>,
}

// SAFETY: PVM2 programs are single-threaded — the engine runs one
// instruction stream per instance and there is no way for a guest to
// create a thread. Without that, the `UnsafeCell` accesses below would
// need synchronization.
unsafe impl<const N: usize> Sync for BumpAlloc<N> {}

impl<const N: usize> BumpAlloc<N> {
    pub const fn new() -> Self {
        BumpAlloc {
            heap: UnsafeCell::new([0; N]),
            pos: UnsafeCell::new(0),
        }
    }

    /// Free everything at once, making the arena usable again.
    ///
    /// # Safety
    ///
    /// Every pointer previously handed out becomes dangling. Call only
    /// where no allocation from the previous run is still reachable —
    /// at an entry point, before any work.
    pub unsafe fn reset(&self) {
        unsafe { *self.pos.get() = 0 };
    }

    /// High-water mark, in bytes. Useful for sizing an arena.
    pub fn used(&self) -> usize {
        unsafe { *self.pos.get() }
    }
}

impl<const N: usize> Default for BumpAlloc<N> {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl<const N: usize> GlobalAlloc for BumpAlloc<N> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pos = unsafe { &mut *self.pos.get() };
        let aligned = (*pos + layout.align() - 1) & !(layout.align() - 1);
        let next = aligned + layout.size();
        if next > N {
            return core::ptr::null_mut();
        }
        *pos = next;
        unsafe { (*self.heap.get()).as_mut_ptr().add(aligned) }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

/// Install a [`BumpAlloc`] of `$bytes` as the program's global
/// allocator, and define `reset_heap()` beside it.
///
/// A macro rather than a static in this crate because
/// `#[global_allocator]` must be unique per binary: a static here would
/// force the arena on every program that links `nub-rt`, including the
/// ones that never allocate.
///
/// ```ignore
/// nub_rt::bump_allocator!(64 * 1024);
///
/// #[nub_rt::endpoint(0)]
/// fn run(_: u64) -> u64 {
///     reset_heap();          // re-entrant: safe to invoke repeatedly
///     my_kernel() as u64
/// }
/// ```
///
/// On host targets it expands to a `reset_heap()` that does nothing, so
/// the same source builds both ways.
#[macro_export]
macro_rules! bump_allocator {
    ($bytes:expr) => {
        #[cfg(target_os = "none")]
        #[global_allocator]
        static __NUB_RT_HEAP: $crate::alloc::BumpAlloc<{ $bytes }> =
            $crate::alloc::BumpAlloc::new();

        /// Release everything allocated so far.
        ///
        /// Call at the top of an entry point, before any work — at that
        /// moment nothing from a previous invocation is reachable, which
        /// is what makes it sound.
        #[cfg(target_os = "none")]
        fn reset_heap() {
            // SAFETY: called at entry, before any allocation of this
            // invocation exists and after every allocation of the
            // previous one has gone out of scope.
            unsafe { __NUB_RT_HEAP.reset() };
        }

        /// No-op on host: the system allocator needs no reset.
        #[cfg(not(target_os = "none"))]
        #[allow(dead_code)]
        fn reset_heap() {}
    };
}
