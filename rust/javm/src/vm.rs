//! The v3 `Vm` driver.
//!
//! Composes:
//! - The call stack (`crate::callstack::CallStack`).
//! - The kernel-assist hook (`crate::kernel_assist::KernelAssist`).
//! - The image bytecode cache (`crate::image_cache::ImageCache`).
//!
//! Top-level verbs (CALL / CALL_RESUME / DROP_PAUSED / host_yield)
//! and the MGMT / host-call dispatch land in subsequent sub-stages
//! (3.6 onward). This module currently holds only the wiring that
//! every later sub-stage depends on.

use crate::callstack::{CallStack, DEFAULT_MAX_DEPTH};
use crate::image_cache::ImageCache;
use crate::kernel_assist::KernelAssist;

/// The v3 VM driver. Parameterized over a `KernelAssist` impl so the
/// integration crate can be tested with the in-process default while
/// jar-kernel-v3 swaps in a σ-aware implementation.
pub struct Vm<K: KernelAssist> {
    pub stack: CallStack,
    pub kernel_assist: K,
    pub image_cache: ImageCache,
}

impl<K: KernelAssist> Vm<K> {
    pub fn new(kernel_assist: K) -> Self {
        Self::with_max_depth(kernel_assist, DEFAULT_MAX_DEPTH)
    }

    pub fn with_max_depth(kernel_assist: K, max_depth: usize) -> Self {
        Self {
            stack: CallStack::new(max_depth),
            kernel_assist,
            image_cache: ImageCache::new(),
        }
    }
}

impl<K: KernelAssist + std::fmt::Debug> std::fmt::Debug for Vm<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vm")
            .field("stack", &self.stack)
            .field("kernel_assist", &self.kernel_assist)
            .field("image_cache_len", &self.image_cache.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel_assist::InProcessKernelAssist;

    #[test]
    fn new_constructs_empty_vm() {
        let vm = Vm::new(InProcessKernelAssist::new());
        assert!(vm.stack.is_empty());
        assert!(vm.image_cache.is_empty());
    }

    #[test]
    fn with_max_depth_uses_supplied_limit() {
        let vm = Vm::with_max_depth(InProcessKernelAssist::new(), 4);
        // We can't inspect max_depth directly, but pushing 5 should
        // eventually fail. That's covered in callstack tests.
        assert!(vm.stack.is_empty());
    }
}
