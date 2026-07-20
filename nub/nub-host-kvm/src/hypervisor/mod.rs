/*
Copyright 2025  The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/// Abstracts over different hypervisor register representations
pub(crate) mod regs;

pub(crate) mod virtual_machine;

pub(crate) mod hyperlight_vm;

use std::fmt::Debug;
#[cfg(kvm)]
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
#[cfg(kvm)]
use std::time::Duration;

/// A trait for platform-specific interrupt handle implementation details
pub(crate) trait InterruptHandleImpl: InterruptHandle {
    /// Set the thread ID for the vcpu thread
    #[cfg(kvm)]
    fn set_tid(&self);

    /// Set the running state
    fn set_running(&self);

    /// Clear the running state
    fn clear_running(&self);

    /// Mark the handle as dropped
    fn set_dropped(&self);

    /// Check if cancellation was requested
    fn is_cancelled(&self) -> bool;

    /// Clear the cancellation request flag
    fn clear_cancel(&self);

    /// Check if debug interrupt was requested (always returns false when gdb feature is disabled)
    fn is_debug_interrupted(&self) -> bool;
}

/// A trait for handling interrupts to a sandbox's vcpu
pub trait InterruptHandle: Send + Sync + Debug {
    /// Interrupt the corresponding sandbox from running.
    ///
    /// - If this is called while the the sandbox currently executing a guest function call, it will interrupt the sandbox and return `true`.
    /// - If this is called while the sandbox is not running (for example before or after calling a guest function), it will do nothing and return `false`.
    ///
    /// # Note
    /// This function will block for the duration of the time it takes for the vcpu thread to be interrupted.
    fn kill(&self) -> bool;

    /// Returns true if the corresponding sandbox has been dropped
    fn dropped(&self) -> bool;
}

#[cfg(kvm)]
#[derive(Debug)]
pub(super) struct LinuxInterruptHandle {
    /// Atomic value packing vcpu execution state.
    ///
    /// Bit layout:
    /// - Bit 2: DEBUG_INTERRUPT_BIT - set when debugger interrupt is requested
    /// - Bit 1: RUNNING_BIT - set when vcpu is actively running
    /// - Bit 0: CANCEL_BIT - set when cancellation has been requested
    ///
    /// CANCEL_BIT persists across vcpu exits/re-entries within a single `VirtualCPU::run()` call
    /// (e.g., during host function calls), but is cleared at the start of each new `VirtualCPU::run()` call.
    state: AtomicU8,

    /// Thread ID where the vcpu is running.
    ///
    /// Note: Multiple VMs may have the same `tid` (same thread runs multiple sandboxes sequentially),
    /// but at most one VM will have RUNNING_BIT set at any given time.
    tid: AtomicU64,

    /// Whether the corresponding VM has been dropped.
    dropped: AtomicBool,

    /// Delay between retry attempts when sending signals to interrupt the vcpu.
    retry_delay: Duration,

    /// Offset from SIGRTMIN for the signal used to interrupt the vcpu thread.
    sig_rt_min_offset: u8,
}

#[cfg(kvm)]
impl LinuxInterruptHandle {
    const RUNNING_BIT: u8 = 1 << 1;
    const CANCEL_BIT: u8 = 1 << 0;

    /// Get the running, cancel and debug flags atomically.
    ///
    /// # Memory Ordering
    /// Uses `Acquire` ordering to synchronize with the `Release` in `set_running()` and `kill()`.
    /// This ensures that when we observe running=true, we also see the correct `tid` value.
    fn get_running_cancel_debug(&self) -> (bool, bool, bool) {
        let state = self.state.load(Ordering::Acquire);
        let running = state & Self::RUNNING_BIT != 0;
        let cancel = state & Self::CANCEL_BIT != 0;
        let debug = false;
        (running, cancel, debug)
    }

    fn send_signal(&self) -> bool {
        let signal_number = libc::SIGRTMIN() + self.sig_rt_min_offset as libc::c_int;
        let mut sent_signal = false;

        loop {
            let (running, cancel, debug) = self.get_running_cancel_debug();

            // Check if we should continue sending signals
            // Exit if not running OR if neither cancel nor debug_interrupt is set
            let should_continue = running && (cancel || debug);

            if !should_continue {
                break;
            }

            tracing::info!("Sending signal to kill vcpu thread...");
            sent_signal = true;
            // Acquire ordering to synchronize with the Release store in set_tid()
            // This ensures we see the correct tid value for the currently running vcpu
            unsafe {
                libc::pthread_kill(self.tid.load(Ordering::Acquire) as _, signal_number);
            }
            std::thread::sleep(self.retry_delay);
        }

        sent_signal
    }
}

#[cfg(kvm)]
impl InterruptHandleImpl for LinuxInterruptHandle {
    fn set_tid(&self) {
        // Release ordering to synchronize with the Acquire load of `running` in send_signal()
        // This ensures that when send_signal() observes RUNNING_BIT=true (via Acquire),
        // it also sees the correct tid value stored here
        self.tid
            .store(unsafe { libc::pthread_self() as u64 }, Ordering::Release);
    }

    fn set_running(&self) {
        // Release ordering to ensure that the tid store (which uses Release)
        // is visible to any thread that observes running=true via Acquire ordering.
        // This prevents the interrupt thread from reading a stale tid value.
        self.state.fetch_or(Self::RUNNING_BIT, Ordering::Release);
    }

    fn is_cancelled(&self) -> bool {
        // Acquire ordering to synchronize with the Release in kill()
        // This ensures we see the cancel flag set by the interrupt thread
        self.state.load(Ordering::Acquire) & Self::CANCEL_BIT != 0
    }

    fn clear_cancel(&self) {
        // Release ordering to ensure that any operations from the previous run()
        // are visible to other threads. While this is typically called by the vcpu thread
        // at the start of run(), the VM itself can move between threads across guest calls.
        self.state.fetch_and(!Self::CANCEL_BIT, Ordering::Release);
    }

    fn clear_running(&self) {
        // Release ordering to ensure all vcpu operations are visible before clearing running
        self.state.fetch_and(!Self::RUNNING_BIT, Ordering::Release);
    }

    fn is_debug_interrupted(&self) -> bool {
        false
    }

    fn set_dropped(&self) {
        // Release ordering to ensure all VM cleanup operations are visible
        // to any thread that checks dropped() via Acquire
        self.dropped.store(true, Ordering::Release);
    }
}

#[cfg(kvm)]
impl InterruptHandle for LinuxInterruptHandle {
    fn kill(&self) -> bool {
        // Release ordering ensures that any writes before kill() are visible to the vcpu thread
        // when it checks is_cancelled() with Acquire ordering
        self.state.fetch_or(Self::CANCEL_BIT, Ordering::Release);

        // Send signals to interrupt the vcpu if it's currently running
        self.send_signal()
    }

    fn dropped(&self) -> bool {
        // Acquire ordering to synchronize with the Release in set_dropped()
        // This ensures we see all VM cleanup operations that happened before drop
        self.dropped.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub(super) struct MultiLaneInterruptHandle {
    handles: Vec<std::sync::Arc<dyn InterruptHandle>>,
}

impl MultiLaneInterruptHandle {
    pub(super) fn new(handles: Vec<std::sync::Arc<dyn InterruptHandle>>) -> Self {
        Self { handles }
    }
}

impl InterruptHandle for MultiLaneInterruptHandle {
    fn kill(&self) -> bool {
        let mut interrupted = false;
        for handle in &self.handles {
            interrupted = handle.kill() || interrupted;
        }
        interrupted
    }

    fn dropped(&self) -> bool {
        self.handles.iter().all(|handle| handle.dropped())
    }
}
