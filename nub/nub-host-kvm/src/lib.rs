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
#![warn(dead_code, missing_docs, unused_mut)]
//! KVM host runtime for executing guest code in lightweight virtual machines.
//!
//! This crate provides the host-side runtime for the nub KVM sandbox, enabling
//! safe execution of untrusted guest code within micro virtual machines with
//! minimal overhead. The runtime manages sandbox creation, guest function calls,
//! memory isolation, and host-guest communication over rkyv-encoded RPC.
//!
//! The primary entry points are [`UninitializedSandbox`] for initial setup and
//! [`MultiUseSandbox`] for executing guest functions.
//!
//! ## Guest Requirements
//!
//! This runtime requires a specially compiled guest binary (the
//! `nub-arch-guestbin` `x86_64-unknown-none` image) and cannot run regular
//! container images or executables.
//!

#![cfg_attr(not(any(test, debug_assertions)), warn(clippy::panic))]
#![cfg_attr(not(any(test, debug_assertions)), warn(clippy::expect_used))]
#![cfg_attr(not(any(test, debug_assertions)), warn(clippy::unwrap_used))]

/// Dealing with errors, including errors across VM boundaries
pub mod error;
/// Wrappers for host and guest functions.
pub mod func;
/// Wrappers for hypervisor implementations
pub mod hypervisor;
/// Functionality to establish and manage an individual sandbox's
/// memory.
///
/// - Virtual Address
///
/// 0x0000    PML4
/// 0x1000    PDPT
/// 0x2000    PD
/// 0x3000    The guest ELF image (loaded into the sandbox's memory).
///
/// - The pointer passed to the Entrypoint in the Guest application is the size of page table + size of code,
///   at this address structs below are laid out in this order
pub mod mem;
/// Metric definitions and helpers
pub mod metrics;
/// The main sandbox implementations. Do not use this module directly in code
/// outside this file. Types from this module needed for public consumption are
/// re-exported below.
pub mod sandbox;
/// Signal handling for Linux
#[cfg(target_os = "linux")]
pub(crate) mod signal_handlers;
// F2.2: `testing/` module dropped (was internal test utilities only).

/// The re-export for the `HyperlightError` type
pub use error::HyperlightError;
/// The re-export for the `is_hypervisor_present` type
pub use hypervisor::virtual_machine::is_hypervisor_present;
/// A sandbox that can call be used to make multiple calls to guest functions,
/// and otherwise reused multiple times
pub use sandbox::MultiUseSandbox;
/// The re-export for the `UninitializedSandbox` type
pub use sandbox::UninitializedSandbox;
/// The re-export for the `GuestBinary` type
pub use sandbox::uninitialized::GuestBinary;

/// The universal `Result` type used throughout the Hyperlight codebase.
pub type Result<T> = core::result::Result<T, error::HyperlightError>;

/// Logs an error then returns with it, more or less equivalent to the bail! macro in anyhow
/// but for HyperlightError instead of anyhow::Error
#[macro_export]
macro_rules! log_then_return {
    ($msg:literal $(,)?) => {{
        let __args = std::format_args!($msg);
        let __err_msg = match __args.as_str() {
            Some(msg) => String::from(msg),
            None => std::format!($msg),
        };
        let __err = $crate::HyperlightError::Error(__err_msg);
        tracing::error!("{}", __err);
        return Err(__err);
    }};
    ($err:expr $(,)?) => {
        tracing::error!("{}", $err);
        return Err($err);
    };
    ($err:stmt $(,)?) => {
        tracing::error!("{}", $err);
        return Err($err);
    };
    ($fmtstr:expr, $($arg:tt)*) => {
           let __err_msg = std::format!($fmtstr, $($arg)*);
           let __err = $crate::error::HyperlightError::Error(__err_msg);
           tracing::error!("{}", __err);
           return Err(__err);
    };
}

/// Same as tracing::debug!, but will additionally print to stdout if the print_debug feature is enabled
#[macro_export]
macro_rules! debug {
    ($($arg:tt)+) =>
    {
        #[cfg(print_debug)]
        println!($($arg)+);
        tracing::debug!($($arg)+);
    }
}
