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

/// Configuration needed to establish a sandbox.
pub mod config;
/// Host-side file mapping preparation for `map_file_cow`.
pub(crate) mod file_mapping;
/// Functionality for reading, but not modifying host functions
pub(crate) mod host_funcs;
/// Functionality for dealing with initialized sandboxes that can
/// call 0 or more guest functions
pub mod initialized_multi_use;
pub(crate) mod outb;
/// Functionality for creating uninitialized sandboxes, manipulating them,
/// and converting them to initialized sandboxes.
pub mod uninitialized;
/// Functionality for properly converting `UninitializedSandbox`es to
/// initialized `Sandbox`es.
pub(crate) mod uninitialized_evolve;

/// Representation of a snapshot of a `Sandbox`.
pub mod snapshot;

/// Trait used by the macros to paper over the differences between hyperlight and hyperlight-wasm
mod callable;

// F2.2: dropped the `trace/` submodule (OpenTelemetry guest tracing).

/// Trait used by the macros to paper over the differences between hyperlight and hyperlight-wasm
pub use callable::Callable;
/// Re-export for `SandboxConfiguration` type
pub use config::SandboxConfiguration;
/// Re-export for the `MultiUseSandbox` type
pub use initialized_multi_use::{MultiUseSandbox, PtRootFinder};
/// Re-export for `GuestBinary` type
pub use uninitialized::GuestBinary;
/// Re-export for `UninitializedSandbox` type
pub use uninitialized::UninitializedSandbox;
