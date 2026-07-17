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

// Counter metric that counter number of times a guest error occurred
pub(crate) static METRIC_GUEST_ERROR: &str = "guest_errors_total";
pub(crate) static METRIC_GUEST_ERROR_LABEL_CODE: &str = "code";

// Counter metric that counts the number of times a guest function was called due to timing out
pub(crate) static METRIC_GUEST_CANCELLATION: &str = "guest_cancellations_total";

// Counter metric that counts the number of times a vCPU was erroneously kicked by a stale cancellation
// This can happen when a signal from a previous guest call arrives late and interrupts a new call (Linux).
pub(crate) static METRIC_ERRONEOUS_VCPU_KICKS: &str = "erroneous_vcpu_kicks_total";

/// Executes the given closure and returns its result directly.
///
/// (Guest-call timing metrics are not emitted in this build; the
/// `name` argument is retained for call-site symmetry.)
pub(crate) fn maybe_time_and_emit_guest_call<T, F: FnOnce() -> T>(_name: &str, f: F) -> T {
    f()
}

/// Executes the given closure and returns its result directly.
///
/// (Host-call timing metrics are not emitted in this build; the
/// `name` argument is retained for call-site symmetry.)
pub(crate) fn maybe_time_and_emit_host_call<T, F: FnOnce() -> T>(_name: &str, f: F) -> T {
    f()
}
