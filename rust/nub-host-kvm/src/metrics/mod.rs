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
// This can happen in two scenarios:
// 1. Linux: A signal from a previous guest call arrives late and interrupts a new call
// 2. Windows: WHvCancelRunVirtualProcessor is called right after vCPU exits but RUNNING_BIT is still true
pub(crate) static METRIC_ERRONEOUS_VCPU_KICKS: &str = "erroneous_vcpu_kicks_total";

// Histogram metric that measures the duration of guest function calls
#[cfg(feature = "function_call_metrics")]
pub(crate) static METRIC_GUEST_FUNC_DURATION: &str = "guest_call_duration_seconds";

// Histogram metric that measures the duration of host function calls
#[cfg(feature = "function_call_metrics")]
pub(crate) static METRIC_HOST_FUNC_DURATION: &str = "host_call_duration_seconds";

/// If the the `function_call_metrics` feature is enabled, this function measures
/// the time it takes to execute the given closure, and will then emit a guest call metric
/// with the given function name.
///
/// If the feature is not enabled, the given closure is executed without any additional metrics being emitted,
/// and the result of the closure is returned directly.
pub(crate) fn maybe_time_and_emit_guest_call<T, F: FnOnce() -> T>(
    #[allow(unused_variables)] name: &str,
    f: F,
) -> T {
    cfg_if::cfg_if! {
        if #[cfg(feature = "function_call_metrics")] {
            use std::time::Instant;

            let start = Instant::now();
            let result = f();
            let duration = start.elapsed();

            static LABEL_GUEST_FUNC_NAME: &str = "function_name";
            metrics::histogram!(METRIC_GUEST_FUNC_DURATION, LABEL_GUEST_FUNC_NAME => name.to_string()).record(duration);
            result
        } else {
            f()
        }
    }
}

/// If the the `function_call_metrics` feature is enabled, this function measures
/// the time it takes to execute the given closure, and will then emit a host call metric
/// with the given function name.
///
/// If the feature is not enabled, the given closure is executed without any additional metrics being emitted,
/// and the result of the closure is returned directly.
pub(crate) fn maybe_time_and_emit_host_call<T, F: FnOnce() -> T>(
    #[allow(unused_variables)] name: &str,
    f: F,
) -> T {
    cfg_if::cfg_if! {
        if #[cfg(feature = "function_call_metrics")] {
            use std::time::Instant;

            let start = Instant::now();
            let result = f();
            let duration = start.elapsed();

            static LABEL_HOST_FUNC_NAME: &str = "function_name";
            metrics::histogram!(METRIC_HOST_FUNC_DURATION, LABEL_HOST_FUNC_NAME => name.to_string()).record(duration);
            result
        } else {
            f()
        }
    }
}
