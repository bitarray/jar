//! Integration test scenarios.

pub mod invalid_wp;
pub mod liveness;
pub mod recovery;
pub mod repeat;
pub mod serial;

use std::time::Duration;

/// Result of a single scenario run.
#[allow(dead_code)]
pub struct ScenarioResult {
    pub name: &'static str,
    pub pass: bool,
    pub duration: Duration,
    pub error: Option<String>,
    /// Per-operation latency samples (e.g., submit-to-confirm times).
    pub latencies: Vec<LatencySample>,
}

/// A single latency measurement.
#[allow(dead_code)]
pub struct LatencySample {
    pub label: String,
    pub duration: Duration,
}

impl ScenarioResult {
    /// Print latency summary if samples are present.
    pub fn print_latency_summary(&self) {
        if self.latencies.is_empty() {
            return;
        }
        let total: Duration = self.latencies.iter().map(|s| s.duration).sum();
        let count = self.latencies.len();
        let avg = total / count as u32;
        let min = self.latencies.iter().map(|s| s.duration).min().unwrap();
        let max = self.latencies.iter().map(|s| s.duration).max().unwrap();
        println!(
            "  Latency: {} samples, avg={:.1}s, min={:.1}s, max={:.1}s",
            count,
            avg.as_secs_f64(),
            min.as_secs_f64(),
            max.as_secs_f64()
        );
    }
}
