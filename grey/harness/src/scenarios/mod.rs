//! Integration test scenarios.

pub mod consistency;
pub mod invalid_wp;
pub mod liveness;
pub mod metrics;
pub mod recovery;
pub mod repeat;
pub mod rpc_errors;
pub mod serial;
pub mod throughput;

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
    /// Scenario-specific numeric metrics (e.g., throughput or queue depth).
    pub metrics: Vec<ScenarioMetric>,
}

/// A single latency measurement.
#[allow(dead_code)]
pub struct LatencySample {
    pub label: String,
    pub duration: Duration,
}

/// A numeric metric emitted by a scenario.
#[allow(dead_code)]
pub struct ScenarioMetric {
    pub label: String,
    pub value: f64,
    pub unit: &'static str,
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

    /// Print numeric metrics if present.
    pub fn print_metric_summary(&self) {
        if self.metrics.is_empty() {
            return;
        }

        println!("  Metrics:");
        for metric in &self.metrics {
            let value = if metric.value.fract().abs() < f64::EPSILON {
                format!("{:.0}", metric.value)
            } else {
                format!("{:.2}", metric.value)
            };
            println!("    {:30} {:>10} {}", metric.label, value, metric.unit);
        }
    }
}
