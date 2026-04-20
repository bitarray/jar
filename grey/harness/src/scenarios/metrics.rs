//! Scenario: verify /metrics endpoint returns valid Prometheus metrics.
//!
//! Checks that the /metrics HTTP endpoint is reachable and contains
//! expected gauges/counters with non-negative values.

use std::time::Instant;

use tracing::info;

use crate::rpc::RpcClient;
use crate::scenarios::ScenarioResult;

/// Required metric names that must be present in the output.
const REQUIRED_METRICS: &[&str] = &[
    "grey_block_height",
    "grey_finalized_height",
    "grey_blocks_produced_total",
    "grey_blocks_imported_total",
    "grey_validator_index",
    "grey_peer_count",
    "grey_stored_blocks",
    "grey_grandpa_round",
    "grey_work_packages_submitted_total",
    "grey_work_packages_accumulated_total",
];

pub async fn run(client: &RpcClient) -> ScenarioResult {
    let start = Instant::now();

    match run_inner(client).await {
        Ok(()) => ScenarioResult {
            name: "metrics",
            pass: true,
            duration: start.elapsed(),
            error: None,
            latencies: vec![],
            metrics: vec![],
        },
        Err(e) => ScenarioResult {
            name: "metrics",
            pass: false,
            duration: start.elapsed(),
            error: Some(e),
            latencies: vec![],
            metrics: vec![],
        },
    }
}

async fn run_inner(client: &RpcClient) -> Result<(), String> {
    info!("Fetching /metrics endpoint...");

    let body = client
        .get_metrics()
        .await
        .map_err(|e| format!("failed to fetch /metrics: {e}"))?;

    if body.is_empty() {
        return Err("metrics response is empty".into());
    }

    info!("Received {} bytes from /metrics", body.len());

    // Check required metrics are present
    for metric in REQUIRED_METRICS {
        if !body.contains(metric) {
            return Err(format!("missing required metric: {metric}"));
        }
    }

    // Verify Prometheus text format: each metric should have a TYPE line
    let type_count = body.lines().filter(|l| l.starts_with("# TYPE")).count();
    if type_count == 0 {
        return Err("no # TYPE lines found — not valid Prometheus format".into());
    }

    // Parse a few key metrics and verify non-negative values
    for line in body.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        // Lines are: metric_name value
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2
            && let Ok(val) = parts[1].parse::<f64>()
            && val < 0.0
        {
            return Err(format!("negative metric value: {} = {}", parts[0], val));
        }
    }

    info!(
        "Metrics check passed: {} TYPE declarations, all {} required metrics present",
        type_count,
        REQUIRED_METRICS.len()
    );

    Ok(())
}
