//! Scenario: verify node recovers after processing invalid inputs.
//!
//! Submits several invalid work packages, then submits a valid pixel
//! and verifies it is correctly stored. Additionally checks that:
//! - Block production continues normally after invalid submissions
//! - Finalization is not disrupted by invalid work packages
//!   Covers Issue #225 Scenario 3.

use std::time::{Duration, Instant};

use crate::poll::submit_and_verify_pixel;
use crate::rpc::RpcClient;
use crate::scenarios::{LatencySample, ScenarioResult};

const SERVICE_ID: u32 = 2000;
const TIMEOUT: Duration = Duration::from_secs(120);

pub async fn run(client: &RpcClient) -> ScenarioResult {
    let start = Instant::now();

    // ── Phase 1: Capture pre-test state ────────────────────────────
    let pre_status = match client.get_status().await {
        Ok(s) => s,
        Err(e) => {
            return ScenarioResult {
                name: "recovery",
                pass: false,
                duration: start.elapsed(),
                error: Some(format!("failed to get pre-test status: {}", e)),
                latencies: vec![],
                metrics: vec![],
            };
        }
    };
    let pre_head_slot = pre_status.head_slot;
    let pre_finalized_slot = pre_status.finalized_slot;

    // ── Phase 2: Submit several invalid work packages ──────────────
    let invalid_payloads = [
        hex::encode([0xDE, 0xAD, 0xBE, 0xEF]),
        String::new(),               // empty
        hex::encode(vec![0u8; 100]), // random bytes
    ];
    for payload in &invalid_payloads {
        // Ignore errors — we expect rejections
        let _ = client.submit_work_package(payload).await;
    }

    // ── Phase 3: Submit a valid pixel and verify it is stored ──────
    let op_start = Instant::now();
    if let Err(e) = submit_and_verify_pixel(client, SERVICE_ID, 99, 99, 128, 64, 32, TIMEOUT).await
    {
        return ScenarioResult {
            name: "recovery",
            pass: false,
            duration: start.elapsed(),
            error: Some(format!(
                "valid pixel failed after invalid submissions: {}",
                e
            )),
            latencies: vec![],
            metrics: vec![],
        };
    }
    let pixel_latency = LatencySample {
        label: "pixel(99,99) after errors".into(),
        duration: op_start.elapsed(),
    };

    // ── Phase 4: Verify block production continues ─────────────────
    // The head slot should have advanced beyond the pre-test value.
    let post_status = match client.get_status().await {
        Ok(s) => s,
        Err(e) => {
            return ScenarioResult {
                name: "recovery",
                pass: false,
                duration: start.elapsed(),
                error: Some(format!("failed to get post-test status: {}", e)),
                latencies: vec![pixel_latency],
                metrics: vec![],
            };
        }
    };

    if post_status.head_slot <= pre_head_slot {
        return ScenarioResult {
            name: "recovery",
            pass: false,
            duration: start.elapsed(),
            error: Some(format!(
                "block production stalled: head_slot did not advance (pre={}, post={})",
                pre_head_slot, post_status.head_slot
            )),
            latencies: vec![pixel_latency],
            metrics: vec![],
        };
    }

    // ── Phase 5: Verify finalization is not disrupted ──────────────
    // The finalized slot should have advanced (or at least not regressed).
    if post_status.finalized_slot < pre_finalized_slot {
        return ScenarioResult {
            name: "recovery",
            pass: false,
            duration: start.elapsed(),
            error: Some(format!(
                "finalization regressed: finalized_slot went from {} to {}",
                pre_finalized_slot, post_status.finalized_slot
            )),
            latencies: vec![pixel_latency],
            metrics: vec![],
        };
    }

    // ── Phase 6: Verify node status is healthy ─────────────────────
    if let Err(e) = client.get_status().await {
        return ScenarioResult {
            name: "recovery",
            pass: false,
            duration: start.elapsed(),
            error: Some(format!("node unhealthy after recovery: {}", e)),
            latencies: vec![pixel_latency],
            metrics: vec![],
        };
    }

    ScenarioResult {
        name: "recovery",
        pass: true,
        duration: start.elapsed(),
        error: None,
        latencies: vec![pixel_latency],
        metrics: vec![
            crate::scenarios::ScenarioMetric {
                label: "head_slot_before".into(),
                value: pre_head_slot as f64,
                unit: "slot",
            },
            crate::scenarios::ScenarioMetric {
                label: "head_slot_after".into(),
                value: post_status.head_slot as f64,
                unit: "slot",
            },
            crate::scenarios::ScenarioMetric {
                label: "finalized_slot_before".into(),
                value: pre_finalized_slot as f64,
                unit: "slot",
            },
            crate::scenarios::ScenarioMetric {
                label: "finalized_slot_after".into(),
                value: post_status.finalized_slot as f64,
                unit: "slot",
            },
        ],
    }
}
