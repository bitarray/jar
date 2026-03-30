//! Scenario: verify node recovers after processing invalid inputs.
//!
//! Submits several invalid work packages, then submits a valid pixel
//! and verifies it is correctly stored. Confirms that error handling
//! does not corrupt the pipeline.

use std::time::{Duration, Instant};

use crate::poll::submit_and_verify_pixel;
use crate::rpc::RpcClient;
use crate::scenarios::{LatencySample, ScenarioResult};

const SERVICE_ID: u32 = 2000;
const TIMEOUT: Duration = Duration::from_secs(120);

pub async fn run(client: &RpcClient) -> ScenarioResult {
    let start = Instant::now();

    // Phase 1: Submit several invalid work packages (should all be rejected)
    let invalid_payloads = [
        hex::encode([0xDE, 0xAD, 0xBE, 0xEF]),
        String::new(),               // empty
        hex::encode(vec![0u8; 100]), // random bytes
    ];
    for payload in &invalid_payloads {
        // Ignore errors — we expect rejections
        let _ = client.submit_work_package(payload).await;
    }

    // Phase 2: Submit a valid pixel and verify it is stored correctly
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
        };
    }
    let latency = LatencySample {
        label: "pixel(99,99) after errors".into(),
        duration: op_start.elapsed(),
    };

    // Phase 3: Verify node status is healthy
    if let Err(e) = client.get_status().await {
        return ScenarioResult {
            name: "recovery",
            pass: false,
            duration: start.elapsed(),
            error: Some(format!("node unhealthy after recovery: {}", e)),
            latencies: vec![latency],
        };
    }

    ScenarioResult {
        name: "recovery",
        pass: true,
        duration: start.elapsed(),
        error: None,
        latencies: vec![latency],
    }
}
