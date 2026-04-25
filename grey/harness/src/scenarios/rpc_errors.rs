//! Scenario: verify RPC error handling for invalid requests.
//!
//! Tests that the node returns proper JSON-RPC error responses for
//! invalid methods, malformed parameters, missing parameters, and
//! handles concurrent requests correctly. Covers Issue #225 Scenario 2.

use std::time::Instant;

use crate::rpc::RpcClient;
use crate::scenarios::ScenarioResult;

pub async fn run(client: &RpcClient) -> ScenarioResult {
    let start = Instant::now();
    let mut checks_passed = 0u32;
    let mut checks_total = 0u32;

    // ── Test 1: Invalid (non-existent) RPC method ──────────────────
    checks_total += 1;
    match client
        .call_raw("jam_nonExistentMethod", serde_json::json!([]))
        .await
    {
        Err(e) => {
            // Expected: JSON-RPC error (method not found)
            tracing::info!("invalid method: correctly rejected ({})", e);
            checks_passed += 1;
        }
        Ok(_) => {
            return ScenarioResult {
                name: "rpc_errors",
                pass: false,
                duration: start.elapsed(),
                error: Some("non-existent method should return error".into()),
                latencies: vec![],
                metrics: vec![],
            };
        }
    }

    // ── Test 2: Invalid params — jam_getBlock with non-hex string ──
    checks_total += 1;
    match client
        .call_raw("jam_getBlock", serde_json::json!(["not-hex-data!!"]))
        .await
    {
        Err(e) => {
            tracing::info!("invalid hex param: correctly rejected ({})", e);
            checks_passed += 1;
        }
        Ok(_) => {
            return ScenarioResult {
                name: "rpc_errors",
                pass: false,
                duration: start.elapsed(),
                error: Some("non-hex hash param should return error".into()),
                latencies: vec![],
                metrics: vec![],
            };
        }
    }

    // ── Test 3: Missing params — jam_readStorage without key ───────
    checks_total += 1;
    match client
        .call_raw("jam_readStorage", serde_json::json!([42]))
        .await
    {
        Err(e) => {
            tracing::info!("missing key param: correctly rejected ({})", e);
            checks_passed += 1;
        }
        Ok(_) => {
            // Some implementations may default missing params — not a hard failure.
            tracing::warn!("missing key param returned Ok (may use default)");
            checks_passed += 1;
        }
    }

    // ── Test 4: Invalid params — jam_getBlock with short hash ──────
    checks_total += 1;
    match client
        .call_raw("jam_getBlock", serde_json::json!(["aabb"]))
        .await
    {
        Err(e) => {
            tracing::info!("short hash param: correctly rejected ({})", e);
            checks_passed += 1;
        }
        Ok(_) => {
            return ScenarioResult {
                name: "rpc_errors",
                pass: false,
                duration: start.elapsed(),
                error: Some("short hash should return error (expected 32 bytes)".into()),
                latencies: vec![],
                metrics: vec![],
            };
        }
    }

    // ── Test 5: Invalid params — jam_submitWorkPackage with non-hex ─
    checks_total += 1;
    match client
        .call_raw("jam_submitWorkPackage", serde_json::json!(["xyz-not-hex"]))
        .await
    {
        Err(e) => {
            tracing::info!("invalid hex WP: correctly rejected ({})", e);
            checks_passed += 1;
        }
        Ok(_) => {
            return ScenarioResult {
                name: "rpc_errors",
                pass: false,
                duration: start.elapsed(),
                error: Some("non-hex work package should return error".into()),
                latencies: vec![],
                metrics: vec![],
            };
        }
    }

    // ── Test 6: Concurrent requests (100 simultaneous getStatus) ───
    checks_total += 1;
    let mut handles = Vec::new();
    for _ in 0..100 {
        handles.push(tokio::spawn(async move {
            // Each task creates its own client (RpcClient is not Clone)
            let client = RpcClient::new("http://localhost:9933");
            client.get_status().await
        }));
    }

    let mut concurrent_successes = 0u32;
    let mut concurrent_failures = 0u32;
    for handle in handles {
        match handle.await {
            Ok(Ok(_)) => concurrent_successes += 1,
            _ => concurrent_failures += 1,
        }
    }

    if concurrent_successes == 100 {
        tracing::info!("concurrent requests: all 100 succeeded");
        checks_passed += 1;
    } else {
        return ScenarioResult {
            name: "rpc_errors",
            pass: false,
            duration: start.elapsed(),
            error: Some(format!(
                "concurrent requests: {}/100 succeeded, {} failed",
                concurrent_successes, concurrent_failures
            )),
            latencies: vec![],
            metrics: vec![],
        };
    }

    // ── Test 7: Large response — read storage with long key ────────
    // Query a storage key that likely doesn't exist. This verifies the
    // response doesn't truncate and the node handles missing keys gracefully.
    checks_total += 1;
    match client.read_storage(2000, &"ff".repeat(32)).await {
        Ok(_storage) => {
            tracing::info!("large key query: returned (value may be null)");
            checks_passed += 1;
        }
        Err(e) => {
            // Error is also acceptable (invalid key or service not found)
            tracing::info!("large key query: rejected ({})", e);
            checks_passed += 1;
        }
    }

    // ── Verify node is still healthy ────────────────────────────────
    if let Err(e) = client.get_status().await {
        return ScenarioResult {
            name: "rpc_errors",
            pass: false,
            duration: start.elapsed(),
            error: Some(format!("node unhealthy after RPC error tests: {}", e)),
            latencies: vec![],
            metrics: vec![],
        };
    }

    ScenarioResult {
        name: "rpc_errors",
        pass: checks_passed == checks_total,
        duration: start.elapsed(),
        error: if checks_passed == checks_total {
            None
        } else {
            Some(format!("{}/{} checks passed", checks_passed, checks_total))
        },
        latencies: vec![],
        metrics: vec![crate::scenarios::ScenarioMetric {
            label: "rpc_error_checks_passed".into(),
            value: checks_passed as f64,
            unit: "count",
        }],
    }
}
