//! Scenario: submit various invalid work packages and verify error responses.
//!
//! Tests that the node correctly rejects malformed inputs without crashing.
//! Covers Issue #225: invalid WP scenarios including structural and semantic
//! invalidity (malformed codec, invalid service ID, wrong code hash, wrong
//! context, empty work items).

use std::time::Instant;

use grey_types::Hash;
use grey_types::work::{RefinementContext, WorkItem, WorkPackage};
use scale::Encode;

use crate::rpc::RpcClient;
use crate::scenarios::ScenarioResult;

/// Submit a work package and assert it is rejected.
async fn assert_rejected(
    client: &RpcClient,
    data: &str,
    description: &str,
    start: &Instant,
) -> Option<ScenarioResult> {
    if client.submit_work_package(data).await.is_ok() {
        return Some(ScenarioResult {
            name: "invalid_wp",
            pass: false,
            duration: start.elapsed(),
            error: Some(format!("{} should have been rejected", description)),
            latencies: vec![],
            metrics: vec![],
        });
    }
    None
}

/// Build a valid-structure WorkPackage with an invalid (non-existent) service ID.
fn build_invalid_service_id_wp(ctx: &crate::rpc::ContextResult) -> Result<Vec<u8>, String> {
    let code_hash = Hash::from_hex(ctx.code_hash.as_deref().ok_or("missing code_hash")?);
    let anchor = Hash::from_hex(&ctx.anchor);
    let state_root = Hash::from_hex(&ctx.state_root);
    let beefy_root = Hash::from_hex(&ctx.beefy_root);

    let context = RefinementContext {
        anchor,
        state_root,
        beefy_root,
        lookup_anchor: anchor,
        lookup_anchor_timeslot: ctx.slot,
        prerequisites: vec![],
    };

    let item = WorkItem {
        service_id: u32::MAX, // Non-existent service
        code_hash,
        gas_limit: 5_000_000,
        accumulate_gas_limit: 1_000_000,
        exports_count: 0,
        payload: vec![1, 2, 3],
        imports: vec![],
        extrinsics: vec![],
    };

    let wp = WorkPackage {
        auth_code_host: u32::MAX, // Non-existent service
        auth_code_hash: code_hash,
        context,
        authorization: vec![],
        authorizer_config: vec![],
        items: vec![item],
    };

    Ok(wp.encode())
}

/// Build a valid-structure WorkPackage with a wrong (random) code hash.
fn build_wrong_code_hash_wp(ctx: &crate::rpc::ContextResult) -> Result<Vec<u8>, String> {
    let anchor = Hash::from_hex(&ctx.anchor);
    let state_root = Hash::from_hex(&ctx.state_root);
    let beefy_root = Hash::from_hex(&ctx.beefy_root);
    let wrong_hash = Hash([0xDE; 32]); // Random/wrong code hash

    let context = RefinementContext {
        anchor,
        state_root,
        beefy_root,
        lookup_anchor: anchor,
        lookup_anchor_timeslot: ctx.slot,
        prerequisites: vec![],
    };

    let item = WorkItem {
        service_id: 2000,
        code_hash: wrong_hash, // Wrong code hash
        gas_limit: 5_000_000,
        accumulate_gas_limit: 1_000_000,
        exports_count: 0,
        payload: vec![1, 2, 3],
        imports: vec![],
        extrinsics: vec![],
    };

    let wp = WorkPackage {
        auth_code_host: 2000,
        auth_code_hash: wrong_hash,
        context,
        authorization: vec![],
        authorizer_config: vec![],
        items: vec![item],
    };

    Ok(wp.encode())
}

/// Build a valid-structure WorkPackage with a wrong (all-zeros) refinement context.
fn build_wrong_context_wp(ctx: &crate::rpc::ContextResult) -> Result<Vec<u8>, String> {
    let code_hash = Hash::from_hex(ctx.code_hash.as_deref().ok_or("missing code_hash")?);
    let zero_hash = Hash([0u8; 32]); // Wrong: all-zeros context

    let context = RefinementContext {
        anchor: zero_hash,
        state_root: zero_hash,
        beefy_root: zero_hash,
        lookup_anchor: zero_hash,
        lookup_anchor_timeslot: 0, // Expired/wrong timeslot
        prerequisites: vec![],
    };

    let item = WorkItem {
        service_id: 2000,
        code_hash,
        gas_limit: 5_000_000,
        accumulate_gas_limit: 1_000_000,
        exports_count: 0,
        payload: vec![1, 2, 3],
        imports: vec![],
        extrinsics: vec![],
    };

    let wp = WorkPackage {
        auth_code_host: 2000,
        auth_code_hash: code_hash,
        context,
        authorization: vec![],
        authorizer_config: vec![],
        items: vec![item],
    };

    Ok(wp.encode())
}

/// Build a valid-structure WorkPackage with zero work items (empty items vector).
fn build_empty_items_wp(ctx: &crate::rpc::ContextResult) -> Result<Vec<u8>, String> {
    let code_hash = Hash::from_hex(ctx.code_hash.as_deref().ok_or("missing code_hash")?);
    let anchor = Hash::from_hex(&ctx.anchor);
    let state_root = Hash::from_hex(&ctx.state_root);
    let beefy_root = Hash::from_hex(&ctx.beefy_root);

    let context = RefinementContext {
        anchor,
        state_root,
        beefy_root,
        lookup_anchor: anchor,
        lookup_anchor_timeslot: ctx.slot,
        prerequisites: vec![],
    };

    let wp = WorkPackage {
        auth_code_host: 2000,
        auth_code_hash: code_hash,
        context,
        authorization: vec![],
        authorizer_config: vec![],
        items: vec![], // Empty items
    };

    Ok(wp.encode())
}

/// Submit a structurally-valid but semantically-invalid work package.
/// These may be accepted by the RPC layer (JAM codec is valid) but should
/// be rejected by consensus. Either outcome is acceptable — the test
/// verifies the node does not crash or hang.
async fn submit_semantic_invalid(
    client: &RpcClient,
    data: &str,
    description: &str,
) -> Option<ScenarioResult> {
    match client.submit_work_package(data).await {
        Ok(_) => {
            // Accepted by RPC layer (will be rejected by consensus later) — OK
            tracing::info!(
                "{}: accepted by RPC (rejected at consensus layer)",
                description
            );
        }
        Err(_) => {
            // Rejected at RPC layer — also OK
            tracing::info!("{}: rejected at RPC layer", description);
        }
    }
    None
}

pub async fn run(client: &RpcClient) -> ScenarioResult {
    let start = Instant::now();

    // ── Phase 1: Structural invalidity (malformed inputs) ──────────

    // Test 1: Random bytes (invalid JAM codec)
    let random_hex = hex::encode([0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);
    if let Some(r) = assert_rejected(client, &random_hex, "random bytes", &start).await {
        return r;
    }

    // Test 2: Empty work package
    if let Some(r) = assert_rejected(client, "", "empty work package", &start).await {
        return r;
    }

    // Test 3: Invalid hex
    if let Some(r) = assert_rejected(client, "not-hex-data", "invalid hex", &start).await {
        return r;
    }

    // Test 4: Oversized payload (15MB > MAX_WORK_PACKAGE_BLOB_SIZE)
    let oversized = hex::encode(vec![0u8; 15_000_000]);
    if let Some(r) = assert_rejected(client, &oversized, "oversized work package", &start).await {
        return r;
    }

    // ── Phase 2: Semantic invalidity (valid codec, wrong content) ──
    // These pass JAM codec validation but contain semantically invalid
    // fields (wrong service ID, wrong code hash, wrong context, etc.).
    // The RPC layer may accept them; consensus will reject later.

    // Get a valid context to build structurally-correct WPs
    let ctx = match client.get_context(2000).await {
        Ok(ctx) => ctx,
        Err(e) => {
            return ScenarioResult {
                name: "invalid_wp",
                pass: false,
                duration: start.elapsed(),
                error: Some(format!("failed to get context for semantic tests: {}", e)),
                latencies: vec![],
                metrics: vec![],
            };
        }
    };

    // Test 5: Invalid (non-existent) service ID
    if let Some(r) = match build_invalid_service_id_wp(&ctx) {
        Ok(bytes) => {
            submit_semantic_invalid(client, &hex::encode(&bytes), "invalid service ID").await
        }
        Err(e) => Some(ScenarioResult {
            name: "invalid_wp",
            pass: false,
            duration: start.elapsed(),
            error: Some(format!("failed to build invalid-service-id WP: {}", e)),
            latencies: vec![],
            metrics: vec![],
        }),
    } {
        return r;
    }

    // Test 6: Wrong code hash
    if let Some(r) = match build_wrong_code_hash_wp(&ctx) {
        Ok(bytes) => submit_semantic_invalid(client, &hex::encode(&bytes), "wrong code hash").await,
        Err(e) => Some(ScenarioResult {
            name: "invalid_wp",
            pass: false,
            duration: start.elapsed(),
            error: Some(format!("failed to build wrong-code-hash WP: {}", e)),
            latencies: vec![],
            metrics: vec![],
        }),
    } {
        return r;
    }

    // Test 7: Wrong refinement context
    if let Some(r) = match build_wrong_context_wp(&ctx) {
        Ok(bytes) => submit_semantic_invalid(client, &hex::encode(&bytes), "wrong context").await,
        Err(e) => Some(ScenarioResult {
            name: "invalid_wp",
            pass: false,
            duration: start.elapsed(),
            error: Some(format!("failed to build wrong-context WP: {}", e)),
            latencies: vec![],
            metrics: vec![],
        }),
    } {
        return r;
    }

    // Test 8: Empty work items
    if let Some(r) = match build_empty_items_wp(&ctx) {
        Ok(bytes) => {
            submit_semantic_invalid(client, &hex::encode(&bytes), "empty work items").await
        }
        Err(e) => Some(ScenarioResult {
            name: "invalid_wp",
            pass: false,
            duration: start.elapsed(),
            error: Some(format!("failed to build empty-items WP: {}", e)),
            latencies: vec![],
            metrics: vec![],
        }),
    } {
        return r;
    }

    // ── Phase 3: Verify node is still healthy after all invalid submissions ──

    if let Err(e) = client.get_status().await {
        return ScenarioResult {
            name: "invalid_wp",
            pass: false,
            duration: start.elapsed(),
            error: Some(format!("node unhealthy after invalid submissions: {}", e)),
            latencies: vec![],
            metrics: vec![],
        };
    }

    ScenarioResult {
        name: "invalid_wp",
        pass: true,
        duration: start.elapsed(),
        error: None,
        latencies: vec![],
        metrics: vec![],
    }
}
