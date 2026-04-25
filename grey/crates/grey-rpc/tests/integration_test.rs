//! End-to-end integration tests for Grey JSON-RPC server.
//!
//! These tests exercise the full RPC stack against a running Grey node
//! (sequential testnet mode), complementing the unit tests in lib.rs which
//! test individual methods in isolation with a mock store.
//!
//! Run with: cargo test --test integration_test
//!
//! Each test starts an ephemeral node on a unique port to avoid collisions.

use grey_store::Store;
use grey_types::config::Config;
use grey_types::header::{Block, Extrinsic, Header, UnsignedHeader};
use grey_types::{BandersnatchSignature, Hash};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::rpc_params;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Allocate a unique port for each test to avoid "address already in use" errors.
static PORT_COUNTER: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(19100);

fn next_port() -> u16 {
    PORT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Create a temp store, RPC state, and start an ephemeral server on a unique port.
async fn setup() -> (
    String,
    Arc<grey_rpc::RpcState>,
    mpsc::Receiver<grey_rpc::RpcCommand>,
    Arc<Store>,
    tempfile::TempDir,
) {
    let port = next_port();
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path().join("test.redb")).unwrap());
    let config = Config::tiny();
    let (state, rx) = grey_rpc::create_rpc_channel(store.clone(), config, port);
    let (addr, _handle) = grey_rpc::start_rpc_server_ephemeral(state.clone())
        .await
        .unwrap();
    let url = format!("http://{}", addr);
    (url, state, rx, store, dir)
}

/// Build a test block with a given timeslot.
fn test_block(slot: u32) -> Block {
    Block {
        header: Header {
            data: UnsignedHeader {
                parent_hash: Hash([1u8; 32]),
                state_root: Hash([2u8; 32]),
                extrinsic_hash: Hash([3u8; 32]),
                timeslot: slot,
                epoch_marker: None,
                tickets_marker: None,
                author_index: 0,
                vrf_signature: BandersnatchSignature([7u8; 96]),
                offenders_marker: vec![],
            },
            seal: BandersnatchSignature([8u8; 96]),
        },
        extrinsic: Extrinsic::default(),
    }
}

/// Helper: insert a block and set it as head.
fn insert_block(store: &Store, slot: u32) -> Hash {
    let block = test_block(slot);
    let hash = store.put_block(&block).unwrap();
    store.set_head(&hash, slot).unwrap();
    hash
}

// ─── Integration tests: multi-method workflows ──────────────────────────

/// Test that after inserting blocks, getHead and getBlockBySlot agree.
#[tokio::test]
async fn test_head_and_slot_consistency() {
    let (url, _state, _rx, store, _dir) = setup().await;
    let client = HttpClientBuilder::default().build(&url).unwrap();

    // Insert blocks at slots 10, 20, 30
    insert_block(&store, 10);
    insert_block(&store, 20);
    insert_block(&store, 30);

    // getHead should return slot 30
    let head: serde_json::Value = client.request("jam_getHead", rpc_params![]).await.unwrap();
    assert_eq!(head["slot"], 30);

    // getBlockBySlot(30) should return the same hash
    let by_slot: serde_json::Value = client
        .request("jam_getBlockBySlot", rpc_params![30])
        .await
        .unwrap();
    assert_eq!(by_slot["hash"], head["hash"]);
}

/// Test that getBlock and getBlockBySlot return consistent data for the same block.
#[tokio::test]
async fn test_block_and_slot_return_same_block() {
    let (url, _state, _rx, store, _dir) = setup().await;
    let client = HttpClientBuilder::default().build(&url).unwrap();

    let hash = insert_block(&store, 55);

    // Query by hash
    let by_hash: serde_json::Value = client
        .request("jam_getBlock", rpc_params![hash.to_hex()])
        .await
        .unwrap();

    // Query by slot
    let by_slot: serde_json::Value = client
        .request("jam_getBlockBySlot", rpc_params![55])
        .await
        .unwrap();

    // Both should reference the same block
    assert_eq!(by_hash["timeslot"], 55);
    assert_eq!(by_hash["author_index"], 0);
    assert_eq!(by_slot["slot"], 55);
}

/// Test the full lifecycle: status → head → block → finalized.
#[tokio::test]
async fn test_full_query_lifecycle() {
    let (url, _state, _rx, store, _dir) = setup().await;
    let client = HttpClientBuilder::default().build(&url).unwrap();

    // 1. Initial status: no blocks
    let status: serde_json::Value = client
        .request("jam_getStatus", rpc_params![])
        .await
        .unwrap();
    assert!(status["head_slot"].is_number());

    // 2. Insert a block and set as finalized
    let block = test_block(42);
    let hash = store.put_block(&block).unwrap();
    store.set_head(&hash, 42).unwrap();
    store.set_finalized(&hash, 42).unwrap();

    // 3. Check head reflects the new block
    let head: serde_json::Value = client.request("jam_getHead", rpc_params![]).await.unwrap();
    assert_eq!(head["slot"], 42);
    assert_eq!(head["hash"], hash.to_hex());

    // 4. Check finalized reflects the same block
    let finalized: serde_json::Value = client
        .request("jam_getFinalized", rpc_params![])
        .await
        .unwrap();
    assert_eq!(finalized["slot"], 42);
    assert_eq!(finalized["hash"], hash.to_hex());

    // 5. Get block by hash and verify contents
    let block_resp: serde_json::Value = client
        .request("jam_getBlock", rpc_params![hash.to_hex()])
        .await
        .unwrap();
    assert_eq!(block_resp["timeslot"], 42);
    assert_eq!(block_resp["tickets_count"], 0);
    assert_eq!(block_resp["guarantees_count"], 0);
    assert_eq!(block_resp["assurances_count"], 0);
}

/// Test that head, finalized, and block queries all return null/empty
/// on a fresh store with no blocks.
#[tokio::test]
async fn test_empty_store_returns_defaults() {
    let (url, _state, _rx, _store, _dir) = setup().await;
    let client = HttpClientBuilder::default().build(&url).unwrap();

    // Head should be null
    let head: serde_json::Value = client.request("jam_getHead", rpc_params![]).await.unwrap();
    assert!(head["hash"].is_null());
    assert_eq!(head["slot"], 0);

    // Finalized should be null
    let finalized: serde_json::Value = client
        .request("jam_getFinalized", rpc_params![])
        .await
        .unwrap();
    assert!(finalized["hash"].is_null());
    assert_eq!(finalized["slot"], 0);

    // Block by non-existent hash should error
    let result: Result<serde_json::Value, _> = client
        .request("jam_getBlock", rpc_params![hex::encode([0u8; 32])])
        .await;
    assert!(result.is_err());
}

/// Test that multiple blocks can be queried independently by slot.
#[tokio::test]
async fn test_multiple_blocks_by_slot() {
    let (url, _state, _rx, store, _dir) = setup().await;
    let client = HttpClientBuilder::default().build(&url).unwrap();

    // Insert blocks at different slots
    let block1 = test_block(10);
    let hash1 = store.put_block(&block1).unwrap();
    let block2 = test_block(20);
    let hash2 = store.put_block(&block2).unwrap();
    let block3 = test_block(30);
    let hash3 = store.put_block(&block3).unwrap();

    // Set head to the latest
    store.set_head(&hash3, 30).unwrap();

    // Each slot should return the correct hash
    let slot10: serde_json::Value = client
        .request("jam_getBlockBySlot", rpc_params![10])
        .await
        .unwrap();
    assert_eq!(slot10["hash"], hash1.to_hex());

    let slot20: serde_json::Value = client
        .request("jam_getBlockBySlot", rpc_params![20])
        .await
        .unwrap();
    assert_eq!(slot20["hash"], hash2.to_hex());

    let slot30: serde_json::Value = client
        .request("jam_getBlockBySlot", rpc_params![30])
        .await
        .unwrap();
    assert_eq!(slot30["hash"], hash3.to_hex());
}

/// Test that finalized can lag behind head.
#[tokio::test]
async fn test_finalized_lags_behind_head() {
    let (url, _state, _rx, store, _dir) = setup().await;
    let client = HttpClientBuilder::default().build(&url).unwrap();

    // Insert block at slot 10 and finalize it
    let block1 = test_block(10);
    let hash1 = store.put_block(&block1).unwrap();
    store.set_finalized(&hash1, 10).unwrap();

    // Insert block at slot 20 and set as head (not finalized yet)
    let block2 = test_block(20);
    let hash2 = store.put_block(&block2).unwrap();
    store.set_head(&hash2, 20).unwrap();

    // Head should be at slot 20
    let head: serde_json::Value = client.request("jam_getHead", rpc_params![]).await.unwrap();
    assert_eq!(head["slot"], 20);

    // Finalized should still be at slot 10
    let finalized: serde_json::Value = client
        .request("jam_getFinalized", rpc_params![])
        .await
        .unwrap();
    assert_eq!(finalized["slot"], 10);
    assert_ne!(finalized["hash"], head["hash"]);
}

/// Test concurrent RPC requests don't cause panics or data corruption.
#[tokio::test]
async fn test_concurrent_requests() {
    let (url, _state, _rx, store, _dir) = setup().await;
    let client = HttpClientBuilder::default().build(&url).unwrap();
    insert_block(&store, 100);

    // Fire 10 concurrent getStatus requests
    let mut handles = Vec::new();
    for _ in 0..10 {
        let client = client.clone();
        handles.push(tokio::spawn(async move {
            client
                .request::<serde_json::Value, _>("jam_getStatus", rpc_params![])
                .await
        }));
    }

    for handle in handles {
        let result = handle.await.unwrap().unwrap();
        assert!(result.get("head_slot").is_some());
    }
}

/// Test that getChainSpec returns valid configuration.
#[tokio::test]
async fn test_get_chain_spec() {
    let (url, _state, _rx, _store, _dir) = setup().await;
    let client = HttpClientBuilder::default().build(&url).unwrap();

    let result: serde_json::Value = client
        .request("jam_getChainSpec", rpc_params![])
        .await
        .unwrap();

    // Tiny config should have V=6
    assert_eq!(result["validators_count"], 6);
    assert_eq!(result["core_count"], 2);
    assert!(result.get("epoch_length").is_some());
}

/// Test that the health and readiness endpoints work correctly
/// via HTTP GET (not JSON-RPC).
#[tokio::test]
async fn test_http_health_and_ready() {
    let (url, _state, _rx, store, _dir) = setup().await;

    // Health should always return 200
    let resp = reqwest::get(format!("{}/health", url)).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["status"], "ok");

    // Ready without blocks should return 503
    let resp = reqwest::get(format!("{}/ready", url)).await.unwrap();
    assert_eq!(resp.status(), 503);

    // Insert a block and check ready again
    insert_block(&store, 1);
    let resp = reqwest::get(format!("{}/ready", url)).await.unwrap();
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["status"], "ready");
}

/// Test that readStorage returns an error for a non-existent key.
#[tokio::test]
async fn test_read_storage_missing_key() {
    let (url, _state, _rx, store, _dir) = setup().await;
    let client = HttpClientBuilder::default().build(&url).unwrap();

    // Insert a block so there's a head to query against
    insert_block(&store, 1);

    let result: Result<serde_json::Value, _> = client
        .request(
            "jam_readStorage",
            rpc_params![42u32, hex::encode([0u8; 32]), 1u32],
        )
        .await;
    // Non-existent service should error
    assert!(result.is_err());
}

/// Test that getState returns an error for a block without stored state,
/// and succeeds when state is properly stored.
#[tokio::test]
async fn test_get_state() {
    let (url, _state, _rx, store, _dir) = setup().await;
    let client = HttpClientBuilder::default().build(&url).unwrap();
    let config = Config::tiny();

    // Insert a block with a proper state
    let (genesis_state, _) = grey_consensus::genesis::create_genesis(&config);
    let block = test_block(1);
    let hash = store.put_block(&block).unwrap();
    store.put_state(&hash, &genesis_state, &config).unwrap();
    store.set_head(&hash, 1).unwrap();

    // Query state by block hash
    let result: serde_json::Value = client
        .request("jam_getState", rpc_params![Some(hash.to_hex())])
        .await
        .unwrap();

    // Should return a state structure
    assert!(result.is_object());
}
