//! JSON-RPC server for the Grey node.
//!
//! Provides endpoints for:
//! - Work package submission
//! - State queries (head, block, service accounts)
//! - Node status
//! - Work package context (refinement context + service info)

use grey_store::Store;
use grey_types::Hash;
use grey_types::config::Config;
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::Server;
use jsonrpsee::types::ErrorObjectOwned;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::sync::mpsc;

/// Commands sent from RPC to the node event loop.
#[derive(Debug)]
pub enum RpcCommand {
    /// Submit a work package for inclusion.
    SubmitWorkPackage { data: Vec<u8> },
}

/// Snapshot of node status exposed via RPC.
#[derive(Clone, Debug, serde::Serialize)]
pub struct NodeStatus {
    pub head_slot: u32,
    pub head_hash: String,
    pub finalized_slot: u32,
    pub finalized_hash: String,
    pub blocks_authored: u64,
    pub blocks_imported: u64,
    pub validator_index: u16,
}

/// Shared state accessible by the RPC server.
pub struct RpcState {
    pub store: Arc<Store>,
    pub config: Config,
    pub status: RwLock<NodeStatus>,
    pub commands: mpsc::Sender<RpcCommand>,
}

#[rpc(server)]
pub trait JamRpc {
    /// Get current node status.
    #[method(name = "jam_getStatus")]
    async fn get_status(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get the head block hash and timeslot.
    #[method(name = "jam_getHead")]
    async fn get_head(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get a block by its header hash (hex-encoded).
    #[method(name = "jam_getBlock")]
    async fn get_block(&self, hash_hex: String) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get a block hash by timeslot.
    #[method(name = "jam_getBlockBySlot")]
    async fn get_block_by_slot(&self, slot: u32) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Submit a work package (hex-encoded JAM-encoded bytes).
    #[method(name = "jam_submitWorkPackage")]
    async fn submit_work_package(
        &self,
        data_hex: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get finalized block info.
    #[method(name = "jam_getFinalized")]
    async fn get_finalized(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Read a value from a service's storage.
    #[method(name = "jam_readStorage")]
    async fn read_storage(
        &self,
        service_id: u32,
        key_hex: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get work-package context: refinement context fields and service code hash.
    /// Clients need this to build valid work packages.
    #[method(name = "jam_getContext")]
    async fn get_context(&self, service_id: u32) -> Result<serde_json::Value, ErrorObjectOwned>;
}

struct RpcImpl {
    state: Arc<RpcState>,
}

fn internal_error(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32603, msg.into(), None::<()>)
}

fn not_found(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32001, msg.into(), None::<()>)
}

#[async_trait]
impl JamRpcServer for RpcImpl {
    async fn get_status(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let status = self.state.status.read().await;
        serde_json::to_value(&*status).map_err(|e| internal_error(e.to_string()))
    }

    async fn get_head(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        match self.state.store.get_head() {
            Ok((hash, slot)) => Ok(serde_json::json!({
                "hash": hex::encode(hash.0),
                "slot": slot,
            })),
            Err(_) => Ok(serde_json::json!({
                "hash": null,
                "slot": 0,
            })),
        }
    }

    async fn get_block(&self, hash_hex: String) -> Result<serde_json::Value, ErrorObjectOwned> {
        let hash_bytes = hex::decode(hash_hex.trim_start_matches("0x"))
            .map_err(|e| internal_error(e.to_string()))?;
        if hash_bytes.len() != 32 {
            return Err(internal_error("hash must be 32 bytes"));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_bytes);

        match self.state.store.get_block(&Hash(hash)) {
            Ok(block) => Ok(serde_json::json!({
                "timeslot": block.header.timeslot,
                "author_index": block.header.author_index,
                "parent_hash": hex::encode(block.header.parent_hash.0),
                "state_root": hex::encode(block.header.state_root.0),
                "extrinsic_hash": hex::encode(block.header.extrinsic_hash.0),
                "tickets_count": block.extrinsic.tickets.len(),
                "guarantees_count": block.extrinsic.guarantees.len(),
                "assurances_count": block.extrinsic.assurances.len(),
            })),
            Err(grey_store::StoreError::NotFound) => Err(not_found("block not found")),
            Err(e) => Err(internal_error(e.to_string())),
        }
    }

    async fn get_block_by_slot(&self, slot: u32) -> Result<serde_json::Value, ErrorObjectOwned> {
        match self.state.store.get_block_hash_by_slot(slot) {
            Ok(hash) => Ok(serde_json::json!({
                "hash": hex::encode(hash.0),
                "slot": slot,
            })),
            Err(grey_store::StoreError::NotFound) => Err(not_found("no block at this slot")),
            Err(e) => Err(internal_error(e.to_string())),
        }
    }

    async fn submit_work_package(
        &self,
        data_hex: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let data = hex::decode(data_hex.trim_start_matches("0x"))
            .map_err(|e| internal_error(format!("invalid hex: {}", e)))?;

        if data.is_empty() {
            return Err(internal_error("empty work package"));
        }

        let hash = grey_crypto::blake2b_256(&data);

        self.state
            .commands
            .send(RpcCommand::SubmitWorkPackage { data })
            .await
            .map_err(|_| internal_error("node channel closed"))?;

        Ok(serde_json::json!({
            "hash": hex::encode(hash.0),
            "status": "submitted",
        }))
    }

    async fn get_finalized(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        match self.state.store.get_finalized() {
            Ok((hash, slot)) => Ok(serde_json::json!({
                "hash": hex::encode(hash.0),
                "slot": slot,
            })),
            Err(_) => Ok(serde_json::json!({
                "hash": null,
                "slot": 0,
            })),
        }
    }

    async fn read_storage(
        &self,
        service_id: u32,
        key_hex: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let (head_hash, head_slot) = self
            .state
            .store
            .get_head()
            .map_err(|e| internal_error(e.to_string()))?;

        let key_bytes = hex::decode(key_hex.trim_start_matches("0x"))
            .map_err(|e| internal_error(format!("invalid hex key: {}", e)))?;

        // Direct lookup via computed state key — avoids full state deserialization
        // and correctly handles service storage (which is opaque in deserialized state).
        match self
            .state
            .store
            .get_service_storage(&head_hash, service_id, &key_bytes)
            .map_err(|e| internal_error(e.to_string()))?
        {
            Some(value) => Ok(serde_json::json!({
                "service_id": service_id,
                "key": hex::encode(&key_bytes),
                "value": hex::encode(&value),
                "length": value.len(),
                "slot": head_slot,
            })),
            None => Ok(serde_json::json!({
                "service_id": service_id,
                "key": hex::encode(&key_bytes),
                "value": null,
                "length": 0,
                "slot": head_slot,
            })),
        }
    }

    async fn get_context(&self, service_id: u32) -> Result<serde_json::Value, ErrorObjectOwned> {
        let (head_hash, head_slot) = self
            .state
            .store
            .get_head()
            .map_err(|e| internal_error(e.to_string()))?;

        // Get block header for state_root
        let block = self
            .state
            .store
            .get_block(&head_hash)
            .map_err(|e| internal_error(e.to_string()))?;

        let anchor = hex::encode(head_hash.0);
        let state_root = hex::encode(block.header.state_root.0);
        let beefy_root = self
            .state
            .store
            .get_accumulation_root(&head_hash, &head_hash)
            .map_err(|e| internal_error(e.to_string()))?
            .map(|h| hex::encode(h.0))
            .unwrap_or_else(|| hex::encode([0u8; 32]));

        // Direct lookup for service code hash (avoids full state deserialization)
        let code_hash = self
            .state
            .store
            .get_service_code_hash(&head_hash, service_id)
            .map_err(|e| internal_error(e.to_string()))?
            .map(|h| hex::encode(h.0));

        Ok(serde_json::json!({
            "slot": head_slot,
            "anchor": anchor,
            "state_root": state_root,
            "beefy_root": beefy_root,
            "code_hash": code_hash,
        }))
    }
}

// ── Health / readiness HTTP endpoints ─────────────────────────────────

/// Tower layer that intercepts GET `/health` and `/ready` before they
/// reach the JSON-RPC handler.
///
/// - `GET /health` — always 200 `{"status":"ok"}` (process is alive)
/// - `GET /ready`  — 200 `{"status":"ready","head_slot":N}` if head is set,
///   503 `{"status":"syncing"}` otherwise
#[derive(Clone)]
struct HealthLayer {
    state: Arc<RpcState>,
}

impl<S> tower::Layer<S> for HealthLayer {
    type Service = HealthService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        HealthService {
            inner,
            state: self.state.clone(),
        }
    }
}

#[derive(Clone)]
struct HealthService<S> {
    inner: S,
    state: Arc<RpcState>,
}

type HttpBody = jsonrpsee::server::HttpBody;

fn json_response(status: u16, body: String) -> http::Response<HttpBody> {
    http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(HttpBody::from(body))
        .unwrap()
}

impl<S, ReqBody> tower::Service<http::Request<ReqBody>> for HealthService<S>
where
    S: tower::Service<http::Request<ReqBody>, Response = http::Response<HttpBody>>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
    ReqBody: Send + 'static,
{
    type Response = http::Response<HttpBody>;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<ReqBody>) -> Self::Future {
        let is_get = req.method() == http::Method::GET;
        let path = req.uri().path().to_owned();

        if is_get && path == "/health" {
            let body = serde_json::json!({"status": "ok"}).to_string();
            Box::pin(async move { Ok(json_response(200, body)) })
        } else if is_get && path == "/ready" {
            let state = self.state.clone();
            Box::pin(async move {
                match state.store.get_head() {
                    Ok((_, slot)) => Ok(json_response(
                        200,
                        serde_json::json!({"status": "ready", "head_slot": slot}).to_string(),
                    )),
                    Err(_) => Ok(json_response(
                        503,
                        serde_json::json!({"status": "syncing"}).to_string(),
                    )),
                }
            })
        } else {
            let fut = self.inner.call(req);
            Box::pin(fut)
        }
    }
}

/// Start the JSON-RPC server. Returns the command receiver for the node event loop.
pub async fn start_rpc_server(
    port: u16,
    state: Arc<RpcState>,
    cors: bool,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>), Box<dyn std::error::Error + Send + Sync>> {
    let addr = format!("0.0.0.0:{}", port);
    let cors_layer = if cors {
        tracing::info!("RPC CORS enabled (permissive)");
        tower_http::cors::CorsLayer::permissive()
    } else {
        tower_http::cors::CorsLayer::new()
    };
    let health_layer = HealthLayer {
        state: state.clone(),
    };
    let middleware = tower::ServiceBuilder::new()
        .layer(cors_layer)
        .layer(health_layer);
    let server = Server::builder()
        .set_http_middleware(middleware)
        .build(&addr)
        .await?;
    let bound_addr = server.local_addr()?;

    let rpc_impl = RpcImpl { state };

    let handle = server.start(rpc_impl.into_rpc());

    let join = tokio::spawn(async move {
        handle.stopped().await;
    });

    tracing::info!("RPC server listening on {}", bound_addr);
    Ok((bound_addr, join))
}

/// Start the RPC server on an ephemeral port (port 0). Useful for testing.
pub async fn start_rpc_server_ephemeral(
    state: Arc<RpcState>,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>), Box<dyn std::error::Error + Send + Sync>> {
    start_rpc_server(0, state, false).await
}

/// Create RPC state and command channel.
pub fn create_rpc_channel(
    store: Arc<Store>,
    config: Config,
    validator_index: u16,
) -> (Arc<RpcState>, mpsc::Receiver<RpcCommand>) {
    let (tx, rx) = mpsc::channel(256);

    let state = Arc::new(RpcState {
        store,
        config,
        status: RwLock::new(NodeStatus {
            head_slot: 0,
            head_hash: String::new(),
            finalized_slot: 0,
            finalized_hash: String::new(),
            blocks_authored: 0,
            blocks_imported: 0,
            validator_index,
        }),
        commands: tx,
    });

    (state, rx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use grey_types::BandersnatchSignature;
    use grey_types::header::{Block, Extrinsic, Header};
    use jsonrpsee::core::client::ClientT;
    use jsonrpsee::http_client::HttpClientBuilder;
    use jsonrpsee::rpc_params;

    /// Create a temp store, RPC state, and start an ephemeral server.
    /// Returns (client_url, rpc_state, command_rx, store, _tempdir).
    async fn setup() -> (
        String,
        Arc<RpcState>,
        mpsc::Receiver<RpcCommand>,
        Arc<Store>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path().join("test.redb")).unwrap());
        let config = Config::tiny();
        let (state, rx) = create_rpc_channel(store.clone(), config, 0);
        let (addr, _handle) = start_rpc_server_ephemeral(state.clone()).await.unwrap();
        let url = format!("http://{}", addr);
        (url, state, rx, store, dir)
    }

    fn test_block(slot: u32) -> Block {
        Block {
            header: Header {
                parent_hash: Hash([1u8; 32]),
                state_root: Hash([2u8; 32]),
                extrinsic_hash: Hash([3u8; 32]),
                timeslot: slot,
                epoch_marker: None,
                tickets_marker: None,
                author_index: 5,
                vrf_signature: BandersnatchSignature([7u8; 96]),
                offenders_marker: vec![],
                seal: BandersnatchSignature([8u8; 96]),
            },
            extrinsic: Extrinsic::default(),
        }
    }

    #[tokio::test]
    async fn test_get_status() {
        let (url, state, _rx, _store, _dir) = setup().await;
        {
            let mut status = state.status.write().await;
            status.head_slot = 42;
            status.head_hash = "abc123".into();
            status.blocks_authored = 10;
        }
        let client = HttpClientBuilder::default().build(&url).unwrap();
        let result: serde_json::Value = client
            .request("jam_getStatus", rpc_params![])
            .await
            .unwrap();
        assert_eq!(result["head_slot"], 42);
        assert_eq!(result["head_hash"], "abc123");
        assert_eq!(result["blocks_authored"], 10);
        assert_eq!(result["validator_index"], 0);
    }

    #[tokio::test]
    async fn test_get_head_empty() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();
        let result: serde_json::Value = client.request("jam_getHead", rpc_params![]).await.unwrap();
        assert!(result["hash"].is_null());
        assert_eq!(result["slot"], 0);
    }

    #[tokio::test]
    async fn test_get_head_with_block() {
        let (url, _state, _rx, store, _dir) = setup().await;
        let block = test_block(100);
        let hash = store.put_block(&block).unwrap();
        store.set_head(&hash, 100).unwrap();

        let client = HttpClientBuilder::default().build(&url).unwrap();
        let result: serde_json::Value = client.request("jam_getHead", rpc_params![]).await.unwrap();
        assert_eq!(result["hash"], hex::encode(hash.0));
        assert_eq!(result["slot"], 100);
    }

    #[tokio::test]
    async fn test_get_block() {
        let (url, _state, _rx, store, _dir) = setup().await;
        let block = test_block(50);
        let hash = store.put_block(&block).unwrap();

        let client = HttpClientBuilder::default().build(&url).unwrap();
        let result: serde_json::Value = client
            .request("jam_getBlock", rpc_params![hex::encode(hash.0)])
            .await
            .unwrap();
        assert_eq!(result["timeslot"], 50);
        assert_eq!(result["author_index"], 5);
    }

    #[tokio::test]
    async fn test_get_block_not_found() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();
        let result: Result<serde_json::Value, _> = client
            .request("jam_getBlock", rpc_params![hex::encode([0u8; 32])])
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_block_invalid_hex() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();
        let result: Result<serde_json::Value, _> =
            client.request("jam_getBlock", rpc_params!["not_hex"]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_block_wrong_length() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();
        let result: Result<serde_json::Value, _> =
            client.request("jam_getBlock", rpc_params!["aabb"]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_block_by_slot() {
        let (url, _state, _rx, store, _dir) = setup().await;
        let block = test_block(77);
        let hash = store.put_block(&block).unwrap();

        let client = HttpClientBuilder::default().build(&url).unwrap();
        let result: serde_json::Value = client
            .request("jam_getBlockBySlot", rpc_params![77])
            .await
            .unwrap();
        assert_eq!(result["hash"], hex::encode(hash.0));
        assert_eq!(result["slot"], 77);
    }

    #[tokio::test]
    async fn test_get_block_by_slot_not_found() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();
        let result: Result<serde_json::Value, _> = client
            .request("jam_getBlockBySlot", rpc_params![9999])
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_finalized_empty() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();
        let result: serde_json::Value = client
            .request("jam_getFinalized", rpc_params![])
            .await
            .unwrap();
        assert!(result["hash"].is_null());
        assert_eq!(result["slot"], 0);
    }

    #[tokio::test]
    async fn test_get_finalized_with_block() {
        let (url, _state, _rx, store, _dir) = setup().await;
        let block = test_block(60);
        let hash = store.put_block(&block).unwrap();
        store.set_finalized(&hash, 60).unwrap();

        let client = HttpClientBuilder::default().build(&url).unwrap();
        let result: serde_json::Value = client
            .request("jam_getFinalized", rpc_params![])
            .await
            .unwrap();
        assert_eq!(result["hash"], hex::encode(hash.0));
        assert_eq!(result["slot"], 60);
    }

    #[tokio::test]
    async fn test_submit_work_package() {
        let (url, _state, mut rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();
        let data = hex::encode([0xAB; 16]);
        let result: serde_json::Value = client
            .request("jam_submitWorkPackage", rpc_params![data])
            .await
            .unwrap();
        assert_eq!(result["status"], "submitted");
        assert!(result["hash"].is_string());

        // Verify command was received
        let cmd = rx.try_recv().unwrap();
        match cmd {
            RpcCommand::SubmitWorkPackage { data } => {
                assert_eq!(data, vec![0xAB; 16]);
            }
        }
    }

    #[tokio::test]
    async fn test_submit_empty_work_package() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();
        let result: Result<serde_json::Value, _> = client
            .request("jam_submitWorkPackage", rpc_params![""])
            .await;
        assert!(result.is_err());
    }

    // ── Health / readiness endpoint tests ──

    async fn http_get(url: &str) -> (u16, String) {
        let resp = reqwest::get(url).await.unwrap();
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap();
        (status, body)
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let (status, body) = http_get(&format!("{}/health", url)).await;
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["status"], "ok");
    }

    #[tokio::test]
    async fn test_ready_not_synced() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let (status, body) = http_get(&format!("{}/ready", url)).await;
        assert_eq!(status, 503);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["status"], "syncing");
    }

    #[tokio::test]
    async fn test_ready_with_head() {
        let (url, _state, _rx, store, _dir) = setup().await;
        let block = test_block(42);
        let hash = store.put_block(&block).unwrap();
        store.set_head(&hash, 42).unwrap();

        let (status, body) = http_get(&format!("{}/ready", url)).await;
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["status"], "ready");
        assert_eq!(json["head_slot"], 42);
    }
}
