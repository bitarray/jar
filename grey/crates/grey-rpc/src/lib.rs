//! JSON-RPC server for the Grey node.
//!
//! Provides endpoints for:
//! - Work package submission
//! - State queries (head, block, service accounts)
//! - Node status
//! - Work package context (refinement context + service info)

use grey_store::Store;
use grey_types::config::Config;
use grey_types::Hash;
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::Server;
use jsonrpsee::types::ErrorObjectOwned;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::RwLock;

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
    async fn get_context(
        &self,
        service_id: u32,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;
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
        let hash_bytes =
            hex::decode(hash_hex.trim_start_matches("0x")).map_err(|e| internal_error(e.to_string()))?;
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
            Err(grey_store::StoreError::NotFound) => {
                Err(not_found("block not found"))
            }
            Err(e) => Err(internal_error(e.to_string())),
        }
    }

    async fn get_block_by_slot(&self, slot: u32) -> Result<serde_json::Value, ErrorObjectOwned> {
        match self.state.store.get_block_hash_by_slot(slot) {
            Ok(hash) => Ok(serde_json::json!({
                "hash": hex::encode(hash.0),
                "slot": slot,
            })),
            Err(grey_store::StoreError::NotFound) => {
                Err(not_found("no block at this slot"))
            }
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

    async fn get_context(
        &self,
        service_id: u32,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
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
        // beefy_root (accumulation output root) — use zero for now;
        // full lookup would require parsing the recent_blocks blob.
        let beefy_root = hex::encode([0u8; 32]);

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
    let middleware = tower::ServiceBuilder::new().layer(cors_layer);
    let server = Server::builder().set_http_middleware(middleware).build(&addr).await?;
    let bound_addr = server.local_addr()?;

    let rpc_impl = RpcImpl { state };

    let handle = server.start(rpc_impl.into_rpc());

    let join = tokio::spawn(async move {
        handle.stopped().await;
    });

    tracing::info!("RPC server listening on {}", bound_addr);
    Ok((bound_addr, join))
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
