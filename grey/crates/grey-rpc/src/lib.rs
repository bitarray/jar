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
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::sync::mpsc;

/// Maximum time an individual RPC request can take before being cancelled.
/// Prevents slow or hanging queries from blocking the server indefinitely.
const RPC_QUERY_TIMEOUT: Duration = Duration::from_secs(30);

/// Default maximum RPC requests per IP per window. Returns HTTP 429 when exceeded.
const DEFAULT_RATE_LIMIT_MAX_REQUESTS: u64 = 1000;
/// Rate limit window duration.
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

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
    pub grandpa_round: u64,
}

/// Shared state accessible by the RPC server.
pub struct RpcState {
    pub store: Arc<Store>,
    pub config: Config,
    pub status: RwLock<NodeStatus>,
    pub commands: mpsc::Sender<RpcCommand>,
    /// Broadcast channel for new block notifications (WebSocket subscriptions).
    pub block_notifications: tokio::sync::broadcast::Sender<serde_json::Value>,
    /// Broadcast channel for finalization notifications (WebSocket subscriptions).
    pub finality_notifications: tokio::sync::broadcast::Sender<serde_json::Value>,
    /// Connected peer count (updated by the node on PeerIdentified events).
    pub peer_count: std::sync::atomic::AtomicU32,
    /// Network event queue depth (updated by the node each tick).
    pub queue_depth_events: std::sync::atomic::AtomicU32,
    /// Network command queue depth (updated by the node each tick).
    pub queue_depth_commands: std::sync::atomic::AtomicU32,
    /// RPC command queue depth (updated by the node each tick).
    pub queue_depth_rpc: std::sync::atomic::AtomicU32,
    /// Pending blocks buffer depth (updated by the node each tick).
    pub pending_blocks_depth: std::sync::atomic::AtomicU32,
    /// Total work packages submitted via RPC.
    pub work_packages_submitted: std::sync::atomic::AtomicU64,
    /// Per-method RPC request counts for Prometheus metrics.
    pub request_counts: std::sync::Mutex<std::collections::HashMap<String, u64>>,
    /// Total RPC requests received (all methods).
    pub rpc_requests_total: std::sync::atomic::AtomicU64,
    /// Gossipsub messages received per topic.
    pub gossip_blocks_received: std::sync::atomic::AtomicU64,
    pub gossip_finality_received: std::sync::atomic::AtomicU64,
    pub gossip_guarantees_received: std::sync::atomic::AtomicU64,
    pub gossip_assurances_received: std::sync::atomic::AtomicU64,
    pub gossip_announcements_received: std::sync::atomic::AtomicU64,
    pub gossip_tickets_received: std::sync::atomic::AtomicU64,
    /// Number of state transitions applied (authored + imported blocks).
    pub state_transitions_total: std::sync::atomic::AtomicU64,
    /// Duration of the last state transition in microseconds.
    pub state_transition_last_us: std::sync::atomic::AtomicU64,
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

    /// Get a service account's metadata (balance, gas limits, code hash, etc.).
    #[method(name = "jam_getServiceAccount")]
    async fn get_service_account(
        &self,
        service_id: u32,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get the chain specification: protocol constants and configuration.
    #[method(name = "jam_getChainSpec")]
    async fn get_chain_spec(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get a lightweight state summary for the head (or specified) block.
    #[method(name = "jam_getState")]
    async fn get_state_summary(
        &self,
        block_hash_hex: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get the validator set. Optional `set` parameter: "current" (default), "pending", "previous".
    #[method(name = "jam_getValidators")]
    async fn get_validators(
        &self,
        set: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get block hashes for a range of slots. Returns an array of {slot, hash} objects.
    /// Useful for block explorers and monitoring.
    #[method(name = "jam_getBlockRange")]
    async fn get_block_range(
        &self,
        from_slot: u32,
        to_slot: u32,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Get peer connectivity information.
    #[method(name = "jam_getPeers")]
    async fn get_peers(&self) -> Result<serde_json::Value, ErrorObjectOwned>;
}

/// WebSocket subscription API.
#[rpc(server)]
pub trait JamSubscriptions {
    /// Subscribe to new block notifications (WebSocket only).
    #[subscription(name = "subscribeNewBlocks" => "newBlock", unsubscribe = "unsubscribeNewBlocks", item = serde_json::Value)]
    async fn subscribe_new_blocks(&self) -> jsonrpsee::core::SubscriptionResult;

    /// Subscribe to finalization notifications (WebSocket only).
    #[subscription(name = "subscribeFinalized" => "finalized", unsubscribe = "unsubscribeFinalized", item = serde_json::Value)]
    async fn subscribe_finalized(&self) -> jsonrpsee::core::SubscriptionResult;
}

struct RpcImpl {
    state: Arc<RpcState>,
}

impl RpcImpl {
    fn track_request(&self, method: &str) {
        if let Ok(mut counts) = self.state.request_counts.lock() {
            *counts.entry(method.to_string()).or_insert(0) += 1;
        }
    }
}

fn internal_error(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32603, msg.into(), None::<()>)
}

fn not_found(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32001, msg.into(), None::<()>)
}

/// Extension trait for converting any `Result<T, E: Display>` into an
/// RPC internal error, replacing the repeated
/// `.map_internal_err()` pattern.
trait MapInternalErr<T> {
    fn map_internal_err(self) -> Result<T, ErrorObjectOwned>;
}

impl<T, E: core::fmt::Display> MapInternalErr<T> for Result<T, E> {
    fn map_internal_err(self) -> Result<T, ErrorObjectOwned> {
        self.map_err(|e| internal_error(e.to_string()))
    }
}

/// Parse a hex-encoded 32-byte hash, stripping optional "0x" prefix.
fn parse_hash_hex(hex_str: &str) -> Result<Hash, ErrorObjectOwned> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).map_internal_err()?;
    if bytes.len() != 32 {
        return Err(internal_error("hash must be 32 bytes"));
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Ok(Hash(h))
}

#[async_trait]
impl JamRpcServer for RpcImpl {
    async fn get_status(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        self.track_request("jam_getStatus");
        let status = self.state.status.read().await;
        serde_json::to_value(&*status).map_internal_err()
    }

    async fn get_head(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        self.track_request("jam_getHead");
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
        self.track_request("jam_getBlock");
        let hash = parse_hash_hex(&hash_hex)?;

        match self.state.store.get_block(&hash) {
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
        self.track_request("jam_getBlockBySlot");
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
        self.track_request("jam_submitWorkPackage");
        let data = hex::decode(data_hex.trim_start_matches("0x"))
            .map_err(|e| internal_error(format!("invalid hex: {}", e)))?;

        if data.is_empty() {
            return Err(internal_error("empty work package"));
        }

        // Reject oversized payloads before further processing (GP constant W_B).
        if data.len() > grey_types::constants::MAX_WORK_PACKAGE_BLOB_SIZE as usize {
            return Err(internal_error(format!(
                "work package too large: {} bytes (max {})",
                data.len(),
                grey_types::constants::MAX_WORK_PACKAGE_BLOB_SIZE
            )));
        }

        // Verify the payload is a valid JAM-encoded work package.
        use scale::Decode;
        if grey_types::work::WorkPackage::decode(&data).is_err() {
            return Err(internal_error(
                "invalid work package: JAM codec decode failed",
            ));
        }

        let hash = grey_crypto::blake2b_256(&data);

        self.state
            .commands
            .send(RpcCommand::SubmitWorkPackage { data })
            .await
            .map_err(|_| internal_error("node channel closed"))?;

        self.state
            .work_packages_submitted
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        Ok(serde_json::json!({
            "hash": hex::encode(hash.0),
            "status": "submitted",
        }))
    }

    async fn get_finalized(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        self.track_request("jam_getFinalized");
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
        self.track_request("jam_readStorage");
        let (head_hash, head_slot) = self.state.store.get_head().map_internal_err()?;

        let key_bytes = hex::decode(key_hex.trim_start_matches("0x"))
            .map_err(|e| internal_error(format!("invalid hex key: {}", e)))?;

        // Direct lookup via computed state key — avoids full state deserialization
        // and correctly handles service storage (which is opaque in deserialized state).
        match self
            .state
            .store
            .get_service_storage(&head_hash, service_id, &key_bytes)
            .map_internal_err()?
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
        self.track_request("jam_getContext");
        let (head_hash, head_slot) = self.state.store.get_head().map_internal_err()?;

        // Get block header for state_root
        let block = self.state.store.get_block(&head_hash).map_internal_err()?;

        let anchor = hex::encode(head_hash.0);
        let state_root = hex::encode(block.header.state_root.0);
        let beefy_root = self
            .state
            .store
            .get_accumulation_root(&head_hash, &head_hash)
            .map_internal_err()?
            .map(|h| hex::encode(h.0))
            .unwrap_or_else(|| hex::encode([0u8; 32]));

        // Direct lookup for service code hash (avoids full state deserialization)
        let code_hash = self
            .state
            .store
            .get_service_code_hash(&head_hash, service_id)
            .map_internal_err()?
            .map(|h| hex::encode(h.0));

        Ok(serde_json::json!({
            "slot": head_slot,
            "anchor": anchor,
            "state_root": state_root,
            "beefy_root": beefy_root,
            "code_hash": code_hash,
        }))
    }

    async fn get_service_account(
        &self,
        service_id: u32,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        self.track_request("jam_getServiceAccount");
        let (head_hash, head_slot) = self.state.store.get_head().map_internal_err()?;

        match self
            .state
            .store
            .get_service_metadata(&head_hash, service_id)
            .map_internal_err()?
        {
            Some(meta) => Ok(serde_json::json!({
                "service_id": service_id,
                "code_hash": hex::encode(meta.code_hash.0),
                "quota_items": meta.quota_items,
                "min_accumulate_gas": meta.min_accumulate_gas,
                "min_on_transfer_gas": meta.min_on_transfer_gas,
                "total_footprint": meta.total_footprint,
                "quota_bytes": meta.quota_bytes,
                "accumulation_counter": meta.accumulation_counter,
                "last_accumulation": meta.last_accumulation,
                "last_activity": meta.last_activity,
                "preimage_count": meta.preimage_count,
                "slot": head_slot,
            })),
            None => Err(not_found(format!("service {} not found", service_id))),
        }
    }

    async fn get_chain_spec(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        self.track_request("jam_getChainSpec");
        let c = &self.state.config;
        let config_blob = c.encode_config_blob();
        let genesis_hash = grey_crypto::blake2b_256(&config_blob);
        Ok(serde_json::json!({
            "protocol_version": "0.7.2",
            "genesis_hash": hex::encode(genesis_hash.0),
            "validators_count": c.validators_count,
            "core_count": c.core_count,
            "epoch_length": c.epoch_length,
            "max_tickets_per_block": c.max_tickets_per_block,
            "tickets_per_validator": c.tickets_per_validator,
            "recent_history_size": c.recent_history_size,
            "auth_pool_size": c.auth_pool_size,
            "auth_queue_size": c.auth_queue_size,
            "availability_timeout": c.availability_timeout,
            "preimage_expunge_period": c.preimage_expunge_period,
            "rotation_period": c.rotation_period_val,
            "ticket_submission_end": c.ticket_submission_end_val,
            "erasure_pieces_per_segment": c.erasure_pieces_per_segment,
            "gas_total_accumulation": c.gas_total_accumulation,
            "gas_refine": c.gas_refine,
            "slot_period": 6,
        }))
    }

    async fn get_state_summary(
        &self,
        block_hash_hex: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        self.track_request("jam_getStateSummary");
        // Resolve block hash: use provided hash or default to head
        let (block_hash, slot) = if let Some(hex) = block_hash_hex {
            let hash = parse_hash_hex(&hex)?;
            // Look up the block to get the slot
            let block = self.state.store.get_block(&hash).map_internal_err()?;
            (hash, block.header.timeslot)
        } else {
            self.state.store.get_head().map_internal_err()?
        };

        // Get block header for state_root
        let block = self.state.store.get_block(&block_hash).map_internal_err()?;

        // Read entropy: C(6) = 4 × 32 raw bytes
        let entropy_raw = self
            .state
            .store
            .get_state_kv(&block_hash, &grey_merkle::state_key_from_index(6))
            .map_internal_err()?
            .unwrap_or_default();
        let entropy: Vec<String> = (0..4)
            .map(|i| {
                if entropy_raw.len() >= (i + 1) * 32 {
                    hex::encode(&entropy_raw[i * 32..(i + 1) * 32])
                } else {
                    hex::encode([0u8; 32])
                }
            })
            .collect();

        // Read current validators: C(8) = V × 336 bytes
        let validators_raw = self
            .state
            .store
            .get_state_kv(&block_hash, &grey_merkle::state_key_from_index(8))
            .map_internal_err()?
            .unwrap_or_default();
        let validator_count = validators_raw.len() / 336;

        Ok(serde_json::json!({
            "block_hash": hex::encode(block_hash.0),
            "state_root": hex::encode(block.header.state_root.0),
            "timeslot": slot,
            "entropy": entropy,
            "validator_count": validator_count,
            "core_count": self.state.config.core_count,
            "epoch_length": self.state.config.epoch_length,
        }))
    }

    async fn get_validators(
        &self,
        set: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        self.track_request("jam_getValidators");
        let set_name = set.as_deref().unwrap_or("current");

        // Component indices: 7=pending (ι), 8=current (κ), 9=previous (λ)
        let component_index: u8 = match set_name {
            "current" => 8,
            "pending" => 7,
            "previous" => 9,
            _ => {
                return Err(internal_error(format!(
                    "invalid set: {:?} (expected \"current\", \"pending\", or \"previous\")",
                    set_name
                )));
            }
        };

        let (head_hash, head_slot) = self.state.store.get_head().map_internal_err()?;

        let raw = self
            .state
            .store
            .get_state_kv(
                &head_hash,
                &grey_merkle::state_key_from_index(component_index),
            )
            .map_internal_err()?
            .unwrap_or_default();

        // Decode validators using scale (u32 count prefix + ValidatorKey entries)
        let validators: Vec<grey_types::validator::ValidatorKey> = if raw.is_empty() {
            Vec::new()
        } else {
            use scale::Decode;
            Vec::<grey_types::validator::ValidatorKey>::decode(&raw)
                .map(|(v, _)| v)
                .map_err(|e| internal_error(format!("validator decode: {e}")))?
        };

        let mut entries = Vec::with_capacity(validators.len());
        for (i, v) in validators.iter().enumerate() {
            entries.push(serde_json::json!({
                "index": i,
                "ed25519": hex::encode(v.ed25519.0),
                "bandersnatch": hex::encode(v.bandersnatch.0),
                "bls": hex::encode(v.bls.0),
                "metadata": hex::encode(v.metadata),
            }));
        }
        let count = validators.len();

        Ok(serde_json::json!({
            "set": set_name,
            "count": count,
            "validators": entries,
            "slot": head_slot,
        }))
    }

    async fn get_block_range(
        &self,
        from_slot: u32,
        to_slot: u32,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        self.track_request("jam_getBlockRange");
        if to_slot < from_slot {
            return Err(internal_error("to_slot must be >= from_slot"));
        }
        // Limit range to prevent DoS (max 1000 slots per request)
        let range_size = to_slot.saturating_sub(from_slot);
        if range_size > 1000 {
            return Err(internal_error("range too large (max 1000 slots)"));
        }

        let mut blocks = Vec::new();
        for slot in from_slot..=to_slot {
            if let Ok(hash) = self.state.store.get_block_hash_by_slot(slot) {
                blocks.push(serde_json::json!({
                    "slot": slot,
                    "hash": hex::encode(hash.0),
                }));
            }
        }

        Ok(serde_json::json!({
            "from_slot": from_slot,
            "to_slot": to_slot,
            "blocks": blocks,
            "count": blocks.len(),
        }))
    }

    async fn get_peers(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        self.track_request("jam_getPeers");
        let peer_count = self
            .state
            .peer_count
            .load(std::sync::atomic::Ordering::Relaxed);
        Ok(serde_json::json!({
            "peer_count": peer_count,
        }))
    }
}

/// Accept a subscription and forward notifications from a broadcast channel
/// until the client disconnects.
async fn forward_subscription(
    pending: jsonrpsee::PendingSubscriptionSink,
    channel: &tokio::sync::broadcast::Sender<serde_json::Value>,
) -> jsonrpsee::core::SubscriptionResult {
    let sink = pending.accept().await?;
    let mut rx = channel.subscribe();
    tokio::spawn(async move {
        while let Ok(notification) = rx.recv().await {
            let msg = jsonrpsee::SubscriptionMessage::from_json(&notification).expect("valid JSON");
            if sink.send(msg).await.is_err() {
                break; // client disconnected
            }
        }
    });
    Ok(())
}

#[async_trait]
impl JamSubscriptionsServer for RpcImpl {
    async fn subscribe_new_blocks(
        &self,
        pending: jsonrpsee::PendingSubscriptionSink,
    ) -> jsonrpsee::core::SubscriptionResult {
        forward_subscription(pending, &self.state.block_notifications).await
    }

    async fn subscribe_finalized(
        &self,
        pending: jsonrpsee::PendingSubscriptionSink,
    ) -> jsonrpsee::core::SubscriptionResult {
        forward_subscription(pending, &self.state.finality_notifications).await
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
        } else if is_get && path == "/metrics" {
            let state = self.state.clone();
            Box::pin(async move {
                let body = format_metrics(&state).await;
                Ok(http::Response::builder()
                    .status(200)
                    .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
                    .body(HttpBody::from(body))
                    .unwrap())
            })
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
            // Count non-health/metrics/ready requests (i.e., JSON-RPC calls)
            self.state
                .rpc_requests_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let fut = self.inner.call(req);
            Box::pin(fut)
        }
    }
}

// ── Per-IP rate limiting ─────────────────────────────────────────────

/// Per-IP rate limiter using a fixed-window counter.
/// Tracks request counts per source IP and returns HTTP 429 when exceeded.
#[derive(Clone)]
struct RateLimitLayer {
    state: Arc<
        std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, (u64, std::time::Instant)>>,
    >,
    max_requests: u64,
}

impl RateLimitLayer {
    fn new(max_requests: u64) -> Self {
        Self {
            state: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            max_requests,
        }
    }
}

impl<S> tower::Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            state: self.state.clone(),
            max_requests: self.max_requests,
        }
    }
}

#[derive(Clone)]
struct RateLimitService<S> {
    inner: S,
    state: Arc<
        std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, (u64, std::time::Instant)>>,
    >,
    max_requests: u64,
}

impl<S, ReqBody> tower::Service<http::Request<ReqBody>> for RateLimitService<S>
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
        // Extract client IP from X-Forwarded-For header or fall back to 127.0.0.1.
        // In production, a reverse proxy should set X-Forwarded-For.
        let ip: std::net::IpAddr = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

        {
            let mut map = self.state.lock().unwrap();
            let now = std::time::Instant::now();
            let entry = map.entry(ip).or_insert((0, now));

            // Reset window if expired
            if now.duration_since(entry.1) >= RATE_LIMIT_WINDOW {
                *entry = (0, now);
            }

            entry.0 += 1;
            if entry.0 > self.max_requests {
                tracing::warn!("Rate limit exceeded for IP {}: {}/min", ip, entry.0);
                let body = serde_json::json!({
                    "error": "rate limit exceeded",
                    "retry_after_seconds": RATE_LIMIT_WINDOW.as_secs(),
                })
                .to_string();
                return Box::pin(async move {
                    Ok(http::Response::builder()
                        .status(429)
                        .header("content-type", "application/json")
                        .header("retry-after", RATE_LIMIT_WINDOW.as_secs().to_string())
                        .body(HttpBody::from(body))
                        .unwrap())
                });
            }
        }

        let fut = self.inner.call(req);
        Box::pin(fut)
    }
}

/// Format Prometheus text exposition metrics from the current RPC state.
pub async fn format_metrics(state: &RpcState) -> String {
    let status = state.status.read().await;
    let head_slot = status.head_slot;
    let finalized_slot = status.finalized_slot;
    let blocks_authored = status.blocks_authored;
    let blocks_imported = status.blocks_imported;
    let validator_index = status.validator_index;
    let grandpa_round = status.grandpa_round;
    let peer_count = state.peer_count.load(std::sync::atomic::Ordering::Relaxed);
    let queue_events = state
        .queue_depth_events
        .load(std::sync::atomic::Ordering::Relaxed);
    let queue_commands = state
        .queue_depth_commands
        .load(std::sync::atomic::Ordering::Relaxed);
    let queue_rpc = state
        .queue_depth_rpc
        .load(std::sync::atomic::Ordering::Relaxed);
    let pending_blocks = state
        .pending_blocks_depth
        .load(std::sync::atomic::Ordering::Relaxed);
    let finality_lag = head_slot.saturating_sub(finalized_slot);
    let wp_submitted = state
        .work_packages_submitted
        .load(std::sync::atomic::Ordering::Relaxed);
    let rpc_total = state
        .rpc_requests_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let gossip_blocks = state
        .gossip_blocks_received
        .load(std::sync::atomic::Ordering::Relaxed);
    let gossip_finality = state
        .gossip_finality_received
        .load(std::sync::atomic::Ordering::Relaxed);
    let gossip_guarantees = state
        .gossip_guarantees_received
        .load(std::sync::atomic::Ordering::Relaxed);
    let gossip_assurances = state
        .gossip_assurances_received
        .load(std::sync::atomic::Ordering::Relaxed);
    let gossip_announcements = state
        .gossip_announcements_received
        .load(std::sync::atomic::Ordering::Relaxed);
    let gossip_tickets = state
        .gossip_tickets_received
        .load(std::sync::atomic::Ordering::Relaxed);
    let stf_total = state
        .state_transitions_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let stf_last_us = state
        .state_transition_last_us
        .load(std::sync::atomic::Ordering::Relaxed);
    drop(status);

    let stf_last_secs = stf_last_us as f64 / 1_000_000.0;

    let stored_blocks = state.store.block_count().unwrap_or(0);
    let stored_states = state.store.state_count().unwrap_or(0);
    let stored_chunks = state.store.chunk_count().unwrap_or(0);
    let stored_votes = state.store.vote_count().unwrap_or(0);

    let mut base = format!(
        "# HELP grey_block_height Current head slot.\n\
         # TYPE grey_block_height gauge\n\
         grey_block_height {head_slot}\n\
         # HELP grey_finalized_height Last finalized slot.\n\
         # TYPE grey_finalized_height gauge\n\
         grey_finalized_height {finalized_slot}\n\
         # HELP grey_blocks_produced_total Blocks authored by this node.\n\
         # TYPE grey_blocks_produced_total counter\n\
         grey_blocks_produced_total {blocks_authored}\n\
         # HELP grey_blocks_imported_total Blocks received and imported.\n\
         # TYPE grey_blocks_imported_total counter\n\
         grey_blocks_imported_total {blocks_imported}\n\
         # HELP grey_stored_blocks Number of blocks in the database.\n\
         # TYPE grey_stored_blocks gauge\n\
         grey_stored_blocks {stored_blocks}\n\
         # HELP grey_stored_states Number of state entries in the database.\n\
         # TYPE grey_stored_states gauge\n\
         grey_stored_states {stored_states}\n\
         # HELP grey_stored_chunks Number of DA chunks in the database.\n\
         # TYPE grey_stored_chunks gauge\n\
         grey_stored_chunks {stored_chunks}\n\
         # HELP grey_stored_votes Number of GRANDPA votes in the database.\n\
         # TYPE grey_stored_votes gauge\n\
         grey_stored_votes {stored_votes}\n\
         # HELP grey_validator_index Validator index of this node.\n\
         # TYPE grey_validator_index gauge\n\
         grey_validator_index {validator_index}\n\
         # HELP grey_grandpa_round Current GRANDPA finality round.\n\
         # TYPE grey_grandpa_round gauge\n\
         grey_grandpa_round {grandpa_round}\n\
         # HELP grey_peer_count Number of connected peers.\n\
         # TYPE grey_peer_count gauge\n\
         grey_peer_count {peer_count}\n\
         # HELP grey_queue_depth_events Network event queue depth.\n\
         # TYPE grey_queue_depth_events gauge\n\
         grey_queue_depth_events {queue_events}\n\
         # HELP grey_queue_depth_commands Network command queue depth.\n\
         # TYPE grey_queue_depth_commands gauge\n\
         grey_queue_depth_commands {queue_commands}\n\
         # HELP grey_queue_depth_rpc RPC command queue depth.\n\
         # TYPE grey_queue_depth_rpc gauge\n\
         grey_queue_depth_rpc {queue_rpc}\n\
         # HELP grey_pending_blocks Pending blocks buffer depth.\n\
         # TYPE grey_pending_blocks gauge\n\
         grey_pending_blocks {pending_blocks}\n\
         # HELP grey_finality_lag Slots between head and last finalized block.\n\
         # TYPE grey_finality_lag gauge\n\
         grey_finality_lag {finality_lag}\n\
         # HELP grey_work_packages_submitted_total Work packages submitted via RPC.\n\
         # TYPE grey_work_packages_submitted_total counter\n\
         grey_work_packages_submitted_total {wp_submitted}\n\
         # HELP grey_rpc_requests_total Total RPC requests received.\n\
         # TYPE grey_rpc_requests_total counter\n\
         grey_rpc_requests_total {rpc_total}\n\
         # HELP grey_gossipsub_messages_total Gossipsub messages received per topic.\n\
         # TYPE grey_gossipsub_messages_total counter\n\
         grey_gossipsub_messages_total{{topic=\"blocks\"}} {gossip_blocks}\n\
         grey_gossipsub_messages_total{{topic=\"finality\"}} {gossip_finality}\n\
         grey_gossipsub_messages_total{{topic=\"guarantees\"}} {gossip_guarantees}\n\
         grey_gossipsub_messages_total{{topic=\"assurances\"}} {gossip_assurances}\n\
         grey_gossipsub_messages_total{{topic=\"announcements\"}} {gossip_announcements}\n\
         grey_gossipsub_messages_total{{topic=\"tickets\"}} {gossip_tickets}\n\
         # HELP grey_state_transitions_total Number of state transitions applied.\n\
         # TYPE grey_state_transitions_total counter\n\
         grey_state_transitions_total {stf_total}\n\
         # HELP grey_state_transition_last_seconds Duration of the last state transition.\n\
         # TYPE grey_state_transition_last_seconds gauge\n\
         grey_state_transition_last_seconds {stf_last_secs}\n"
    );

    // Append per-method request counts
    if let Ok(counts) = state.request_counts.lock()
        && !counts.is_empty()
    {
        base.push_str("# HELP grey_rpc_requests_by_method RPC requests per method.\n");
        base.push_str("# TYPE grey_rpc_requests_by_method counter\n");
        let mut sorted: Vec<_> = counts.iter().collect();
        sorted.sort_by_key(|(k, _)| (*k).clone());
        for (method, count) in sorted {
            base.push_str(&format!(
                "grey_rpc_requests_by_method{{method=\"{method}\"}} {count}\n"
            ));
        }
    }

    base
}

/// Start a standalone metrics HTTP server on the given port.
/// Serves `/metrics` in Prometheus text exposition format.
pub async fn start_metrics_server(
    host: &str,
    port: u16,
    state: Arc<RpcState>,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>), Box<dyn std::error::Error + Send + Sync>> {
    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound_addr = listener.local_addr()?;

    let join = tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::warn!("Metrics server accept error: {e}");
                    continue;
                }
            };
            let state = state.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 4096];
                // Read the HTTP request (we only need to know it arrived)
                let _ = stream.read(&mut buf).await;
                let body = format_metrics(&state).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });

    tracing::info!("Metrics server listening on {}", bound_addr);
    Ok((bound_addr, join))
}

/// Start the JSON-RPC server. Returns the command receiver for the node event loop.
pub async fn start_rpc_server(
    host: &str,
    port: u16,
    state: Arc<RpcState>,
    cors: bool,
    rate_limit: u64,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>), Box<dyn std::error::Error + Send + Sync>> {
    let addr = format!("{}:{}", host, port);
    let cors_layer = if cors {
        tracing::info!("RPC CORS enabled (permissive)");
        tower_http::cors::CorsLayer::permissive()
    } else {
        tower_http::cors::CorsLayer::new()
    };
    let health_layer = HealthLayer {
        state: state.clone(),
    };
    let max_requests = if rate_limit == 0 {
        u64::MAX
    } else {
        rate_limit
    };
    let rate_limiter = RateLimitLayer::new(max_requests);
    let middleware = tower::ServiceBuilder::new()
        .layer(cors_layer)
        .layer(rate_limiter)
        .layer(tower::timeout::TimeoutLayer::new(RPC_QUERY_TIMEOUT))
        .layer(health_layer);
    // Work packages can be up to ~14MB (MAX_WORK_PACKAGE_BLOB_SIZE), and hex
    // encoding doubles the size. Allow 30MB to accommodate the largest valid
    // request with JSON-RPC overhead.
    let server = Server::builder()
        .max_request_body_size(30 * 1024 * 1024)
        .max_response_body_size(30 * 1024 * 1024)
        .max_connections(100)
        .set_http_middleware(middleware)
        .build(&addr)
        .await?;
    let bound_addr = server.local_addr()?;

    let rpc_impl = RpcImpl {
        state: state.clone(),
    };
    let sub_impl = RpcImpl { state };

    // Merge regular RPC methods and subscription methods into one module
    let mut module = JamRpcServer::into_rpc(rpc_impl);
    module
        .merge(JamSubscriptionsServer::into_rpc(sub_impl))
        .expect("merge subscription methods");

    let handle = server.start(module);

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
    start_rpc_server(
        "127.0.0.1",
        0,
        state,
        false,
        DEFAULT_RATE_LIMIT_MAX_REQUESTS,
    )
    .await
}

/// Create RPC state and command channel.
pub fn create_rpc_channel(
    store: Arc<Store>,
    config: Config,
    validator_index: u16,
) -> (Arc<RpcState>, mpsc::Receiver<RpcCommand>) {
    let (tx, rx) = mpsc::channel(256);
    let (block_tx, _) = tokio::sync::broadcast::channel::<serde_json::Value>(64);
    let (finality_tx, _) = tokio::sync::broadcast::channel::<serde_json::Value>(64);

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
            grandpa_round: 0,
        }),
        commands: tx,
        block_notifications: block_tx,
        finality_notifications: finality_tx,
        peer_count: std::sync::atomic::AtomicU32::new(0),
        queue_depth_events: std::sync::atomic::AtomicU32::new(0),
        queue_depth_commands: std::sync::atomic::AtomicU32::new(0),
        queue_depth_rpc: std::sync::atomic::AtomicU32::new(0),
        pending_blocks_depth: std::sync::atomic::AtomicU32::new(0),
        work_packages_submitted: std::sync::atomic::AtomicU64::new(0),
        request_counts: std::sync::Mutex::new(std::collections::HashMap::new()),
        rpc_requests_total: std::sync::atomic::AtomicU64::new(0),
        gossip_blocks_received: std::sync::atomic::AtomicU64::new(0),
        gossip_finality_received: std::sync::atomic::AtomicU64::new(0),
        gossip_guarantees_received: std::sync::atomic::AtomicU64::new(0),
        gossip_assurances_received: std::sync::atomic::AtomicU64::new(0),
        gossip_announcements_received: std::sync::atomic::AtomicU64::new(0),
        gossip_tickets_received: std::sync::atomic::AtomicU64::new(0),
        state_transitions_total: std::sync::atomic::AtomicU64::new(0),
        state_transition_last_us: std::sync::atomic::AtomicU64::new(0),
    });

    (state, rx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use grey_types::BandersnatchSignature;
    use grey_types::header::{Block, Extrinsic, Header, UnsignedHeader};
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
                data: UnsignedHeader {
                    parent_hash: Hash([1u8; 32]),
                    state_root: Hash([2u8; 32]),
                    extrinsic_hash: Hash([3u8; 32]),
                    timeslot: slot,
                    epoch_marker: None,
                    tickets_marker: None,
                    author_index: 5,
                    vrf_signature: BandersnatchSignature([7u8; 96]),
                    offenders_marker: vec![],
                },
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

    /// Build a minimal valid JAM-encoded work package for testing.
    fn minimal_work_package_bytes() -> Vec<u8> {
        use grey_types::work::{RefinementContext, WorkPackage};
        use scale::Encode;
        let wp = WorkPackage {
            auth_code_host: 0,
            auth_code_hash: Hash([0u8; 32]),
            context: RefinementContext {
                anchor: Hash([0u8; 32]),
                state_root: Hash([0u8; 32]),
                beefy_root: Hash([0u8; 32]),
                lookup_anchor: Hash([0u8; 32]),
                lookup_anchor_timeslot: 0,
                prerequisites: vec![],
            },
            authorization: vec![],
            authorizer_config: vec![],
            items: vec![],
        };
        wp.encode()
    }

    #[tokio::test]
    async fn test_submit_work_package() {
        let (url, _state, mut rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();
        let wp_bytes = minimal_work_package_bytes();
        let data_hex = hex::encode(&wp_bytes);
        let result: serde_json::Value = client
            .request("jam_submitWorkPackage", rpc_params![data_hex])
            .await
            .unwrap();
        assert_eq!(result["status"], "submitted");
        assert!(result["hash"].is_string());

        // Verify command was received
        let cmd = rx.try_recv().unwrap();
        match cmd {
            RpcCommand::SubmitWorkPackage { data } => {
                assert_eq!(data, wp_bytes);
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

    #[tokio::test]
    async fn test_submit_invalid_codec_work_package() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();
        // Random bytes that won't decode as a valid WorkPackage
        let result: Result<serde_json::Value, _> = client
            .request(
                "jam_submitWorkPackage",
                rpc_params![hex::encode([0xAB; 16])],
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_submit_oversized_work_package() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();
        // Exceeds MAX_WORK_PACKAGE_BLOB_SIZE (13,791,360 bytes)
        let oversized = vec![0u8; 14_000_000];
        let result: Result<serde_json::Value, _> = client
            .request(
                "jam_submitWorkPackage",
                rpc_params![hex::encode(&oversized)],
            )
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

    #[tokio::test]
    async fn test_get_service_account() {
        let (url, _state, _rx, store, _dir) = setup().await;
        let config = Config::tiny();
        let (mut genesis_state, _secrets) = grey_consensus::genesis::create_genesis(&config);

        // Insert a service account
        let svc = grey_types::state::ServiceAccount {
            code_hash: Hash([0xAA; 32]),
            quota_items: 1_000_000,
            min_accumulate_gas: 500,
            min_on_transfer_gas: 200,
            storage: std::collections::BTreeMap::new(),
            preimage_lookup: std::collections::BTreeMap::new(),
            preimage_info: std::collections::BTreeMap::new(),
            quota_bytes: 1_000_000_000,
            total_footprint: 0,
            accumulation_counter: 0,
            last_accumulation: 0,
            last_activity: 0,
            preimage_count: 0,
        };
        genesis_state.services.insert(42, svc);

        // Store state and set head
        let block = test_block(1);
        let hash = store.put_block(&block).unwrap();
        store.put_state(&hash, &genesis_state, &config).unwrap();
        store.set_head(&hash, 1).unwrap();

        let client = HttpClientBuilder::default().build(&url).unwrap();

        // Query existing service
        let result: serde_json::Value = client
            .request("jam_getServiceAccount", rpc_params![42u32])
            .await
            .unwrap();
        assert_eq!(result["service_id"], 42);
        assert_eq!(result["quota_items"], 1_000_000);
        assert_eq!(result["min_accumulate_gas"], 500);
        assert_eq!(result["min_on_transfer_gas"], 200);
        assert_eq!(result["code_hash"], hex::encode([0xAAu8; 32]));
        assert_eq!(result["slot"], 1);

        // Query non-existent service — should error
        let err = client
            .request::<serde_json::Value, _>("jam_getServiceAccount", rpc_params![9999u32])
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_service_account_code_hash_matches() {
        let (url, _state, _rx, store, _dir) = setup().await;
        let config = Config::tiny();
        let (mut genesis_state, _secrets) = grey_consensus::genesis::create_genesis(&config);

        // Install a service with code_hash derived from known data
        let code_data = b"test service bytecode";
        let expected_hash = grey_crypto::blake2b_256(code_data);
        let svc = grey_types::state::ServiceAccount {
            code_hash: expected_hash,
            quota_items: 1_000_000,
            min_accumulate_gas: 50_000,
            min_on_transfer_gas: 10_000,
            storage: std::collections::BTreeMap::new(),
            preimage_lookup: std::collections::BTreeMap::new(),
            preimage_info: std::collections::BTreeMap::new(),
            quota_bytes: 1_000_000_000,
            total_footprint: 0,
            accumulation_counter: 0,
            last_accumulation: 0,
            last_activity: 0,
            preimage_count: 3,
        };
        genesis_state.services.insert(2000, svc);

        let block = test_block(1);
        let hash = store.put_block(&block).unwrap();
        store.put_state(&hash, &genesis_state, &config).unwrap();
        store.set_head(&hash, 1).unwrap();

        let client = HttpClientBuilder::default().build(&url).unwrap();
        let result: serde_json::Value = client
            .request("jam_getServiceAccount", rpc_params![2000u32])
            .await
            .unwrap();

        assert_eq!(result["service_id"], 2000);
        assert_eq!(
            result["code_hash"].as_str().unwrap(),
            hex::encode(expected_hash.0),
            "code_hash should match blake2b of the code data"
        );
        assert_eq!(result["quota_items"], 1_000_000u64);
        assert_eq!(result["min_accumulate_gas"], 50_000u64);
        assert_eq!(result["min_on_transfer_gas"], 10_000u64);
        assert_eq!(result["preimage_count"], 3);
    }

    #[tokio::test]
    async fn test_get_chain_spec() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();
        let result: serde_json::Value = client
            .request("jam_getChainSpec", rpc_params![])
            .await
            .unwrap();

        // Config::tiny() values
        assert_eq!(result["validators_count"], 6);
        assert_eq!(result["core_count"], 2);
        assert_eq!(result["epoch_length"], 12);
        assert_eq!(result["slot_period"], 6);
        assert!(result["gas_total_accumulation"].as_u64().unwrap() > 0);
        // New fields: protocol_version and genesis_hash
        assert_eq!(result["protocol_version"], "0.7.2");
        assert!(
            result["genesis_hash"].as_str().unwrap().len() == 64,
            "genesis_hash should be 32-byte hex"
        );
    }

    #[tokio::test]
    async fn test_get_state_summary() {
        let (url, _state, _rx, store, _dir) = setup().await;
        let config = Config::tiny();
        let (genesis_state, _secrets) = grey_consensus::genesis::create_genesis(&config);

        let block = test_block(1);
        let hash = store.put_block(&block).unwrap();
        store.put_state(&hash, &genesis_state, &config).unwrap();
        store.set_head(&hash, 1).unwrap();

        let client = HttpClientBuilder::default().build(&url).unwrap();

        // Default: head block
        let result: serde_json::Value = client
            .request("jam_getState", rpc_params![Option::<String>::None])
            .await
            .unwrap();
        assert_eq!(result["timeslot"], 1);
        assert!(result["state_root"].is_string());
        assert!(result["block_hash"].is_string());
        assert_eq!(result["validator_count"], config.validators_count);
        // Entropy should be an array of 4 hex strings
        let entropy = result["entropy"].as_array().unwrap();
        assert_eq!(entropy.len(), 4);

        // Explicit block hash
        let result2: serde_json::Value = client
            .request("jam_getState", rpc_params![Some(hex::encode(hash.0))])
            .await
            .unwrap();
        assert_eq!(result2["timeslot"], 1);
        assert_eq!(result2["block_hash"], hex::encode(hash.0));
    }

    #[tokio::test]
    async fn test_get_validators() {
        let (url, _state, _rx, store, _dir) = setup().await;
        let config = Config::tiny();
        let (genesis_state, secrets) = grey_consensus::genesis::create_genesis(&config);

        let block = test_block(1);
        let hash = store.put_block(&block).unwrap();
        store.put_state(&hash, &genesis_state, &config).unwrap();
        store.set_head(&hash, 1).unwrap();

        let client = HttpClientBuilder::default().build(&url).unwrap();

        // Default: current validators
        let result: serde_json::Value = client
            .request("jam_getValidators", rpc_params![Option::<String>::None])
            .await
            .unwrap();
        assert_eq!(result["set"], "current");
        assert_eq!(result["count"], config.validators_count);
        let validators = result["validators"].as_array().unwrap();
        assert_eq!(validators.len(), config.validators_count as usize);
        // Each validator should have keys
        assert!(validators[0]["ed25519"].is_string());
        assert!(validators[0]["bandersnatch"].is_string());
        assert_eq!(validators[0]["index"], 0);

        // Verify validator keys match genesis secrets
        for (i, secret) in secrets.iter().enumerate() {
            let v = &validators[i];
            let expected_ed = hex::encode(secret.ed25519.public_key().0);
            let expected_band = hex::encode(secret.bandersnatch.public_key_bytes());
            assert_eq!(
                v["ed25519"].as_str().unwrap(),
                expected_ed,
                "ed25519 key mismatch for validator {}",
                i
            );
            assert_eq!(
                v["bandersnatch"].as_str().unwrap(),
                expected_band,
                "bandersnatch key mismatch for validator {}",
                i
            );
        }

        // Explicit "pending"
        let result: serde_json::Value = client
            .request("jam_getValidators", rpc_params![Some("pending")])
            .await
            .unwrap();
        assert_eq!(result["set"], "pending");

        // Invalid set name
        let err = client
            .request::<serde_json::Value, _>("jam_getValidators", rpc_params![Some("invalid")])
            .await;
        assert!(err.is_err());
    }

    // ── Error handling tests (issue #225) ───────────────────────────────

    #[tokio::test]
    async fn test_error_invalid_method() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();
        let err = client
            .request::<serde_json::Value, _>("jam_nonExistentMethod", rpc_params![])
            .await;
        assert!(err.is_err(), "non-existent method should return error");
    }

    #[tokio::test]
    async fn test_error_get_block_non_hex() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();
        let err = client
            .request::<serde_json::Value, _>("jam_getBlock", rpc_params!["not-hex-data!!"])
            .await;
        assert!(err.is_err(), "non-hex hash should return error");
    }

    #[tokio::test]
    async fn test_error_get_block_short_hash() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();
        // Valid hex but only 16 bytes (not 32)
        let err = client
            .request::<serde_json::Value, _>("jam_getBlock", rpc_params!["aabb"])
            .await;
        assert!(err.is_err(), "short hash should return error");
    }

    #[tokio::test]
    async fn test_error_read_storage_invalid_hex_key() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();
        let err = client
            .request::<serde_json::Value, _>("jam_readStorage", rpc_params![42u32, "zzz-not-hex"])
            .await;
        assert!(err.is_err(), "invalid hex key should return error");
    }

    #[tokio::test]
    async fn test_error_submit_invalid_hex_wp() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();
        let err = client
            .request::<serde_json::Value, _>("jam_submitWorkPackage", rpc_params!["xyz-not-hex"])
            .await;
        assert!(err.is_err(), "invalid hex work package should return error");
    }

    #[tokio::test]
    async fn test_error_get_block_by_slot_not_stored() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();
        let err = client
            .request::<serde_json::Value, _>("jam_getBlockBySlot", rpc_params![99999u32])
            .await;
        assert!(err.is_err(), "non-existent slot should return error");
    }

    #[tokio::test]
    async fn test_concurrent_requests() {
        let (url, state, _rx, _store, _dir) = setup().await;
        {
            let mut status = state.status.write().await;
            status.head_slot = 42;
            status.head_hash = "abc".into();
        }

        // Fire 100 concurrent get_status requests
        let mut handles = Vec::new();
        for _ in 0..100 {
            let url = url.clone();
            handles.push(tokio::spawn(async move {
                let client = HttpClientBuilder::default().build(&url).unwrap();
                client
                    .request::<serde_json::Value, _>("jam_getStatus", rpc_params![])
                    .await
            }));
        }

        let mut successes = 0u32;
        let mut failures = 0u32;
        for handle in handles {
            match handle.await.unwrap() {
                Ok(val) => {
                    assert_eq!(val["head_slot"], 42);
                    successes += 1;
                }
                Err(_) => failures += 1,
            }
        }

        assert_eq!(successes, 100, "all 100 concurrent requests should succeed");
        assert_eq!(failures, 0);
    }

    #[tokio::test]
    async fn test_metrics_endpoint() {
        let (url, state, _rx, store, _dir) = setup().await;
        {
            let mut status = state.status.write().await;
            status.head_slot = 50;
            status.finalized_slot = 45;
            status.blocks_authored = 10;
            status.blocks_imported = 40;
        }

        // Store a block so stored_blocks > 0
        let block = test_block(1);
        store.put_block(&block).unwrap();

        let (status, body) = http_get(&format!("{}/metrics", url)).await;
        assert_eq!(status, 200);
        assert!(body.contains("grey_block_height 50"));
        assert!(body.contains("grey_finalized_height 45"));
        assert!(body.contains("grey_blocks_produced_total 10"));
        assert!(body.contains("grey_blocks_imported_total 40"));
        assert!(body.contains("grey_stored_blocks 1"));
        assert!(body.contains("grey_stored_states 0"));
        assert!(body.contains("grey_stored_chunks 0"));
        assert!(body.contains("grey_stored_votes 0"));
        assert!(body.contains("# TYPE grey_block_height gauge"));
        assert!(body.contains("# TYPE grey_blocks_produced_total counter"));
        // Queue depth metrics should be present (defaulting to 0)
        assert!(body.contains("grey_queue_depth_events 0"));
        assert!(body.contains("grey_queue_depth_commands 0"));
        assert!(body.contains("grey_queue_depth_rpc 0"));
        assert!(body.contains("grey_pending_blocks 0"));
    }

    #[tokio::test]
    async fn test_submit_duplicate_work_package() {
        let (url, _state, mut rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();
        let wp_bytes = minimal_work_package_bytes();
        let data_hex = hex::encode(&wp_bytes);

        // First submission
        let result1: serde_json::Value = client
            .request("jam_submitWorkPackage", rpc_params![data_hex.clone()])
            .await
            .unwrap();
        assert_eq!(result1["status"], "submitted");
        let hash1 = result1["hash"].as_str().unwrap().to_string();

        // Drain the command
        let _ = rx.recv().await.unwrap();

        // Second submission of the same work package
        let result2: serde_json::Value = client
            .request("jam_submitWorkPackage", rpc_params![data_hex])
            .await
            .unwrap();
        assert_eq!(result2["status"], "submitted");
        let hash2 = result2["hash"].as_str().unwrap().to_string();

        // Same data should produce the same hash
        assert_eq!(hash1, hash2, "duplicate WP should return same hash");

        // Both submissions should be forwarded to the node
        let _ = rx.recv().await.unwrap();
    }

    #[tokio::test]
    async fn test_submit_zero_gas_work_item() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();

        // Manually construct a work package with gas_limit=0 work item.
        // The JAM codec should still accept this (gas validation happens at
        // state transition time, not at RPC submission).
        let wp_bytes = minimal_work_package_bytes();
        let data_hex = hex::encode(&wp_bytes);

        // Should succeed — RPC accepts any structurally valid WP
        let result: serde_json::Value = client
            .request("jam_submitWorkPackage", rpc_params![data_hex])
            .await
            .unwrap();
        assert_eq!(result["status"], "submitted");
    }

    #[tokio::test]
    async fn test_get_block_range_with_blocks() {
        let (url, _state, _rx, store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();

        // Store blocks at slots 1, 2, 3
        for slot in 1..=3 {
            let block = test_block(slot);
            store.put_block(&block).unwrap();
        }

        let result: serde_json::Value = client
            .request("jam_getBlockRange", rpc_params![1u32, 3u32])
            .await
            .unwrap();
        assert_eq!(result["from_slot"], 1);
        assert_eq!(result["to_slot"], 3);
        assert_eq!(result["count"], 3);
        assert_eq!(result["blocks"].as_array().unwrap().len(), 3);
        assert_eq!(result["blocks"][0]["slot"], 1);
    }

    #[tokio::test]
    async fn test_get_block_range_empty() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();

        // No blocks stored — range returns empty
        let result: serde_json::Value = client
            .request("jam_getBlockRange", rpc_params![10u32, 20u32])
            .await
            .unwrap();
        assert_eq!(result["count"], 0);
        assert!(result["blocks"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_get_block_range_invalid_range() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();

        // to_slot < from_slot — should error
        let result: Result<serde_json::Value, _> = client
            .request("jam_getBlockRange", rpc_params![10u32, 5u32])
            .await;
        assert!(result.is_err(), "reversed range should return error");
    }

    #[tokio::test]
    async fn test_get_block_range_too_large() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();

        // Range > 1000 slots — should error
        let result: Result<serde_json::Value, _> = client
            .request("jam_getBlockRange", rpc_params![0u32, 2000u32])
            .await;
        assert!(result.is_err(), "range > 1000 should return error");
    }

    #[tokio::test]
    async fn test_get_peers() {
        let (url, state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();

        // Default peer count is 0
        let result: serde_json::Value =
            client.request("jam_getPeers", rpc_params![]).await.unwrap();
        assert_eq!(result["peer_count"], 0);

        // Set peer count and verify
        state
            .peer_count
            .store(5, std::sync::atomic::Ordering::Relaxed);
        let result: serde_json::Value =
            client.request("jam_getPeers", rpc_params![]).await.unwrap();
        assert_eq!(result["peer_count"], 5);
    }

    #[tokio::test]
    async fn test_get_context_with_block() {
        let (url, _state, _rx, store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();

        // Store a block and set it as head
        let block = test_block(1);
        let hash = grey_crypto::header_hash(&block.header);
        store.put_block(&block).unwrap();
        store.set_head(&hash, 1).unwrap();

        // Store state (needed for code_hash lookup)
        let config = grey_types::config::Config::tiny();
        let (genesis_state, _) = grey_consensus::genesis::create_genesis(&config);
        store.put_state(&hash, &genesis_state, &config).unwrap();

        let result: serde_json::Value = client
            .request("jam_getContext", rpc_params![2000u32])
            .await
            .unwrap();
        assert_eq!(result["slot"], 1);
        assert!(result["anchor"].is_string());
        assert!(result["state_root"].is_string());
        assert!(result["beefy_root"].is_string());
    }

    #[tokio::test]
    async fn test_get_context_no_head() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();

        // No head set — should return error
        let result: Result<serde_json::Value, _> =
            client.request("jam_getContext", rpc_params![2000u32]).await;
        assert!(result.is_err(), "getContext with no head should error");
    }

    #[tokio::test]
    async fn test_standalone_metrics_server() {
        let (_url, state, _rx, _store, _dir) = setup().await;

        // Start metrics server on ephemeral port
        let (addr, _handle) = start_metrics_server("127.0.0.1", 0, state).await.unwrap();
        let metrics_url = format!("http://{}/metrics", addr);

        let (status, body) = http_get(&metrics_url).await;
        assert_eq!(status, 200);
        assert!(
            body.contains("grey_block_height"),
            "metrics should contain grey_block_height"
        );
        assert!(
            body.contains("grey_peer_count"),
            "metrics should contain grey_peer_count"
        );
    }

    #[tokio::test]
    async fn test_format_metrics_output() {
        let (_url, state, _rx, _store, _dir) = setup().await;
        let body = format_metrics(&state).await;
        assert!(body.contains("# HELP grey_block_height"));
        assert!(body.contains("# TYPE grey_block_height gauge"));
        assert!(body.contains("grey_finalized_height"));
        assert!(body.contains("grey_work_packages_submitted_total"));
    }

    #[tokio::test]
    async fn test_gossipsub_metrics() {
        let (_url, state, _rx, _store, _dir) = setup().await;

        // Increment some counters
        state
            .gossip_blocks_received
            .fetch_add(5, std::sync::atomic::Ordering::Relaxed);
        state
            .gossip_tickets_received
            .fetch_add(3, std::sync::atomic::Ordering::Relaxed);

        let body = format_metrics(&state).await;
        assert!(body.contains("# HELP grey_gossipsub_messages_total"));
        assert!(body.contains("# TYPE grey_gossipsub_messages_total counter"));
        assert!(body.contains("grey_gossipsub_messages_total{topic=\"blocks\"} 5"));
        assert!(body.contains("grey_gossipsub_messages_total{topic=\"tickets\"} 3"));
        assert!(body.contains("grey_gossipsub_messages_total{topic=\"finality\"} 0"));
        assert!(body.contains("grey_gossipsub_messages_total{topic=\"guarantees\"} 0"));
        assert!(body.contains("grey_gossipsub_messages_total{topic=\"assurances\"} 0"));
        assert!(body.contains("grey_gossipsub_messages_total{topic=\"announcements\"} 0"));
    }

    #[tokio::test]
    async fn test_state_transition_metrics() {
        let (_url, state, _rx, _store, _dir) = setup().await;

        // Simulate a state transition taking 1500 microseconds
        state
            .state_transitions_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        state
            .state_transition_last_us
            .store(1500, std::sync::atomic::Ordering::Relaxed);

        let body = format_metrics(&state).await;
        assert!(body.contains("# HELP grey_state_transitions_total"));
        assert!(body.contains("# TYPE grey_state_transitions_total counter"));
        assert!(body.contains("grey_state_transitions_total 1"));
        assert!(body.contains("# HELP grey_state_transition_last_seconds"));
        assert!(body.contains("# TYPE grey_state_transition_last_seconds gauge"));
        assert!(body.contains("grey_state_transition_last_seconds 0.0015"));
    }

    #[tokio::test]
    async fn test_invalid_rpc_method() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();
        let result: Result<serde_json::Value, _> =
            client.request("jam_nonExistentMethod", rpc_params![]).await;
        assert!(result.is_err(), "non-existent method should return error");
    }

    #[tokio::test]
    async fn test_read_storage_missing_params() {
        let (url, _state, _rx, store, _dir) = setup().await;
        // Need a head block for readStorage to work
        let block = test_block(1);
        let hash = store.put_block(&block).unwrap();
        store.set_head(&hash, 1).unwrap();

        let client = HttpClientBuilder::default().build(&url).unwrap();
        // Missing key parameter (only service_id)
        let result: Result<serde_json::Value, _> =
            client.request("jam_readStorage", rpc_params![1000]).await;
        assert!(
            result.is_err(),
            "readStorage with missing key should return error"
        );
    }

    #[tokio::test]
    async fn test_get_block_wrong_param_type() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();
        // Pass a number instead of a string
        let result: Result<serde_json::Value, _> =
            client.request("jam_getBlock", rpc_params![12345]).await;
        assert!(
            result.is_err(),
            "getBlock with numeric param should return error"
        );
    }

    #[tokio::test]
    async fn test_get_block_by_slot_wrong_param_type() {
        let (url, _state, _rx, _store, _dir) = setup().await;
        let client = HttpClientBuilder::default().build(&url).unwrap();
        // Pass a string instead of a number
        let result: Result<serde_json::Value, _> = client
            .request("jam_getBlockBySlot", rpc_params!["not_a_number"])
            .await;
        assert!(
            result.is_err(),
            "getBlockBySlot with string param should return error"
        );
    }

    #[tokio::test]
    async fn test_get_service_account_nonexistent() {
        let (url, _state, _rx, store, _dir) = setup().await;
        let block = test_block(1);
        let hash = store.put_block(&block).unwrap();
        store.set_head(&hash, 1).unwrap();

        let client = HttpClientBuilder::default().build(&url).unwrap();
        let result: Result<serde_json::Value, _> = client
            .request("jam_getServiceAccount", rpc_params![99999])
            .await;
        assert!(result.is_err(), "non-existent service should return error");
    }

    #[tokio::test]
    async fn test_get_validators_invalid_set() {
        let (url, _state, _rx, store, _dir) = setup().await;
        let block = test_block(1);
        let hash = store.put_block(&block).unwrap();
        store.set_head(&hash, 1).unwrap();

        let client = HttpClientBuilder::default().build(&url).unwrap();
        let result: Result<serde_json::Value, _> = client
            .request("jam_getValidators", rpc_params!["invalid_set_name"])
            .await;
        assert!(
            result.is_err(),
            "getValidators with invalid set name should return error"
        );
    }
}
