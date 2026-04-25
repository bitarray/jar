//! JSON-RPC client for grey-rpc.

use serde::Deserialize;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("HTTP error calling {method}: {source}")]
    Http {
        method: String,
        source: reqwest::Error,
    },
    #[error("JSON-RPC error calling {method}: [{code}] {message}")]
    JsonRpc {
        method: String,
        code: i64,
        message: String,
    },
    #[error("missing 'result' in response to {method}")]
    MissingResult { method: String },
    #[error("failed to deserialize response for {method}: {detail}")]
    Deserialize { method: String, detail: String },
}

/// Default per-RPC-call timeout. Prevents individual calls from hanging
/// indefinitely when the node is overloaded or unresponsive.
const RPC_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct NodeStatus {
    pub head_slot: u32,
    pub head_hash: String,
    pub finalized_slot: u32,
    pub finalized_hash: String,
    pub blocks_authored: u64,
    pub blocks_imported: u64,
    pub validator_index: u16,
}

#[derive(Debug, Deserialize)]
pub struct ContextResult {
    pub slot: u32,
    pub anchor: String,
    pub state_root: String,
    pub beefy_root: String,
    pub code_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct StateSummaryResult {
    pub block_hash: String,
    pub state_root: String,
    pub timeslot: u32,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct StorageResult {
    pub service_id: u32,
    pub key: String,
    pub value: Option<String>,
    pub length: u32,
    pub slot: u32,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct SubmitResult {
    pub hash: String,
    pub status: String,
}

pub struct RpcClient {
    http: reqwest::Client,
    endpoint: String,
    next_id: AtomicU64,
}

impl RpcClient {
    pub fn new(endpoint: &str) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(RPC_CALL_TIMEOUT)
                .build()
                .expect("failed to build HTTP client"),
            endpoint: endpoint.to_string(),
            next_id: AtomicU64::new(1),
        }
    }

    /// Maximum number of retry attempts for transient HTTP failures.
    const MAX_RETRIES: u32 = 3;
    /// Base delay between retries (doubled each attempt).
    const RETRY_BASE_DELAY: std::time::Duration = std::time::Duration::from_millis(200);

    /// Call an RPC method with automatic retry on transient HTTP errors.
    /// JSON-RPC errors (method not found, invalid params) are not retried.
    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T, RpcError> {
        let mut last_err = None;
        for attempt in 0..=Self::MAX_RETRIES {
            match self.call_once::<T>(method, params.clone()).await {
                Ok(result) => return Ok(result),
                Err(RpcError::Http { .. }) if attempt < Self::MAX_RETRIES => {
                    let delay = Self::RETRY_BASE_DELAY * 2u32.pow(attempt);
                    tracing::warn!(
                        "RPC call {} failed (attempt {}/{}), retrying in {:?}",
                        method,
                        attempt + 1,
                        Self::MAX_RETRIES + 1,
                        delay
                    );
                    tokio::time::sleep(delay).await;
                    last_err = None; // Will be set on next failure
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or(RpcError::MissingResult {
            method: method.to_string(),
        }))
    }

    async fn call_once<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T, RpcError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let resp: serde_json::Value = self
            .http
            .post(&self.endpoint)
            .json(&body)
            .send()
            .await
            .map_err(|e| RpcError::Http {
                method: method.to_string(),
                source: e,
            })?
            .json()
            .await
            .map_err(|e| RpcError::Http {
                method: method.to_string(),
                source: e,
            })?;
        if let Some(err) = resp.get("error") {
            let message = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown")
                .to_string();
            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
            return Err(RpcError::JsonRpc {
                method: method.to_string(),
                code,
                message,
            });
        }
        let result = resp.get("result").ok_or_else(|| RpcError::MissingResult {
            method: method.to_string(),
        })?;
        serde_json::from_value(result.clone()).map_err(|e| RpcError::Deserialize {
            method: method.to_string(),
            detail: e.to_string(),
        })
    }

    pub async fn get_status(&self) -> Result<NodeStatus, RpcError> {
        self.call("jam_getStatus", serde_json::json!([])).await
    }

    pub async fn get_context(&self, service_id: u32) -> Result<ContextResult, RpcError> {
        self.call("jam_getContext", serde_json::json!([service_id]))
            .await
    }

    pub async fn get_state_summary(
        &self,
        block_hash: Option<&str>,
    ) -> Result<StateSummaryResult, RpcError> {
        self.call("jam_getState", serde_json::json!([block_hash]))
            .await
    }

    pub async fn read_storage(
        &self,
        service_id: u32,
        key_hex: &str,
    ) -> Result<StorageResult, RpcError> {
        self.call("jam_readStorage", serde_json::json!([service_id, key_hex]))
            .await
    }

    pub async fn submit_work_package(&self, data_hex: &str) -> Result<SubmitResult, RpcError> {
        self.call("jam_submitWorkPackage", serde_json::json!([data_hex]))
            .await
    }

    /// Call an arbitrary RPC method with the given parameters.
    /// Returns the raw JSON result value on success, or the RPC error on failure.
    /// Useful for negative testing (invalid methods, bad params, etc.).
    pub async fn call_raw(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError> {
        self.call(method, params).await
    }

    /// Fetch the raw Prometheus metrics from the /metrics HTTP endpoint.
    /// The endpoint is on the same host/port as the RPC server.
    pub async fn get_metrics(&self) -> Result<String, RpcError> {
        let url = self.endpoint.replace("http://", "");
        let metrics_url = format!("http://{}/metrics", url.trim_end_matches('/'));
        let resp = self
            .http
            .get(&metrics_url)
            .send()
            .await
            .map_err(|e| RpcError::Http {
                method: "GET /metrics".to_string(),
                source: e,
            })?;
        resp.text().await.map_err(|e| RpcError::Http {
            method: "GET /metrics".to_string(),
            source: e,
        })
    }
}

/// Multi-validator RPC client for querying all nodes in a testnet.
///
/// Wraps multiple `RpcClient` instances and provides methods to
/// query all validators and compare their responses.
#[allow(dead_code)]
pub struct MultiRpcClient {
    clients: Vec<RpcClient>,
}

#[allow(dead_code)]
impl MultiRpcClient {
    /// Create a multi-client from a list of RPC endpoint URLs.
    pub fn new(endpoints: &[String]) -> Self {
        Self {
            clients: endpoints.iter().map(|e| RpcClient::new(e)).collect(),
        }
    }

    /// Create a multi-client for sequential testnet validators.
    /// Assumes validators listen on consecutive ports starting at `base_port`.
    pub fn for_testnet(host: &str, base_port: u16, count: u16) -> Self {
        let endpoints: Vec<String> = (0..count)
            .map(|i| format!("http://{}:{}", host, base_port + i))
            .collect();
        Self::new(&endpoints)
    }

    /// Number of validators/endpoints.
    pub fn count(&self) -> usize {
        self.clients.len()
    }

    /// Get a reference to a specific validator's client.
    pub fn client(&self, index: usize) -> &RpcClient {
        &self.clients[index]
    }

    /// Query status from all validators. Returns (index, result) pairs.
    pub async fn get_all_status(&self) -> Vec<(usize, Result<NodeStatus, RpcError>)> {
        let mut results = Vec::with_capacity(self.clients.len());
        for (i, client) in self.clients.iter().enumerate() {
            results.push((i, client.get_status().await));
        }
        results
    }

    /// Check if all validators agree on the finalized block hash.
    /// Returns Ok(hash) if all agree, Err with divergence details if not.
    pub async fn check_finalized_consensus(&self) -> Result<String, String> {
        let statuses = self.get_all_status().await;
        let mut finalized_hashes: Vec<(usize, String)> = Vec::new();

        for (i, result) in &statuses {
            match result {
                Ok(status) => {
                    finalized_hashes.push((*i, status.finalized_hash.clone()));
                }
                Err(e) => {
                    return Err(format!("validator {} unreachable: {}", i, e));
                }
            }
        }

        if finalized_hashes.is_empty() {
            return Err("no validators responded".to_string());
        }

        let reference_hash = &finalized_hashes[0].1;
        let divergent: Vec<_> = finalized_hashes
            .iter()
            .filter(|(_, h)| h != reference_hash)
            .collect();

        if divergent.is_empty() {
            Ok(reference_hash.clone())
        } else {
            let mut msg = format!(
                "finalized hash divergence: v0={}, divergent: ",
                reference_hash
            );
            for (i, h) in &divergent {
                msg.push_str(&format!("v{}={}, ", i, h));
            }
            Err(msg)
        }
    }

    /// Check if all validators are within `max_slot_diff` slots of each other.
    pub async fn check_head_proximity(&self, max_slot_diff: u32) -> Result<(), String> {
        let statuses = self.get_all_status().await;
        let mut slots: Vec<(usize, u32)> = Vec::new();

        for (i, result) in &statuses {
            match result {
                Ok(status) => slots.push((*i, status.head_slot)),
                Err(e) => return Err(format!("validator {} unreachable: {}", i, e)),
            }
        }

        if slots.is_empty() {
            return Err("no validators responded".to_string());
        }

        let min_slot = slots.iter().map(|(_, s)| *s).min().unwrap();
        let max_slot = slots.iter().map(|(_, s)| *s).max().unwrap();

        if max_slot - min_slot > max_slot_diff {
            let details: Vec<String> = slots.iter().map(|(i, s)| format!("v{}={}", i, s)).collect();
            Err(format!(
                "head slot spread {} exceeds max {}: [{}]",
                max_slot - min_slot,
                max_slot_diff,
                details.join(", ")
            ))
        } else {
            Ok(())
        }
    }
}
