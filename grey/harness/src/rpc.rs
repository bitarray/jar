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

    async fn call<T: serde::de::DeserializeOwned>(
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
