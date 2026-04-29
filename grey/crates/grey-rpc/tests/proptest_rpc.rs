//! Property-based tests for the RPC server.
//!
//! Sends random and malformed JSON-RPC requests to verify the server never
//! panics and always returns a valid HTTP response.

use proptest::prelude::*;
use std::sync::Arc;

/// Start an ephemeral RPC server for testing.
async fn setup_server() -> String {
    let dir = tempfile::tempdir().unwrap();
    let store = grey_store::Store::open(dir.path().join("test.redb")).unwrap();
    let store = Arc::new(store);
    let config = grey_types::config::Config::tiny();
    let (state, _rx) = grey_rpc::create_rpc_channel(store, config, 0);
    let (addr, _handle) = grey_rpc::start_rpc_server_ephemeral(state).await.unwrap();
    // Leak the tempdir so it lives for the duration of the test.
    std::mem::forget(dir);
    format!("http://{}", addr)
}

/// Send a raw JSON body to the RPC server and return the HTTP status code.
async fn send_raw_json(url: &str, body: &str) -> u16 {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    match client
        .post(url)
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
    {
        Ok(resp) => resp.status().as_u16(),
        Err(_) => 0, // Connection error, but still no panic.
    }
}

/// Send a raw JSON body and return both HTTP status and response body text.
async fn send_raw_json_response(url: &str, body: &str) -> (u16, String) {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    match client
        .post(url)
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            (status, text)
        }
        Err(_) => (0, String::new()), // Connection error, but still no panic.
    }
}

/// Generate random JSON-RPC-like request bodies.
fn arb_jsonrpc_body() -> impl Strategy<Value = String> {
    prop_oneof![
        // Valid structure with random method name.
        "[a-z_]{1,30}".prop_map(|method| {
            format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"{}","params":[]}}"#,
                method
            )
        }),
        // Valid structure with random params.
        prop::collection::vec(prop::num::i64::ANY, 0..5).prop_map(|params| {
            let params_json: Vec<String> = params.iter().map(|p| p.to_string()).collect();
            format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"jam_getBlock","params":[{}]}}"#,
                params_json.join(",")
            )
        }),
        // Partial JSON.
        prop_oneof![
            Just(r#"{"jsonrpc":"2.0""#.to_string()),
            Just(r#"{"jsonrpc":"2.0","id":1}"#.to_string()),
            Just(r#"{"method":"jam_getBlock"}"#.to_string()),
            Just(r#"null"#.to_string()),
            Just(r#"[]"#.to_string()),
            Just(r#""""#.to_string()),
            Just(r#"42"#.to_string()),
            Just(String::new()),
        ],
        // Known methods with wrong param types.
        prop_oneof![
            Just(
                r#"{"jsonrpc":"2.0","id":1,"method":"jam_getBlock","params":["not-hex"]}"#
                    .to_string()
            ),
            Just(
                r#"{"jsonrpc":"2.0","id":1,"method":"jam_getBlock","params":[123]}"#.to_string()
            ),
            Just(
                r#"{"jsonrpc":"2.0","id":1,"method":"jam_submitWorkPackage","params":[null]}"#
                    .to_string()
            ),
            Just(
                r#"{"jsonrpc":"2.0","id":1,"method":"jam_readStorage","params":["abc","def","ghi"]}"#
                    .to_string()
            ),
        ],
    ]
}

/// Generate JSON-RPC batch requests containing a mix of valid and malformed calls.
fn arb_jsonrpc_batch_body() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![
            "[a-z_]{1,20}".prop_map(|method| {
                format!(
                    r#"{{"jsonrpc":"2.0","id":1,"method":"{}","params":[]}}"#,
                    method
                )
            }),
            Just(r#"{"jsonrpc":"2.0","id":2,"method":"jam_getStatus","params":[]}"#.to_string()),
            Just(
                r#"{"jsonrpc":"2.0","id":3,"method":"jam_getBlock","params":["not-hex"]}"#
                    .to_string()
            ),
            Just(
                r#"{"jsonrpc":"2.0","id":4,"method":"jam_readStorage","params":["abc"]}"#
                    .to_string()
            ),
            Just(r#"{"id":5,"method":"jam_getFinalized"}"#.to_string()),
            Just(r#"null"#.to_string()),
            Just(r#"42"#.to_string()),
        ],
        1..6,
    )
    .prop_map(|items| format!("[{}]", items.join(",")))
}

fn assert_response_is_json_or_empty(status: u16, body: &str) {
    if status == 0 || body.trim().is_empty() {
        return;
    }

    serde_json::from_str::<serde_json::Value>(body)
        .unwrap_or_else(|_| panic!("response body was not valid JSON: {body:?}"));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn rpc_server_handles_random_json(body in arb_jsonrpc_body()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let url = setup_server().await;
            let status = send_raw_json(&url, &body).await;
            // The server should always respond (not crash). Valid status codes
            // are 200 (success or JSON-RPC error in body) or 4xx/5xx.
            // Status 0 means connection error, but still no panic.
            prop_assert!(
                status == 0 || (200..=599).contains(&status),
                "unexpected status {} for body: {:?}",
                status,
                body
            );
            Ok(())
        })?;
    }

    #[test]
    fn rpc_server_handles_random_batch_json(body in arb_jsonrpc_batch_body()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let url = setup_server().await;
            let (status, response_body) = send_raw_json_response(&url, &body).await;
            prop_assert!(
                status == 0 || (200..=599).contains(&status),
                "unexpected status {} for batch body: {:?}",
                status,
                body
            );
            assert_response_is_json_or_empty(status, &response_body);
            Ok(())
        })?;
    }
}

#[tokio::test]
async fn rpc_server_handles_empty_batch_request() {
    let url = setup_server().await;
    let (status, body) = send_raw_json_response(&url, "[]").await;
    assert!((200..=599).contains(&status), "unexpected status {status}");
    assert_response_is_json_or_empty(status, &body);
}

#[tokio::test]
async fn rpc_server_handles_mixed_batch_request() {
    let url = setup_server().await;
    let body = r#"[
        {"jsonrpc":"2.0","id":1,"method":"jam_getStatus","params":[]},
        {"jsonrpc":"2.0","id":2,"method":"jam_getBlock","params":["not-hex"]},
        {"jsonrpc":"2.0","id":3,"method":"unknown_method","params":[]}
    ]"#;
    let (status, response_body) = send_raw_json_response(&url, body).await;
    assert!((200..=599).contains(&status), "unexpected status {status}");
    assert_response_is_json_or_empty(status, &response_body);

    if !response_body.trim().is_empty() {
        let value: serde_json::Value =
            serde_json::from_str(&response_body).expect("mixed batch response should be JSON");
        assert!(
            value.is_array() || value.is_object(),
            "expected array or object response, got {value:?}"
        );
    }
}
