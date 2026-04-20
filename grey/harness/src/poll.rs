//! Polling utilities: wait_until, RPC readiness, service readiness, pixel verification.

use std::time::{Duration, Instant};

use tracing::info;

use crate::pixel;
use crate::rpc::{RpcClient, SubmitResult};

#[derive(Debug, thiserror::Error)]
#[error("timed out waiting for {label} ({timeout:?})")]
pub struct TimeoutError {
    label: String,
    timeout: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MetricsSnapshot {
    head_slot: u32,
    work_packages_submitted: u64,
    work_packages_accumulated: u64,
}

/// Poll `predicate` every `interval` until it returns `true`, or fail after `timeout`.
pub async fn wait_until<F, Fut>(
    predicate: F,
    interval: Duration,
    timeout: Duration,
    label: &str,
) -> Result<(), TimeoutError>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate().await {
            return Ok(());
        }
        tokio::time::sleep(interval).await;
    }
    Err(TimeoutError {
        label: label.to_string(),
        timeout,
    })
}

/// Wait for the RPC endpoint to respond.
pub async fn wait_for_rpc(client: &RpcClient, timeout: Duration) -> Result<(), TimeoutError> {
    wait_until(
        || async { client.get_status().await.is_ok() },
        Duration::from_secs(1),
        timeout,
        "RPC ready",
    )
    .await
}

/// Wait for a service to have a non-null code_hash.
pub async fn wait_for_service(
    client: &RpcClient,
    service_id: u32,
    timeout: Duration,
) -> Result<(), TimeoutError> {
    wait_until(
        || async {
            client
                .get_context(service_id)
                .await
                .map(|ctx| ctx.code_hash.is_some())
                .unwrap_or(false)
        },
        Duration::from_secs(2),
        timeout,
        &format!("service {service_id} ready"),
    )
    .await
}

fn parse_metric_u64(body: &str, name: &str) -> Result<u64, String> {
    let line = body
        .lines()
        .find(|line| line.split_whitespace().next() == Some(name))
        .ok_or_else(|| format!("missing metric: {name}"))?;
    let value = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("missing value for metric: {name}"))?;
    value
        .parse::<u64>()
        .map_err(|e| format!("invalid metric {name}: {e}"))
}

async fn fetch_metrics_snapshot(
    client: &RpcClient,
) -> Result<MetricsSnapshot, Box<dyn std::error::Error>> {
    let body = client.get_metrics().await?;
    Ok(MetricsSnapshot {
        head_slot: parse_metric_u64(&body, "grey_block_height")? as u32,
        work_packages_submitted: parse_metric_u64(&body, "grey_work_packages_submitted_total")?,
        work_packages_accumulated: parse_metric_u64(&body, "grey_work_packages_accumulated_total")?,
    })
}

async fn wait_for_metrics_progress(
    client: &RpcClient,
    before: MetricsSnapshot,
    timeout: Duration,
) -> Result<MetricsSnapshot, TimeoutError> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(snapshot) = fetch_metrics_snapshot(client).await
            && snapshot.work_packages_submitted > before.work_packages_submitted
            && snapshot.work_packages_accumulated > before.work_packages_accumulated
        {
            return Ok(snapshot);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(TimeoutError {
        label: "RPC submission + accumulation metrics".to_string(),
        timeout,
    })
}

async fn find_guarantee_block(
    client: &RpcClient,
    from_slot: u32,
    to_slot: u32,
) -> Result<Option<u32>, Box<dyn std::error::Error>> {
    if from_slot > to_slot {
        return Ok(None);
    }

    let blocks = client.get_block_range(from_slot, to_slot).await?;
    for entry in blocks.blocks {
        let block = client.get_block(&entry.hash).await?;
        if block.guarantees_count > 0 {
            return Ok(Some(entry.slot));
        }
    }
    Ok(None)
}

/// Check if a pixel at (x,y) with color (r,g,b) is written in storage.
pub fn pixel_matches(value: &str, x: u8, y: u8, r: u8, g: u8, b: u8) -> bool {
    let offset = (y as usize * 100 + x as usize) * 3 * 2; // hex offset
    if offset + 6 > value.len() {
        return false;
    }
    let expected = format!("{r:02x}{g:02x}{b:02x}");
    value[offset..offset + 6] == expected
}

/// Check if a pixel at (x,y) with color (r,g,b) is written in storage.
pub async fn check_pixel(
    client: &RpcClient,
    service_id: u32,
    x: u8,
    y: u8,
    r: u8,
    g: u8,
    b: u8,
) -> bool {
    let Ok(storage) = client.read_storage(service_id, "00").await else {
        return false;
    };
    let Some(value) = &storage.value else {
        return false;
    };
    pixel_matches(value, x, y, r, g, b)
}

/// Submit a pixel work package but do not wait for confirmation.
#[allow(clippy::too_many_arguments)]
pub async fn submit_pixel_work_package(
    client: &RpcClient,
    service_id: u32,
    x: u8,
    y: u8,
    r: u8,
    g: u8,
    b: u8,
) -> Result<SubmitResult, Box<dyn std::error::Error>> {
    let ctx = client.get_context(service_id).await?;
    assert!(
        ctx.code_hash.is_some(),
        "service code_hash must be non-null"
    );

    let wp_bytes = pixel::build_pixel_work_package(service_id, &ctx, x, y, r, g, b)?;
    let data_hex = hex::encode(&wp_bytes);
    let result = client.submit_work_package(&data_hex).await?;
    let color_hex = format!("#{r:02x}{g:02x}{b:02x}");
    info!(
        "submitted ({x},{y}) {color_hex} hash={}...",
        &result.hash[..16.min(result.hash.len())]
    );
    Ok(result)
}

/// Wait for a previously-submitted pixel to appear in storage.
#[allow(clippy::too_many_arguments)]
pub async fn wait_for_pixel(
    client: &RpcClient,
    service_id: u32,
    x: u8,
    y: u8,
    r: u8,
    g: u8,
    b: u8,
    timeout: Duration,
) -> Result<(), TimeoutError> {
    let color_hex = format!("#{r:02x}{g:02x}{b:02x}");
    wait_until(
        || async { check_pixel(client, service_id, x, y, r, g, b).await },
        Duration::from_secs(2),
        timeout,
        &format!("pixel ({x},{y}) {color_hex}"),
    )
    .await
}

/// Submit a pixel work package and wait for it to appear in storage.
#[allow(clippy::too_many_arguments)]
pub async fn submit_and_verify_pixel(
    client: &RpcClient,
    service_id: u32,
    x: u8,
    y: u8,
    r: u8,
    g: u8,
    b: u8,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let before_metrics = fetch_metrics_snapshot(client).await?;
    submit_pixel_work_package(client, service_id, x, y, r, g, b).await?;
    let after_metrics = wait_for_metrics_progress(client, before_metrics, timeout).await?;
    let guarantee_slot = find_guarantee_block(
        client,
        before_metrics.head_slot.saturating_add(1),
        after_metrics.head_slot,
    )
    .await?
    .ok_or_else(|| {
        format!(
            "metrics advanced from slot {} to {} but no guarantee block was found",
            before_metrics.head_slot, after_metrics.head_slot
        )
    })?;
    wait_for_pixel(client, service_id, x, y, r, g, b, timeout).await?;

    let storage = client.read_storage(service_id, "00").await?;
    let color_hex = format!("#{r:02x}{g:02x}{b:02x}");
    info!(
        "({x},{y}) {color_hex} ok (included at slot {guarantee_slot}, visible at head slot {})",
        storage.slot
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_metric_u64;

    #[test]
    fn parse_metric_u64_reads_plain_counter_lines() {
        let body = "\
# HELP grey_work_packages_accumulated_total Work packages accumulated.\n\
# TYPE grey_work_packages_accumulated_total counter\n\
grey_work_packages_accumulated_total 7\n";
        assert_eq!(
            parse_metric_u64(body, "grey_work_packages_accumulated_total").unwrap(),
            7
        );
    }

    #[test]
    fn parse_metric_u64_errors_when_metric_missing() {
        let err = parse_metric_u64("grey_block_height 12\n", "grey_missing_metric").unwrap_err();
        assert!(err.contains("missing metric"));
    }
}
