//! Genesis workflow queue — ensures sequential execution across all genesis workflows.
//!
//! Each workflow run polls the GitHub API for earlier active runs. If any exist,
//! it waits until they complete before proceeding. Ordering by `created_at`
//! ensures FIFO — no starvation, no silent drops.

use crate::github;

const POLL_INTERVAL_SECS: u64 = 10;
const TIMEOUT_SECS: u64 = 600; // 10 minutes
const GENESIS_WORKFLOW_PREFIX: &str = ".github/workflows/genesis-";

/// Resolve workflow IDs for all genesis workflows by path prefix.
fn resolve_genesis_workflow_ids() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let output = github::gh(&[
        "api",
        "repos/{owner}/{repo}/actions/workflows",
        "--jq",
        ".workflows[] | [.id, .path] | @tsv",
    ])?;

    let ids: Vec<String> = output
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() == 2 && parts[1].starts_with(GENESIS_WORKFLOW_PREFIX) {
                Some(parts[0].trim().to_string())
            } else {
                None
            }
        })
        .collect();

    if ids.is_empty() {
        return Err("no genesis workflows found".into());
    }

    eprintln!("genesis-queue: found {} genesis workflow(s)", ids.len());
    Ok(ids)
}

/// Wait until all earlier genesis workflow runs have completed.
/// Polls every 10 seconds, times out after 10 minutes.
///
/// Only runs in GitHub Actions (requires GITHUB_RUN_ID environment variable).
pub fn wait_for_queue() -> Result<(), Box<dyn std::error::Error>> {
    let run_id = std::env::var("GITHUB_RUN_ID")
        .map_err(|_| "GITHUB_RUN_ID not set — not running in GitHub Actions")?;

    // Get this run's created_at
    let my_created_at = github::gh(&[
        "api",
        &format!("repos/{{owner}}/{{repo}}/actions/runs/{run_id}"),
        "--jq",
        ".created_at",
    ])?
    .trim()
    .to_string();

    eprintln!(
        "genesis-queue: run {run_id} created at {my_created_at}, checking for earlier runs..."
    );

    let workflow_ids = resolve_genesis_workflow_ids()?;
    let delay = std::time::Duration::from_secs(POLL_INTERVAL_SECS);
    let timeout = std::time::Duration::from_secs(TIMEOUT_SECS);
    let start = std::time::Instant::now();

    loop {
        let mut earlier_active: Vec<(String, String)> = Vec::new();

        for wf_id in &workflow_ids {
            for status in &["in_progress", "queued"] {
                let output = github::gh(&[
                    "api",
                    &format!(
                        "repos/{{owner}}/{{repo}}/actions/workflows/{wf_id}/runs?status={status}&per_page=10"
                    ),
                    "--jq",
                    ".workflow_runs[] | [.id, .created_at] | @tsv",
                ])?;

                for line in output.lines() {
                    let parts: Vec<&str> = line.split('\t').collect();
                    if parts.len() == 2 {
                        let id = parts[0].trim();
                        let created = parts[1].trim();
                        if id != run_id && created < my_created_at.as_str() {
                            earlier_active.push((id.to_string(), created.to_string()));
                        }
                    }
                }
            }
        }

        if earlier_active.is_empty() {
            eprintln!("genesis-queue: no earlier runs active, proceeding");
            return Ok(());
        }

        if start.elapsed() >= timeout {
            return Err(format!(
                "genesis-queue: timed out after {}s waiting for {} earlier run(s): {}",
                TIMEOUT_SECS,
                earlier_active.len(),
                earlier_active
                    .iter()
                    .map(|(id, _)| id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
            .into());
        }

        eprintln!(
            "genesis-queue: waiting for {} earlier run(s) ({:.0}s elapsed)",
            earlier_active.len(),
            start.elapsed().as_secs_f64()
        );
        std::thread::sleep(delay);
    }
}
