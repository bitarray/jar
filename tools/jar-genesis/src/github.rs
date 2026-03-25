use std::process::Command;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum GhError {
    #[error("gh command failed: {0}")]
    CommandFailed(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Run a `gh` CLI command and return stdout.
pub fn gh(args: &[&str]) -> Result<String, GhError> {
    let output = Command::new("gh").args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GhError::CommandFailed(format!(
            "gh {} failed: {}",
            args.join(" "),
            stderr.trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Post a comment on a PR.
pub fn pr_comment(pr: u64, body: &str) -> Result<(), GhError> {
    gh(&["pr", "comment", &pr.to_string(), "--body", body])?;
    Ok(())
}

/// Get PR details as JSON.
pub fn pr_view(pr: u64, fields: &str) -> Result<serde_json::Value, GhError> {
    let output = gh(&["pr", "view", &pr.to_string(), "--json", fields])?;
    serde_json::from_str(&output)
        .map_err(|e| GhError::CommandFailed(format!("failed to parse PR JSON: {e}")))
}

/// Watch PR checks until they pass or fail.
pub fn pr_checks_watch(pr: u64) -> Result<(), GhError> {
    let status = Command::new("gh")
        .args(["pr", "checks", &pr.to_string(), "--watch", "--fail-fast"])
        .status()?;
    if !status.success() {
        return Err(GhError::CommandFailed("PR checks failed".to_string()));
    }
    Ok(())
}

/// Merge a PR with a specific head commit SHA and custom subject.
pub fn pr_merge(pr: u64, head_sha: &str, subject: &str) -> Result<(), GhError> {
    gh(&[
        "pr",
        "merge",
        &pr.to_string(),
        "--merge",
        "--match-head-commit",
        head_sha,
        "--subject",
        subject,
    ])?;
    Ok(())
}

/// Trigger a workflow via workflow_dispatch.
pub fn workflow_run(workflow: &str, inputs: &[(&str, &str)]) -> Result<(), GhError> {
    let mut args = vec!["workflow", "run", workflow];
    for (key, value) in inputs {
        args.push("-f");
        let kv = format!("{key}={value}");
        // Need to leak the string to get a &str — this is fine for CLI usage
        args.push(Box::leak(kv.into_boxed_str()));
    }
    gh(&args)?;
    Ok(())
}

/// Fetch paginated API results.
pub fn api_paginate(path: &str, jq: &str) -> Result<serde_json::Value, GhError> {
    let output = gh(&["api", path, "--paginate", "--jq", jq])?;
    serde_json::from_str(&output)
        .map_err(|e| GhError::CommandFailed(format!("failed to parse API JSON: {e}")))
}
