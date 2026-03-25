use std::path::Path;

use crate::cache;
use crate::git;
use crate::github;
use crate::lean;
use crate::types::SelectTargetsOutput;

/// Run the PR-opened workflow: compute and post comparison targets.
pub fn run(pr: u64, created_at: &str) -> Result<(), Box<dyn std::error::Error>> {
    let repo_root = git::repo_root()?;
    let spec_dir = Path::new(&repo_root).join("spec");

    // Fetch and read cache
    git::fetch("origin", "genesis-state")?;
    let cache_json = git::show_file("origin/genesis-state:genesis.json")?;
    let cache_indices: Vec<serde_json::Value> = serde_json::from_str(&cache_json)?;

    // Check cache staleness
    if let Err(e) = cache::check_staleness(&cache_indices, &spec_dir) {
        github::pr_comment(pr, &format!(
            "**JAR Bot:** Genesis cache is stale — cannot compute comparison targets. {e}"
        ))?;
        return Err(e.into());
    }

    // Parse PR created_at to epoch
    let pr_created_epoch = parse_iso8601_to_epoch(created_at)?;

    // Get ranking snapshot
    let ranking_json = git::show_file("origin/genesis-state:ranking.json")
        .unwrap_or_else(|_| "{}".to_string());
    let ranking: serde_json::Value = serde_json::from_str(&ranking_json)?;

    // Find ranking snapshot for this PR's created_at
    let ranking_snapshot = find_ranking_snapshot(&cache_indices, &ranking, pr_created_epoch);

    // Build input for genesis_select_targets
    let mut input = serde_json::json!({
        "prId": pr,
        "prCreatedAt": pr_created_epoch,
        "indices": cache_indices,
    });
    if let Some(snapshot) = &ranking_snapshot {
        input["ranking"] = snapshot.clone();
    }

    let output: SelectTargetsOutput =
        lean::invoke("genesis_select_targets", &input, &spec_dir)?;

    // Format and post comment
    let mut comment = String::from("## Genesis Review\n\n**Comparison targets:**\n\n");
    for target in &output.targets {
        let short = &target[..8.min(target.len())];
        comment.push_str(&format!("- `{short}` ({target})\n"));
    }
    comment.push_str("\n### How to review\n\n");
    comment.push_str("Post a comment with the following format (rank from best to worst):\n\n");
    comment.push_str("```\n/review\n");
    comment.push_str("difficulty: <commit1>, <commit2>, ..., <commitN>, currentPR\n");
    comment.push_str("novelty: <commit1>, <commit2>, ..., <commitN>, currentPR\n");
    comment.push_str("design: <commit1>, <commit2>, ..., <commitN>, currentPR\n");
    comment.push_str("verdict: merge\n```\n\n");
    comment.push_str("Use the short commit hashes above and `currentPR` for this PR.\n");
    comment.push_str("Each line ranks all comparison targets + this PR from best to worst.\n\n");
    comment.push_str("To meta-review another reviewer's comment, react with 👍 or 👎.");

    github::pr_comment(pr, &comment)?;

    Ok(())
}

fn parse_iso8601_to_epoch(s: &str) -> Result<u64, Box<dyn std::error::Error>> {
    // Simple ISO 8601 parsing: "2026-03-25T10:51:59Z"
    // Use the `date` command for robustness
    let output = std::process::Command::new("date")
        .args(["-d", s, "+%s"])
        .output()?;
    if !output.status.success() {
        return Err(format!("failed to parse date '{s}'").into());
    }
    let epoch: u64 = String::from_utf8_lossy(&output.stdout).trim().parse()?;
    Ok(epoch)
}

fn find_ranking_snapshot(
    indices: &[serde_json::Value],
    ranking: &serde_json::Value,
    epoch: u64,
) -> Option<serde_json::Value> {
    let last = indices
        .iter()
        .filter(|idx| idx["epoch"].as_u64().map(|e| e < epoch).unwrap_or(false))
        .last()?;
    let commit_hash = last["commitHash"].as_str()?;
    ranking.get(commit_hash).cloned()
}
