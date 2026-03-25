use std::path::Path;

use crate::cache;
use crate::git;
use crate::github;
use crate::lean;
use crate::review;
use crate::types::{MergeReadiness, SelectTargetsOutput};

/// Run the review workflow: process a /review comment.
pub fn run(
    pr: u64,
    comment_author: &str,
    _comment_body: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let repo_root = git::repo_root()?;
    let spec_dir = Path::new(&repo_root).join("spec");

    // Fetch and read cache
    git::fetch("origin", "genesis-state")?;
    let cache_json = git::show_file("origin/genesis-state:genesis.json")?;
    let cache_indices: Vec<serde_json::Value> = serde_json::from_str(&cache_json)?;

    // Check cache staleness
    if let Err(e) = cache::check_staleness(&cache_indices, &spec_dir) {
        github::pr_comment(pr, &format!(
            "**JAR Bot:** Genesis cache is stale — cannot process review. {e}"
        ))?;
        return Err(e.into());
    }

    // Get PR head SHA and created_at
    let pr_json = github::pr_view(pr, "headRefOid,createdAt")?;
    let head_sha = pr_json["headRefOid"].as_str().unwrap_or("").to_string();
    let pr_created_at = pr_json["createdAt"].as_str().unwrap_or("");

    let pr_created_epoch = {
        let output = std::process::Command::new("date")
            .args(["-d", pr_created_at, "+%s"])
            .output()?;
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<u64>()?
    };

    // Get ranking snapshot
    let ranking_json = git::show_file("origin/genesis-state:ranking.json")
        .unwrap_or_else(|_| "{}".to_string());
    let ranking: serde_json::Value = serde_json::from_str(&ranking_json)?;

    let ranking_snapshot = find_ranking_snapshot(&cache_indices, &ranking, pr_created_epoch);

    // Compute comparison targets
    let mut targets_input = serde_json::json!({
        "prId": pr,
        "prCreatedAt": pr_created_epoch,
        "indices": cache_indices,
    });
    if let Some(snapshot) = &ranking_snapshot {
        targets_input["ranking"] = snapshot.clone();
    }

    let targets_output: SelectTargetsOutput =
        lean::invoke("genesis_select_targets", &targets_input, &spec_dir)?;
    let targets = targets_output.targets;

    // Collect all reviews (not just this one — we need the full set for quorum check)
    let collected = review::collect(pr, &head_sha, &targets)?;

    // Check merge readiness
    let check_input = serde_json::json!({
        "reviews": collected.reviews,
        "metaReviews": collected.meta_reviews,
        "indices": cache_indices,
    });
    let readiness: MergeReadiness = lean::invoke("genesis_check_merge", &check_input, &spec_dir)?;

    let review_count = collected.reviews.len();
    let meta_count = collected.meta_reviews.len();

    if readiness.ready {
        // Quorum reached — trigger merge workflow
        github::workflow_run(
            "genesis-merge.yml",
            &[("pr_number", &pr.to_string())],
        )?;

        github::pr_comment(pr, &format!(
            "**JAR Bot:** Quorum reached — triggering merge.\n\
             Reviews: {review_count}, meta-reviews: {meta_count}.\n\
             Merge weight: {}/{} (>50%).",
            readiness.merge_weight, readiness.total_weight
        ))?;
    } else {
        github::pr_comment(pr, &format!(
            "**JAR Bot:** Review recorded from @{comment_author} ({review_count} reviews, {meta_count} meta-reviews).\n\
             Merge weight: {}/{} (need >50%).",
            readiness.merge_weight, readiness.total_weight
        ))?;
    }

    Ok(())
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
