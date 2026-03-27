use std::path::Path;

use crate::cache;
use crate::git;
use crate::github;
use crate::lean;
use crate::replay;
use crate::review;
use crate::types::{MergeReadiness, SelectTargetsOutput};

/// Run the merge workflow for a PR.
pub fn run(pr: u64, founder_override: bool) -> Result<(), Box<dyn std::error::Error>> {
    // --- Step 0: Guard against already-merged PRs ---
    let state_json = github::pr_view(pr, "state")?;
    let state = state_json["state"].as_str().unwrap_or("");
    if state == "MERGED" {
        eprintln!("PR #{pr} is already merged — skipping.");
        return Ok(());
    }

    let repo_root = git::repo_root()?;
    let spec_dir = Path::new(&repo_root).join("spec");

    // --- Step 1: Read and verify cache ---
    git::fetch("origin", "genesis-state")?;
    let cache_json = git::show_file("origin/genesis-state:genesis.json")?;
    let cache_indices: Vec<serde_json::Value> = serde_json::from_str(&cache_json)?;

    if let Err(e) = cache::check_staleness(&cache_indices, &spec_dir) {
        github::pr_comment(
            pr,
            &format!("**JAR Bot:** Genesis cache is stale — cannot merge. {e}"),
        )?;
        return Err(e.into());
    }

    // --- Step 2: Get PR details ---
    let pr_json = github::pr_view(pr, "headRefOid,author,createdAt,body")?;
    let head_sha = pr_json["headRefOid"].as_str().unwrap_or("").to_string();
    let mut author = pr_json["author"]["login"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let pr_created_at = pr_json["createdAt"].as_str().unwrap_or("");
    let pr_body = pr_json["body"].as_str().unwrap_or("");

    let pr_created_epoch = parse_epoch(pr_created_at)?;

    // Parse PR body flags
    if let Some(genesis_author) = parse_flag(pr_body, "Set-Genesis-Author") {
        author = genesis_author;
    }

    // --- Step 3: Compute comparison targets ---
    let ranking_json = git::show_file("origin/genesis-state:ranking.json")
        .unwrap_or_else(|_| "{}".to_string());
    let ranking: serde_json::Value = serde_json::from_str(&ranking_json)?;
    let ranking_snapshot = find_ranking_snapshot(&cache_indices, &ranking, pr_created_epoch);

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

    // --- Step 4: Check no commits after last review ---
    check_no_new_commits(pr)?;

    // --- Step 5: Collect reviews ---
    let collected = review::collect(pr, &head_sha, &targets)?;

    // --- Step 6: Re-check quorum (defense-in-depth) ---
    let check_input = serde_json::json!({
        "reviews": collected.reviews,
        "metaReviews": collected.meta_reviews,
        "indices": cache_indices,
    });
    let readiness: MergeReadiness = lean::invoke("genesis_check_merge", &check_input, &spec_dir)?;

    if !readiness.ready && !founder_override {
        github::pr_comment(
            pr,
            &format!(
                "**JAR Bot:** Quorum not reached — cannot merge.\n\
                 Merge weight: {}/{} (need >50%).",
                readiness.merge_weight, readiness.total_weight
            ),
        )?;
        return Err("quorum not reached".into());
    }

    let merge_type = if founder_override {
        "founder override"
    } else {
        "quorum reached"
    };

    // --- Step 7: Build SignedCommit and evaluate ---
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let commit_json = serde_json::json!({
        "id": head_sha,
        "prId": pr,
        "author": author,
        "mergeEpoch": epoch,
        "prCreatedAt": pr_created_epoch,
        "comparisonTargets": targets,
        "reviews": collected.reviews,
        "metaReviews": collected.meta_reviews,
        "founderOverride": founder_override,
    });

    let mut eval_input = serde_json::json!({
        "commit": commit_json,
        "pastIndices": cache_indices,
    });
    if let Some(snapshot) = &ranking_snapshot {
        eval_input["ranking"] = snapshot.clone();
    }

    let index: serde_json::Value = lean::invoke("genesis_evaluate", &eval_input, &spec_dir)?;

    let score = &index["score"];
    let weight_delta = index["weightDelta"].as_u64().unwrap_or(0);

    // Post warnings
    let mut all_warnings: Vec<String> = collected.warnings.clone();
    if let Some(eval_warnings) = index["warnings"].as_array() {
        for w in eval_warnings {
            if let Some(s) = w.as_str() {
                all_warnings.push(s.to_string());
            }
        }
    }

    if !all_warnings.is_empty() {
        let warning_lines: String = all_warnings.iter().map(|w| format!("- {w}\n")).collect();
        github::pr_comment(
            pr,
            &format!("**JAR Bot:** Evaluation warnings:\n{warning_lines}"),
        )?;
    }

    // Strip warnings from index for trailer
    let mut index_for_trailer = index.clone();
    if let Some(obj) = index_for_trailer.as_object_mut() {
        obj.remove("warnings");
    }

    // --- Step 8: Wait for CI ---
    if let Err(_) = github::pr_checks_watch(pr) {
        github::pr_comment(
            pr,
            &format!("**JAR Bot:** Checks failed — cannot merge ({merge_type})."),
        )?;
        return Err("checks failed".into());
    }

    // --- Step 9: Merge with trailers ---
    let commit_compact = serde_json::to_string(&commit_json)?;
    let index_compact = serde_json::to_string(&index_for_trailer)?;
    let subject = format!(
        "Merge PR #{pr}\n\n\
         Genesis-Commit: {commit_compact}\n\
         Genesis-Index: {index_compact}\n\
         Genesis-PR: #{pr}\n\
         Genesis-Author: {author}"
    );

    github::pr_merge(pr, &head_sha, &subject)?;

    // Confirm merge
    for attempt in 1..=5 {
        let state_json = github::pr_view(pr, "state")?;
        let state = state_json["state"].as_str().unwrap_or("");
        if state == "MERGED" {
            break;
        }
        if attempt == 5 {
            github::pr_comment(
                pr,
                &format!("**JAR Bot:** Merge failed unexpectedly (state: {state})."),
            )?;
            return Err(format!("PR #{pr} not merged (state: {state})").into());
        }
        eprintln!("Waiting for merge state propagation (attempt {attempt}, state: {state})...");
        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    github::pr_comment(
        pr,
        &format!(
            "**JAR Bot:** Merged ({merge_type}).\nScore: {}\nWeight delta: {weight_delta}",
            serde_json::to_string(score)?
        ),
    )?;

    // --- Step 10: Update genesis-state cache ---
    update_cache(pr, &spec_dir, &cache_indices, &index_for_trailer, &commit_json)?;

    // --- Step 11: Verify cache integrity ---
    // Pull latest master (now includes the merge), then verify
    git::git_cmd(&["pull", "origin", "master", "--ff-only"])?;
    replay::verify_cache()?;

    Ok(())
}

/// Update the genesis-state branch with the new index and ranking.
fn update_cache(
    pr: u64,
    spec_dir: &Path,
    cache_indices: &[serde_json::Value],
    new_index: &serde_json::Value,
    new_commit: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    // Update genesis.json
    let mut updated_indices = cache_indices.to_vec();
    updated_indices.push(new_index.clone());

    // Compute updated ranking from all SignedCommits in git history
    let genesis_commit = git::read_genesis_commit_hash(spec_dir)?;
    git::git_cmd(&["pull", "origin", "master", "--ff-only"])?;

    let merge_commits = git::log_merge_commits(&genesis_commit)?;
    let mut signed_commits = Vec::new();
    for (_, message) in &merge_commits {
        if let Some(commit_line) = git::parse_trailer(message, "Genesis-Commit") {
            if let Ok(mut commit) = serde_json::from_str::<serde_json::Value>(&commit_line) {
                crate::replay::expand_review_hashes_public(&mut commit);
                signed_commits.push(commit);
            }
        }
    }

    let ranking_input = serde_json::json!({
        "signedCommits": signed_commits,
        "indices": updated_indices,
    });
    let ranking_output: serde_json::Value =
        lean::invoke("genesis_ranking", &ranking_input, spec_dir)?;
    let new_ranking = &ranking_output["ranking"];

    let new_commit_hash = new_index["commitHash"].as_str().unwrap_or("");

    // Update ranking.json
    let existing_ranking_json = git::show_file("origin/genesis-state:ranking.json")
        .unwrap_or_else(|_| "{}".to_string());
    let mut existing_ranking: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&existing_ranking_json)?;
    existing_ranking.insert(new_commit_hash.to_string(), new_ranking.clone());

    // Write to genesis-state branch via worktree
    git::fetch("origin", "genesis-state")?;
    git::git_cmd(&["worktree", "add", "/tmp/genesis-state", "origin/genesis-state"])?;
    git::git_cmd_in("/tmp/genesis-state", &["checkout", "-B", "genesis-state", "origin/genesis-state"])?;

    std::fs::write(
        "/tmp/genesis-state/genesis.json",
        serde_json::to_string_pretty(&updated_indices)?,
    )?;
    std::fs::write(
        "/tmp/genesis-state/ranking.json",
        serde_json::to_string_pretty(&serde_json::Value::Object(existing_ranking))?,
    )?;

    git::git_cmd_in("/tmp/genesis-state", &["config", "user.name", "JAR Bot"])?;
    git::git_cmd_in(
        "/tmp/genesis-state",
        &["config", "user.email", "legal@bitarray.dev"],
    )?;
    git::git_cmd_in("/tmp/genesis-state", &["add", "genesis.json", "ranking.json"])?;
    git::git_cmd_in(
        "/tmp/genesis-state",
        &[
            "commit",
            "-m",
            &format!("genesis: update state for PR #{pr}"),
        ],
    )?;
    git::git_cmd_in("/tmp/genesis-state", &["push", "origin", "genesis-state"])?;
    git::git_cmd(&["worktree", "remove", "/tmp/genesis-state"])?;

    Ok(())
}

fn check_no_new_commits(pr: u64) -> Result<(), Box<dyn std::error::Error>> {
    let repo = std::env::var("GITHUB_REPOSITORY").unwrap_or_else(|_| {
        github::gh(&["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"])
            .unwrap_or_default()
            .trim()
            .to_string()
    });

    let comments_json = github::pr_view(pr, "comments")?;
    let last_review_at = comments_json["comments"]
        .as_array()
        .and_then(|comments| {
            comments
                .iter()
                .filter(|c| {
                    c["body"]
                        .as_str()
                        .map(|b| b.starts_with("/review"))
                        .unwrap_or(false)
                })
                .last()
                .and_then(|c| c["createdAt"].as_str().map(|s| s.to_string()))
        });

    if let Some(last_review) = last_review_at {
        let commits_output = github::gh(&[
            "api",
            &format!("repos/{repo}/pulls/{pr}/commits"),
            "--jq",
            "last | .commit.committer.date",
        ])?;
        let last_commit_at = commits_output.trim();

        if !last_commit_at.is_empty() && last_commit_at > &last_review {
            github::pr_comment(pr, &format!(
                "**JAR Bot:** New commits pushed after the last review (commit: {last_commit_at}, review: {last_review}). Aborting merge — please re-review."
            ))?;
            return Err("commits pushed after last review".into());
        }
    }

    Ok(())
}

fn parse_flag(body: &str, flag: &str) -> Option<String> {
    let prefix = format!("{flag}:");
    for line in body.lines() {
        if line.is_empty() {
            break; // Only check leading lines before first blank line
        }
        if let Some(rest) = line.strip_prefix(&prefix) {
            let value = rest.trim().trim_start_matches('@');
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn parse_epoch(iso: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let output = std::process::Command::new("date")
        .args(["-d", iso, "+%s"])
        .output()?;
    if !output.status.success() {
        return Err(format!("failed to parse date '{iso}'").into());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().parse()?)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_flag_basic() {
        let body = "Set-Genesis-Author: @alice\n\nThis PR does something.";
        assert_eq!(parse_flag(body, "Set-Genesis-Author"), Some("alice".to_string()));
    }

    #[test]
    fn test_parse_flag_no_at() {
        let body = "Set-Genesis-Author: alice\n\nBody text.";
        assert_eq!(parse_flag(body, "Set-Genesis-Author"), Some("alice".to_string()));
    }

    #[test]
    fn test_parse_flag_missing() {
        let body = "Some other text\n\nBody.";
        assert_eq!(parse_flag(body, "Set-Genesis-Author"), None);
    }

    #[test]
    fn test_parse_flag_after_blank_line_ignored() {
        let body = "\nSet-Genesis-Author: @alice";
        assert_eq!(parse_flag(body, "Set-Genesis-Author"), None);
    }

    #[test]
    fn test_find_ranking_snapshot_empty() {
        let indices: Vec<serde_json::Value> = vec![];
        let ranking = serde_json::json!({});
        assert!(find_ranking_snapshot(&indices, &ranking, 1000).is_none());
    }

    #[test]
    fn test_find_ranking_snapshot_all_future() {
        let indices = vec![serde_json::json!({"commitHash": "abc", "epoch": 2000})];
        let ranking = serde_json::json!({"abc": ["abc"]});
        // epoch 1000 < 2000, so nothing is before it
        assert!(find_ranking_snapshot(&indices, &ranking, 1000).is_none());
    }

    #[test]
    fn test_find_ranking_snapshot_picks_last_before_epoch() {
        let indices = vec![
            serde_json::json!({"commitHash": "aaa", "epoch": 100}),
            serde_json::json!({"commitHash": "bbb", "epoch": 200}),
            serde_json::json!({"commitHash": "ccc", "epoch": 300}),
        ];
        let ranking = serde_json::json!({
            "aaa": ["aaa"],
            "bbb": ["bbb", "aaa"],
            "ccc": ["ccc", "bbb", "aaa"],
        });
        // epoch 250: last before it is bbb (epoch 200)
        let snapshot = find_ranking_snapshot(&indices, &ranking, 250).unwrap();
        assert_eq!(snapshot, serde_json::json!(["bbb", "aaa"]));
    }

    #[test]
    fn test_find_ranking_snapshot_missing_key() {
        let indices = vec![serde_json::json!({"commitHash": "abc", "epoch": 100})];
        let ranking = serde_json::json!({}); // key not present
        assert!(find_ranking_snapshot(&indices, &ranking, 200).is_none());
    }

    #[test]
    fn test_parse_flag_multiple_flags() {
        let body = "Set-Genesis-Author: @alice\nSome-Other-Flag: value\n\nBody text.";
        assert_eq!(parse_flag(body, "Set-Genesis-Author"), Some("alice".to_string()));
        assert_eq!(parse_flag(body, "Some-Other-Flag"), Some("value".to_string()));
    }
}
