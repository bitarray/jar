use std::collections::HashMap;
use std::path::Path;

use crate::git;
use crate::hash;
use crate::lean;
use crate::types::CommitIndex;

/// A parsed merge commit with genesis trailers.
struct GenesisCommitEntry {
    signed_commit: serde_json::Value,
    stored_index: serde_json::Value,
}

/// Walk merge commits and collect genesis entries.
fn collect_entries(
    genesis_commit: &str,
) -> Result<Vec<GenesisCommitEntry>, Box<dyn std::error::Error>> {
    let merge_commits = git::log_merge_commits(genesis_commit)?;
    let mut entries = Vec::new();

    for (hash, message) in &merge_commits {
        let index_json = match git::parse_trailer(message, "Genesis-Index") {
            Some(json) => json,
            None => continue, // Not a genesis merge commit
        };

        let commit_json = match git::parse_trailer(message, "Genesis-Commit") {
            Some(json) => json,
            None => {
                eprintln!(
                    "WARNING: No Genesis-Commit trailer for merge {hash}. Cannot replay."
                );
                // Still track the stored index
                let stored_index: serde_json::Value = serde_json::from_str(&index_json)?;
                entries.push(GenesisCommitEntry {
                    signed_commit: serde_json::Value::Null,
                    stored_index,
                });
                continue;
            }
        };

        // Parse and expand short hashes in review rankings
        let mut commit: serde_json::Value = serde_json::from_str(&commit_json)?;
        expand_review_hashes(&mut commit);

        let stored_index: serde_json::Value = serde_json::from_str(&index_json)?;
        entries.push(GenesisCommitEntry {
            signed_commit: commit,
            stored_index,
        });
    }

    Ok(entries)
}

/// Expand short hashes in review rankings to full hashes.
pub fn expand_review_hashes_public(commit: &mut serde_json::Value) {
    expand_review_hashes(commit);
}

fn expand_review_hashes(commit: &mut serde_json::Value) {
    let head = commit["id"].as_str().unwrap_or("").to_string();
    let targets: Vec<String> = commit["comparisonTargets"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let mut candidates = targets.clone();
    candidates.push(head.clone());

    if let Some(reviews) = commit["reviews"].as_array_mut() {
        for review in reviews {
            for field in &[
                "difficultyRanking",
                "noveltyRanking",
                "designQualityRanking",
            ] {
                if let Some(ranking) = review[*field].as_array_mut() {
                    for entry in ranking.iter_mut() {
                        if let Some(h) = entry.as_str() {
                            if h.len() < 40 {
                                if let Ok(full) = hash::expand_short_hash(h, &candidates) {
                                    *entry = serde_json::Value::String(full);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Get the ranking snapshot for a commit based on its epoch.
fn get_ranking_snapshot(
    indices: &[serde_json::Value],
    rankings: &HashMap<String, serde_json::Value>,
    epoch: u64,
) -> Option<serde_json::Value> {
    // Find the last index with epoch < target epoch
    let last = indices
        .iter()
        .filter(|idx| {
            idx["epoch"]
                .as_u64()
                .map(|e| e < epoch)
                .unwrap_or(false)
        })
        .last()?;

    let commit_hash = last["commitHash"].as_str()?;
    rankings.get(commit_hash).cloned()
}

/// Core incremental replay loop. Evaluates each signed commit incrementally.
/// Returns (rebuilt_indices, ranking_snapshots).
fn replay_incremental(
    spec_dir: &Path,
    signed_commits: &[serde_json::Value],
) -> Result<(Vec<serde_json::Value>, HashMap<String, serde_json::Value>), Box<dyn std::error::Error>>
{
    let mut indices: Vec<serde_json::Value> = Vec::new();
    let mut rankings: HashMap<String, serde_json::Value> = HashMap::new();
    let mut commits: Vec<serde_json::Value> = Vec::new();

    for commit in signed_commits {
        if commit.is_null() {
            continue;
        }

        let pr_created_at = commit["prCreatedAt"]
            .as_u64()
            .or_else(|| commit["mergeEpoch"].as_u64())
            .unwrap_or(0);

        let ranking_snapshot = get_ranking_snapshot(&indices, &rankings, pr_created_at);

        // Build input for genesis_evaluate
        let mut input = serde_json::json!({
            "commit": commit,
            "pastIndices": indices,
        });
        if let Some(ranking) = &ranking_snapshot {
            input["ranking"] = ranking.clone();
        }

        // Evaluate
        let mut index: serde_json::Value = lean::invoke("genesis_evaluate", &input, spec_dir)?;

        // Strip warnings for cache compatibility
        if let Some(obj) = index.as_object_mut() {
            obj.remove("warnings");
        }

        indices.push(index.clone());
        commits.push(commit.clone());

        // Compute ranking snapshot
        let ranking_input = serde_json::json!({
            "signedCommits": commits,
            "indices": indices,
        });
        let ranking_output: serde_json::Value =
            lean::invoke("genesis_ranking", &ranking_input, spec_dir)?;
        let snapshot = ranking_output["ranking"].clone();

        let commit_hash = index["commitHash"]
            .as_str()
            .unwrap_or("")
            .to_string();
        rankings.insert(commit_hash, snapshot);
    }

    Ok((indices, rankings))
}

fn spec_dir() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let root = git::repo_root()?;
    Ok(Path::new(&root).join("spec"))
}

/// Replay and verify genesis state from git history.
pub fn verify() -> Result<(), Box<dyn std::error::Error>> {
    let spec = spec_dir()?;
    let genesis_commit = git::read_genesis_commit_hash(&spec)?;

    if genesis_commit == "0000000000000000000000000000000000000000" {
        eprintln!("Genesis not launched (genesisCommit is zero).");
        return Ok(());
    }

    let entries = collect_entries(&genesis_commit)?;
    let signed_commits: Vec<serde_json::Value> =
        entries.iter().map(|e| e.signed_commit.clone()).collect();
    let stored_indices: Vec<serde_json::Value> =
        entries.iter().map(|e| e.stored_index.clone()).collect();

    let replayable: Vec<&serde_json::Value> =
        signed_commits.iter().filter(|c| !c.is_null()).collect();
    eprintln!(
        "Replaying {} of {} entries...",
        replayable.len(),
        stored_indices.len()
    );

    // Build ranking map incrementally
    let (_, rankings) = replay_incremental(&spec, &signed_commits)?;

    // Validate using genesis_validate
    let input = serde_json::json!({
        "indices": stored_indices,
        "signedCommits": signed_commits.iter().filter(|c| !c.is_null()).collect::<Vec<_>>(),
        "rankings": rankings,
    });

    let result: serde_json::Value = lean::invoke("genesis_validate", &input, &spec)?;
    println!("{}", serde_json::to_string_pretty(&result)?);

    let valid = result["valid"].as_bool().unwrap_or(false);
    let errors = result["errors"].as_array().map(|a| a.len()).unwrap_or(0);

    if valid {
        eprintln!(
            "Verified {} of {} indices. All match.",
            replayable.len(),
            stored_indices.len()
        );
        Ok(())
    } else {
        eprintln!(
            "Verification failed: {errors} errors in {} replayable indices.",
            replayable.len()
        );
        std::process::exit(1);
    }
}

/// Replay, rebuild, and compare against genesis-state cache.
pub fn verify_cache() -> Result<(), Box<dyn std::error::Error>> {
    let spec = spec_dir()?;
    let genesis_commit = git::read_genesis_commit_hash(&spec)?;

    if genesis_commit == "0000000000000000000000000000000000000000" {
        eprintln!("Genesis not launched (genesisCommit is zero).");
        return Ok(());
    }

    let entries = collect_entries(&genesis_commit)?;
    let signed_commits: Vec<serde_json::Value> =
        entries.iter().map(|e| e.signed_commit.clone()).collect();

    let replayable: Vec<&serde_json::Value> =
        signed_commits.iter().filter(|c| !c.is_null()).collect();

    let (rebuilt_indices, rebuilt_rankings) = replay_incremental(&spec, &signed_commits)?;

    // Fetch cache
    git::fetch("origin", "genesis-state")?;
    let cache_json = git::show_file("origin/genesis-state:genesis.json")?;
    let cache: Vec<serde_json::Value> = serde_json::from_str(&cache_json)?;

    if rebuilt_indices.len() != cache.len() {
        eprintln!(
            "MISMATCH: rebuilt {} indices but cache has {}.",
            rebuilt_indices.len(),
            cache.len()
        );
        std::process::exit(1);
    }

    let mut errors = 0;

    // Compare indices
    for i in 0..rebuilt_indices.len() {
        let r = serde_json::to_string(&rebuilt_indices[i])?;
        let c = serde_json::to_string(&cache[i])?;
        if r != c {
            let hash = rebuilt_indices[i]["commitHash"]
                .as_str()
                .unwrap_or("unknown");
            eprintln!("MISMATCH at index {i} (commit {hash}):");
            eprintln!("  rebuilt: {r}");
            eprintln!("  cache:   {c}");
            errors += 1;
        }
    }

    // Compare rankings
    let cached_ranking_json =
        git::show_file("origin/genesis-state:ranking.json").unwrap_or_else(|_| "{}".to_string());
    let cached_ranking: HashMap<String, serde_json::Value> =
        serde_json::from_str(&cached_ranking_json)?;

    if !cached_ranking.is_empty() {
        if rebuilt_rankings.len() != cached_ranking.len() {
            eprintln!(
                "RANKING MISMATCH: rebuilt {} entries but cache has {}.",
                rebuilt_rankings.len(),
                cached_ranking.len()
            );
            errors += 1;
        } else {
            for (key, rebuilt_val) in &rebuilt_rankings {
                if let Some(cached_val) = cached_ranking.get(key) {
                    let r = serde_json::to_string(rebuilt_val)?;
                    let c = serde_json::to_string(cached_val)?;
                    if r != c {
                        eprintln!("RANKING MISMATCH for commit {}:", &key[..8.min(key.len())]);
                        eprintln!("  rebuilt: {r}");
                        eprintln!("  cache:   {c}");
                        errors += 1;
                    }
                } else {
                    eprintln!("RANKING MISMATCH: key {} not in cache.", &key[..8.min(key.len())]);
                    errors += 1;
                }
            }
        }
    } else {
        eprintln!("ranking.json not found or empty — skipping ranking verification.");
    }

    if errors == 0 {
        eprintln!(
            "Cache verified: {} indices match rebuilt state.",
            rebuilt_indices.len()
        );
        Ok(())
    } else {
        eprintln!("Cache verification failed: {errors} mismatches.");
        std::process::exit(1);
    }
}

/// Replay and rebuild, outputting to stdout.
pub fn rebuild() -> Result<(), Box<dyn std::error::Error>> {
    let spec = spec_dir()?;
    let genesis_commit = git::read_genesis_commit_hash(&spec)?;

    if genesis_commit == "0000000000000000000000000000000000000000" {
        eprintln!("Genesis not launched (genesisCommit is zero).");
        return Ok(());
    }

    let entries = collect_entries(&genesis_commit)?;
    let signed_commits: Vec<serde_json::Value> =
        entries.iter().map(|e| e.signed_commit.clone()).collect();

    let (rebuilt_indices, rebuilt_rankings) = replay_incremental(&spec, &signed_commits)?;

    eprintln!("=== genesis.json ===");
    println!("{}", serde_json::to_string_pretty(&rebuilt_indices)?);
    eprintln!("=== ranking.json ===");
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!(rebuilt_rankings))?
    );
    eprintln!(
        "Rebuilt {} of {} indices.",
        rebuilt_indices.len(),
        entries.len()
    );

    Ok(())
}
