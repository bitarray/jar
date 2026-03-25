//! Integration tests for Lean tool wire format compatibility.
//! These tests require Lean binaries built via `cd spec && lake build genesis_*`.
//! Run with: cargo test -p jar-genesis -- --ignored

use std::path::PathBuf;

use jar_genesis::lean;
use jar_genesis::types::*;

fn spec_dir() -> PathBuf {
    let root = jar_genesis::git::repo_root().expect("not in a git repo");
    PathBuf::from(root).join("spec")
}

#[test]
#[ignore]
fn test_select_targets_empty_indices() {
    let input = serde_json::json!({
        "prId": 999,
        "prCreatedAt": 9999999999u64,
        "indices": [],
        "ranking": [],
    });
    let output: SelectTargetsOutput =
        lean::invoke("genesis_select_targets", &input, &spec_dir()).unwrap();
    assert!(output.targets.is_empty());
}

#[test]
#[ignore]
fn test_select_targets_with_real_cache() {
    // Load the real cache + ranking and verify targets are selected
    let spec = spec_dir();
    jar_genesis::git::fetch("origin", "genesis-state").unwrap();
    let cache_json = jar_genesis::git::show_file("origin/genesis-state:genesis.json").unwrap();
    let cache: Vec<serde_json::Value> = serde_json::from_str(&cache_json).unwrap();
    let ranking_json = jar_genesis::git::show_file("origin/genesis-state:ranking.json")
        .unwrap_or_else(|_| "{}".to_string());
    let ranking: serde_json::Value = serde_json::from_str(&ranking_json).unwrap();

    assert!(!cache.is_empty(), "cache should not be empty");

    // Find the ranking snapshot for the last index
    let last_hash = cache.last().unwrap()["commitHash"].as_str().unwrap();
    let ranking_snapshot = ranking.get(last_hash).cloned().unwrap_or(serde_json::json!([]));

    let input = serde_json::json!({
        "prId": 999,
        "prCreatedAt": 9999999999u64,
        "indices": cache,
        "ranking": ranking_snapshot,
    });
    let output: SelectTargetsOutput =
        lean::invoke("genesis_select_targets", &input, &spec).unwrap();
    assert_eq!(output.targets.len(), 7, "should select 7 comparison targets");
    for target in &output.targets {
        assert_eq!(target.len(), 40, "target should be 40-char hex hash: {target}");
    }
}

#[test]
#[ignore]
fn test_check_merge_no_reviews() {
    let input = serde_json::json!({
        "reviews": [],
        "metaReviews": [],
        "indices": [],
    });
    let output: MergeReadiness =
        lean::invoke("genesis_check_merge", &input, &spec_dir()).unwrap();
    assert!(!output.ready);
    assert_eq!(output.merge_weight, 0);
}

#[test]
#[ignore]
fn test_check_merge_founder_review() {
    // Build a scenario with the founder reviewing (has weight from initEvalState)
    let spec = spec_dir();
    jar_genesis::git::fetch("origin", "genesis-state").unwrap();
    let cache_json = jar_genesis::git::show_file("origin/genesis-state:genesis.json").unwrap();
    let cache: Vec<serde_json::Value> = serde_json::from_str(&cache_json).unwrap();

    let review = EmbeddedReview {
        reviewer: "sorpaas".to_string(),
        difficulty_ranking: vec!["currentPR".to_string()],
        novelty_ranking: vec!["currentPR".to_string()],
        design_quality_ranking: vec!["currentPR".to_string()],
        verdict: Verdict::Merge,
    };

    let input = serde_json::json!({
        "reviews": [review],
        "metaReviews": [],
        "indices": cache,
    });
    let output: MergeReadiness =
        lean::invoke("genesis_check_merge", &input, &spec).unwrap();
    // Founder has weight — single merge vote should reach quorum
    assert!(output.ready, "founder review should reach quorum (mergeWeight={}, totalWeight={})",
        output.merge_weight, output.total_weight);
}

#[test]
#[ignore]
fn test_evaluate_minimal_commit() {
    let commit = serde_json::json!({
        "id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "prId": 999,
        "author": "testuser",
        "mergeEpoch": 1774000000u64,
        "comparisonTargets": [],
        "reviews": [{
            "reviewer": "sorpaas",
            "difficultyRanking": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            "noveltyRanking": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            "designQualityRanking": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            "verdict": "merge",
        }],
        "metaReviews": [],
        "founderOverride": false,
    });

    let input = serde_json::json!({
        "commit": commit,
        "pastIndices": [],
    });

    let output: serde_json::Value =
        lean::invoke("genesis_evaluate", &input, &spec_dir()).unwrap();

    // Verify output has expected fields
    assert_eq!(output["commitHash"], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(output["score"]["difficulty"].is_number());
    assert!(output["score"]["novelty"].is_number());
    assert!(output["score"]["designQuality"].is_number());
    assert!(output["weightDelta"].is_number());
    assert_eq!(output["contributor"], "testuser");
    assert_eq!(output["founderOverride"], false);
}

#[test]
#[ignore]
fn test_ranking_single_commit() {
    let commit = serde_json::json!({
        "id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "prId": 1,
        "author": "alice",
        "mergeEpoch": 1774000000u64,
        "comparisonTargets": [],
        "reviews": [],
        "metaReviews": [],
        "founderOverride": false,
    });
    let index = serde_json::json!({
        "commitHash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "epoch": 1774000000u64,
        "score": {"difficulty": 100, "novelty": 100, "designQuality": 100},
        "contributor": "alice",
        "weightDelta": 100,
        "reviewers": [],
        "metaReviews": [],
        "mergeVotes": [],
        "rejectVotes": [],
        "founderOverride": false,
    });

    let input = serde_json::json!({
        "signedCommits": [commit],
        "indices": [index],
    });

    let output: RankingOutput =
        lean::invoke("genesis_ranking", &input, &spec_dir()).unwrap();
    assert_eq!(output.ranking.len(), 1);
    assert_eq!(output.ranking[0], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
}
