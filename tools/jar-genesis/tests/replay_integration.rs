//! Integration tests for replay and cache verification.
//! These tests require full git history + Lean binaries.
//! Run with: cargo test -p jar-genesis -- --ignored

use std::path::PathBuf;

fn spec_dir() -> PathBuf {
    let root = jar_genesis::git::repo_root().expect("not in a git repo");
    PathBuf::from(root).join("spec")
}

#[test]
#[ignore]
fn test_replay_verify() {
    jar_genesis::replay::verify().expect("replay --verify failed");
}

#[test]
#[ignore]
fn test_replay_verify_cache() {
    jar_genesis::replay::verify_cache().expect("replay --verify-cache failed");
}

#[test]
#[ignore]
fn test_cache_check_current_repo() {
    let spec = spec_dir();
    jar_genesis::git::fetch("origin", "genesis-state").expect("failed to fetch genesis-state");
    let cache_json =
        jar_genesis::git::show_file("origin/genesis-state:genesis.json").expect("no cache");
    let cache: Vec<serde_json::Value> = serde_json::from_str(&cache_json).unwrap();

    jar_genesis::cache::check_staleness(&cache, &spec)
        .expect("cache staleness check failed");
}

#[test]
#[ignore]
fn test_git_log_merge_commits_has_genesis_entries() {
    let spec = spec_dir();
    let genesis_commit = jar_genesis::git::read_genesis_commit_hash(&spec).unwrap();
    let commits = jar_genesis::git::log_merge_commits(&genesis_commit).unwrap();

    // Should have at least some genesis merge commits
    let genesis_count = commits
        .iter()
        .filter(|(_, msg)| jar_genesis::git::parse_trailer(msg, "Genesis-Index").is_some())
        .count();

    assert!(
        genesis_count > 50,
        "expected >50 genesis merges, got {genesis_count}"
    );
}

#[test]
#[ignore]
fn test_read_genesis_commit_hash() {
    let spec = spec_dir();
    let hash = jar_genesis::git::read_genesis_commit_hash(&spec).unwrap();
    assert_eq!(hash.len(), 40, "genesis commit should be 40-char hex");
    assert!(
        hash.chars().all(|c| c.is_ascii_hexdigit()),
        "genesis commit should be hex: {hash}"
    );
    assert_ne!(
        hash,
        "0000000000000000000000000000000000000000",
        "genesis should be launched"
    );
}
