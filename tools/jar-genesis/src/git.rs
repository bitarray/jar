use std::path::Path;
use std::process::Command;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum GitError {
    #[error("git command failed: {0}")]
    CommandFailed(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Run a git command and return stdout as a string.
fn git(args: &[&str]) -> Result<String, GitError> {
    let output = Command::new("git").args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GitError::CommandFailed(format!(
            "git {} failed: {}",
            args.join(" "),
            stderr.trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Run a git command (public wrapper). Returns stdout.
pub fn git_cmd(args: &[&str]) -> Result<String, GitError> {
    git(args)
}

/// Run a git command in a specific directory. Returns stdout.
pub fn git_cmd_in(dir: &str, args: &[&str]) -> Result<String, GitError> {
    let output = Command::new("git").arg("-C").arg(dir).args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GitError::CommandFailed(format!(
            "git -C {dir} {} failed: {}",
            args.join(" "),
            stderr.trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Get merge commits from genesis_commit..HEAD, oldest first.
/// Returns (hash, full commit message) pairs.
pub fn log_merge_commits(genesis_commit: &str) -> Result<Vec<(String, String)>, GitError> {
    log_merge_commits_ref(genesis_commit, "HEAD")
}

/// Walk merge commits between `genesis_commit` and `end_ref` (e.g. "origin/master").
pub fn log_merge_commits_ref(
    genesis_commit: &str,
    end_ref: &str,
) -> Result<Vec<(String, String)>, GitError> {
    let range = format!("{genesis_commit}..{end_ref}");
    let hashes = git(&["log", "--merges", "--reverse", "--format=%H", &range])?;
    let mut result = Vec::new();
    for hash in hashes.lines() {
        let hash = hash.trim();
        if hash.is_empty() {
            continue;
        }
        let message = git(&["log", "-1", "--format=%B", hash])?;
        result.push((hash.to_string(), message));
    }
    Ok(result)
}

/// Show a file from a git ref (e.g. `origin/genesis-state:genesis.json`).
pub fn show_file(refspec: &str) -> Result<String, GitError> {
    git(&["show", refspec])
}

/// Fetch a remote branch.
pub fn fetch(remote: &str, branch: &str) -> Result<(), GitError> {
    git(&["fetch", remote, branch])?;
    Ok(())
}

/// Parse the root of the git repo.
pub fn repo_root() -> Result<String, GitError> {
    let root = git(&["rev-parse", "--show-toplevel"])?;
    Ok(root.trim().to_string())
}

/// Extract a trailer value from a commit message.
/// Trailers are lines like `Genesis-Commit: {...}` at the end of the message.
pub fn parse_trailer(message: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}: ");
    for line in message.lines() {
        if let Some(rest) = line.strip_prefix(&prefix) {
            return Some(rest.to_string());
        }
    }
    None
}

/// Count the number of Genesis-Index trailers in the merge history.
pub fn count_genesis_trailers(genesis_commit: &str) -> Result<usize, GitError> {
    let range = format!("{genesis_commit}..HEAD");
    let output = git(&["log", "--merges", "--format=%B", &range])?;
    let count = output
        .lines()
        .filter(|line| line.starts_with("Genesis-Index: "))
        .count();
    Ok(count)
}

/// Read the genesis commit hash from the Lean source file.
pub fn read_genesis_commit_hash(spec_dir: &Path) -> Result<String, GitError> {
    let state_file = spec_dir.join("Genesis/State.lean");
    let content = std::fs::read_to_string(&state_file).map_err(|e| {
        GitError::CommandFailed(format!("failed to read {}: {e}", state_file.display()))
    })?;
    for line in content.lines() {
        // Match: def genesisCommit := "..."
        if let Some(rest) = line.strip_prefix("def genesisCommit")
            && let Some(start) = rest.find('"')
            && let Some(end) = rest[start + 1..].find('"')
        {
            return Ok(rest[start + 1..start + 1 + end].to_string());
        }
    }
    Err(GitError::CommandFailed(
        "genesisCommit not found in Genesis/State.lean".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_trailer() {
        let msg = "Merge PR #97\n\nGenesis-Commit: {\"id\":\"abc\"}\nGenesis-Index: {\"commitHash\":\"abc\"}\n";
        assert_eq!(
            parse_trailer(msg, "Genesis-Commit"),
            Some("{\"id\":\"abc\"}".to_string())
        );
        assert_eq!(
            parse_trailer(msg, "Genesis-Index"),
            Some("{\"commitHash\":\"abc\"}".to_string())
        );
        assert_eq!(parse_trailer(msg, "Missing-Key"), None);
    }

    #[test]
    fn test_parse_trailer_no_trailers() {
        let msg = "Just a plain commit message\n";
        assert_eq!(parse_trailer(msg, "Genesis-Commit"), None);
    }

    #[test]
    fn test_parse_trailer_compact_json() {
        // Real-world trailer with compact JSON
        let msg = r#"Merge PR #97

Genesis-Commit: {"id":"abc","prId":97,"author":"alice","mergeEpoch":1000,"comparisonTargets":[],"reviews":[],"metaReviews":[],"founderOverride":false}
Genesis-Index: {"commitHash":"abc","epoch":1000,"score":{"difficulty":85,"novelty":100,"designQuality":85},"contributor":"alice","weightDelta":88,"reviewers":[],"metaReviews":[],"mergeVotes":[],"rejectVotes":[],"founderOverride":false}
Genesis-PR: #97
Genesis-Author: alice
"#;
        let commit = parse_trailer(msg, "Genesis-Commit").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&commit).unwrap();
        assert_eq!(parsed["id"], "abc");
        assert_eq!(parsed["prId"], 97);

        let index = parse_trailer(msg, "Genesis-Index").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&index).unwrap();
        assert_eq!(parsed["commitHash"], "abc");
        assert_eq!(parsed["score"]["difficulty"], 85);
    }

    #[test]
    fn test_parse_trailer_pr_number() {
        let msg = "Merge PR #42\n\nGenesis-PR: #42\n";
        assert_eq!(parse_trailer(msg, "Genesis-PR"), Some("#42".to_string()));
    }

    #[test]
    fn test_parse_trailer_only_index_no_commit() {
        // A merge commit that has Genesis-Index but no Genesis-Commit (shouldn't happen but test it)
        let msg = "Merge PR #1\n\nGenesis-Index: {\"commitHash\":\"abc\"}\n";
        assert!(parse_trailer(msg, "Genesis-Index").is_some());
        assert!(parse_trailer(msg, "Genesis-Commit").is_none());
    }
}
