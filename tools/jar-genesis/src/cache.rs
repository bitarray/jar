use std::path::Path;

use crate::git;

/// Check that cache length matches the number of Genesis-Index trailers in git history.
/// Returns Ok(()) if they match.
pub fn check_staleness(
    cache: &[serde_json::Value],
    spec_dir: &Path,
) -> Result<(), String> {
    let genesis_commit = git::read_genesis_commit_hash(spec_dir)
        .map_err(|e| format!("failed to read genesis commit: {e}"))?;

    if genesis_commit == "0000000000000000000000000000000000000000" {
        return Ok(()); // Genesis not launched
    }

    let history_count = git::count_genesis_trailers(&genesis_commit)
        .map_err(|e| format!("failed to count trailers: {e}"))?;

    if cache.len() != history_count {
        return Err(format!(
            "{} entries cached, {} in git history",
            cache.len(),
            history_count
        ));
    }

    Ok(())
}

/// CLI entry point: check cache from a file path.
pub fn check(cache_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(cache_file)?;
    let cache: Vec<serde_json::Value> = serde_json::from_str(&content)?;

    let repo_root = git::repo_root()?;
    let spec_dir = Path::new(&repo_root).join("spec");

    match check_staleness(&cache, &spec_dir) {
        Ok(()) => Ok(()),
        Err(msg) => {
            eprintln!("ERROR: genesis cache stale — {msg}");
            std::process::exit(1);
        }
    }
}
