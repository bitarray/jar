use crate::git;

/// Check that the genesis cache length matches the number of Genesis-Index
/// trailers in git history. Returns Ok(()) if they match.
pub fn check(cache_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(cache_file)?;
    let cache: Vec<serde_json::Value> = serde_json::from_str(&content)?;

    let repo_root = git::repo_root()?;
    let spec_dir = std::path::Path::new(&repo_root).join("spec");
    let genesis_commit = git::read_genesis_commit_hash(&spec_dir)?;
    let history_count = git::count_genesis_trailers(&genesis_commit)?;

    if cache.len() != history_count {
        eprintln!(
            "ERROR: genesis cache stale — {} entries cached, {} in git history",
            cache.len(),
            history_count
        );
        std::process::exit(1);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    // Integration tests require a git repo — use #[ignore]
}
