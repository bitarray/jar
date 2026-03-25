/// Replay and verify genesis state from git history.
pub fn verify() -> Result<(), Box<dyn std::error::Error>> {
    // TODO: implement
    eprintln!("replay --verify: not yet implemented");
    std::process::exit(1);
}

/// Replay, rebuild, and compare against genesis-state cache.
pub fn verify_cache() -> Result<(), Box<dyn std::error::Error>> {
    // TODO: implement
    eprintln!("replay --verify-cache: not yet implemented");
    std::process::exit(1);
}

/// Replay and rebuild, outputting to stdout.
pub fn rebuild() -> Result<(), Box<dyn std::error::Error>> {
    // TODO: implement
    eprintln!("replay --rebuild: not yet implemented");
    std::process::exit(1);
}
