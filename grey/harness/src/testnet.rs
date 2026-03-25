//! Testnet subprocess management.

use std::path::PathBuf;
use std::process::Stdio;

use tokio::process::{Child, Command};
use tracing::info;

/// A running grey testnet subprocess. Killed on drop.
pub struct TestnetProcess {
    child: Child,
    log_path: PathBuf,
}

impl TestnetProcess {
    /// Spawn `grey --testnet 0 --rpc-cors`, writing output to a log file.
    pub async fn spawn() -> Result<Self, Box<dyn std::error::Error>> {
        let grey_bin = Self::find_binary()?;
        let log_path = std::env::temp_dir().join("grey-harness-testnet.log");
        let log_file = std::fs::File::create(&log_path)?;
        let log_stderr = log_file.try_clone()?;

        info!("starting testnet (bin={}, log={})", grey_bin.display(), log_path.display());

        let child = Command::new(&grey_bin)
            .args(["--testnet", "0", "--rpc-cors"])
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_stderr))
            .kill_on_drop(true)
            .spawn()?;

        Ok(Self { child, log_path })
    }

    pub fn log_path(&self) -> &PathBuf {
        &self.log_path
    }

    /// Shut down the testnet.
    pub async fn kill(&mut self) {
        let _ = self.child.kill().await;
    }

    /// Find the grey binary. Checks target/debug first, then target/release.
    fn find_binary() -> Result<PathBuf, Box<dyn std::error::Error>> {
        // Workspace root is two levels up from the harness crate directory (grey/harness/).
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let workspace_root = PathBuf::from(manifest_dir)
            .parent()
            .and_then(|p| p.parent())
            .expect("harness must be inside workspace")
            .to_path_buf();

        for profile in ["debug", "release"] {
            let bin = workspace_root.join("target").join(profile).join("grey");
            if bin.exists() {
                return Ok(bin);
            }
        }
        Err("grey binary not found in target/debug or target/release — run `cargo build -p grey` first".into())
    }
}
