use std::path::Path;
use std::process::Command;

use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LeanError {
    #[error("lean tool '{tool}' failed: {message}")]
    ToolFailed { tool: String, message: String },
    #[error("lean tool '{tool}' not found at {path}")]
    NotFound { tool: String, path: String },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Invoke a Lean genesis CLI tool by piping JSON to stdin and reading JSON from stdout.
pub fn invoke<I: Serialize, O: DeserializeOwned>(
    tool: &str,
    input: &I,
    spec_dir: &Path,
) -> Result<O, LeanError> {
    let bin_path = spec_dir.join(".lake/build/bin").join(tool);
    if !bin_path.exists() {
        return Err(LeanError::NotFound {
            tool: tool.to_string(),
            path: bin_path.display().to_string(),
        });
    }

    let input_json = serde_json::to_string(input)?;
    let output = Command::new(&bin_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(input_json.as_bytes())?;
            }
            child.wait_with_output()
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(LeanError::ToolFailed {
            tool: tool.to_string(),
            message: stderr.trim().to_string(),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(serde_json::from_str(stdout.trim())?)
}
