//! Measurement-environment control.

/// Re-exec this process with ASLR disabled.
///
/// Address-space layout is the single largest source of run-to-run
/// variance for interpreters and JITs: it decides code and data
/// alignment, which decides i-cache set conflicts and branch-predictor
/// aliasing. Two runs of an identical binary can differ by several
/// percent purely from where the loader happened to put things — enough
/// to invent or hide a difference between two engines.
///
/// `personality(ADDR_NO_RANDOMIZE)` only affects children, so we set it
/// and `exec` ourselves. The `BENCH_COMPARE_NO_ASLR` marker stops the
/// recursion.
///
/// Must run before anything that reserves address space — some engines
/// map multi-gigabyte guard regions at startup and never move them.
pub fn disable_aslr_and_restart() {
    #[cfg(target_os = "linux")]
    {
        const ADDR_NO_RANDOMIZE: libc::c_ulong = 0x0004_0000;
        const MARKER: &str = "BENCH_COMPARE_NO_ASLR";

        if std::env::var_os(MARKER).is_some() {
            return;
        }

        // Querying with 0xffff_ffff returns the current persona without
        // changing it; a failure here means the syscall is unavailable
        // (a restrictive seccomp filter, say), so measure anyway rather
        // than refusing to run.
        let current = unsafe { libc::personality(0xffff_ffff) };
        if current < 0 {
            return;
        }
        if unsafe { libc::personality(current as libc::c_ulong | ADDR_NO_RANDOMIZE) } < 0 {
            return;
        }

        let exe = match std::env::current_exe() {
            Ok(p) => p,
            Err(_) => return,
        };
        let args: Vec<String> = std::env::args().skip(1).collect();
        let err = std::process::Command::new(exe)
            .args(args)
            .env(MARKER, "1")
            .exec_replace();
        // Only reached if exec failed; carry on with ASLR enabled.
        let _ = err;
    }
}

#[cfg(target_os = "linux")]
trait ExecReplace {
    fn exec_replace(&mut self) -> std::io::Error;
}

#[cfg(target_os = "linux")]
impl ExecReplace for std::process::Command {
    fn exec_replace(&mut self) -> std::io::Error {
        use std::os::unix::process::CommandExt;
        self.exec()
    }
}
