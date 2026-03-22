//! Jar Differential Fuzzer
//!
//! Two-process comparison harness: generates random JSON inputs, invokes both
//! Jar (oracle) and an implementation-under-test via subprocess, and compares
//! JSON outputs. Any divergence is a bug.
//!
//! Also supports `--generate-only` mode to produce test vectors from Jar alone.
//!
//! Usage:
//!   jar-fuzz --jar-bin <path> --sub-transition safrole --seed 42 --steps 100
//!            [--impl-bin <path>]
//!            [--generate-only --output-dir <dir>]

use clap::Parser;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

mod gen;

#[derive(Parser)]
#[command(name = "jar-fuzz", about = "Differential fuzzer for JAM STF")]
struct Args {
    /// Path to the Jar STF binary (oracle)
    #[arg(long)]
    jar_bin: PathBuf,

    /// Path to the implementation-under-test binary (optional)
    #[arg(long)]
    impl_bin: Option<PathBuf>,

    /// Sub-transition to test
    #[arg(long)]
    sub_transition: String,

    /// Random seed
    #[arg(long, default_value_t = 42)]
    seed: u64,

    /// Number of test steps
    #[arg(long, default_value_t = 100)]
    steps: u64,

    /// Generate test vectors only (no comparison)
    #[arg(long)]
    generate_only: bool,

    /// Output directory for generated vectors
    #[arg(long)]
    output_dir: Option<PathBuf>,

    /// Input directory of existing JSON test vectors to use instead of random generation
    #[arg(long)]
    input_dir: Option<PathBuf>,
}

/// XorShift64 PRNG — simple, reproducible, no external dependency.
struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_u8(&mut self) -> u8 {
        (self.next_u64() & 0xFF) as u8
    }

    fn gen_bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u8()).collect()
    }

    fn gen_hex(&mut self, n: usize) -> String {
        let bytes = self.gen_bytes(n);
        format!("0x{}", hex::encode(&bytes))
    }

    fn gen_range(&mut self, lo: u64, hi: u64) -> u64 {
        if lo >= hi {
            return lo;
        }
        lo + self.next_u64() % (hi - lo)
    }

    fn gen_bool(&mut self) -> bool {
        self.next_u64() & 1 == 0
    }
}

/// Run a binary with a JSON input file and return parsed JSON output.
fn run_stf(bin: &Path, sub_transition: &str, input_path: &Path) -> Result<Value, String> {
    let output = Command::new(bin)
        .args([sub_transition, input_path.to_str().unwrap()])
        .output()
        .map_err(|e| format!("failed to run {}: {}", bin.display(), e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "{} exited with {}: {}",
            bin.display(),
            output.status,
            stderr
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .map_err(|e| format!("failed to parse JSON from {}: {}", bin.display(), e))
}

/// Recursively compare two JSON values, returning a description of the first difference.
fn json_diff(path: &str, a: &Value, b: &Value) -> Option<String> {
    match (a, b) {
        (Value::Object(ma), Value::Object(mb)) => {
            for key in ma.keys().chain(mb.keys()) {
                let va = ma.get(key);
                let vb = mb.get(key);
                match (va, vb) {
                    (Some(va), Some(vb)) => {
                        if let Some(diff) = json_diff(&format!("{path}.{key}"), va, vb) {
                            return Some(diff);
                        }
                    }
                    (Some(_), None) => {
                        return Some(format!("{path}.{key}: present in oracle, missing in impl"))
                    }
                    (None, Some(_)) => {
                        return Some(format!("{path}.{key}: missing in oracle, present in impl"))
                    }
                    (None, None) => unreachable!(),
                }
            }
            None
        }
        (Value::Array(aa), Value::Array(ab)) => {
            if aa.len() != ab.len() {
                return Some(format!(
                    "{path}: array length {}/{}",
                    aa.len(),
                    ab.len()
                ));
            }
            for (i, (va, vb)) in aa.iter().zip(ab.iter()).enumerate() {
                if let Some(diff) = json_diff(&format!("{path}[{i}]"), va, vb) {
                    return Some(diff);
                }
            }
            None
        }
        _ => {
            if a != b {
                Some(format!("{path}: {a} != {b}"))
            } else {
                None
            }
        }
    }
}

fn main() {
    let args = Args::parse();

    // Collect input files if using existing vectors
    let input_files: Vec<PathBuf> = if let Some(ref dir) = args.input_dir {
        let mut files: Vec<PathBuf> = fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("cannot read {}: {}", dir.display(), e))
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.to_str().is_some_and(|s| s.ends_with(".input.json")))
            .collect();
        files.sort();
        files
    } else {
        vec![]
    };

    if let Some(ref dir) = args.output_dir {
        fs::create_dir_all(dir)
            .unwrap_or_else(|e| panic!("cannot create {}: {}", dir.display(), e));
    }

    let mut rng = Rng::new(args.seed);
    let steps = if !input_files.is_empty() {
        input_files.len() as u64
    } else {
        args.steps
    };

    let mut divergences = 0u64;
    let tmp_dir = std::env::temp_dir().join("jar-fuzz");
    fs::create_dir_all(&tmp_dir).ok();

    for step in 0..steps {
        // Get or generate input JSON
        let input_path = if !input_files.is_empty() {
            input_files[step as usize].clone()
        } else {
            let input_json = gen::generate_input(&mut rng, &args.sub_transition);
            let path = tmp_dir.join(format!("step-{step}.json"));
            fs::write(&path, serde_json::to_string_pretty(&input_json).unwrap()).unwrap();
            path
        };

        // Run Jar (oracle)
        let jar_result = run_stf(&args.jar_bin, &args.sub_transition, &input_path);
        let jar_output = match jar_result {
            Ok(v) => v,
            Err(e) => {
                eprintln!("step {step}: jar error: {e}");
                continue;
            }
        };

        if args.generate_only {
            // Write input + output as separate files
            if let Some(ref dir) = args.output_dir {
                let input_json: Value =
                    serde_json::from_str(&fs::read_to_string(&input_path).unwrap()).unwrap();
                let name = format!("{}-seed{}-step{step}", args.sub_transition, args.seed);
                let input_out = dir.join(format!("{name}.input.json"));
                let output_out = dir.join(format!("{name}.output.json"));
                fs::write(
                    &input_out,
                    serde_json::to_string_pretty(&input_json).unwrap(),
                )
                .unwrap();
                fs::write(
                    &output_out,
                    serde_json::to_string_pretty(&jar_output).unwrap(),
                )
                .unwrap();
            } else {
                println!("{}", serde_json::to_string_pretty(&jar_output).unwrap());
            }
            continue;
        }

        // Run implementation under test
        if let Some(ref impl_bin) = args.impl_bin {
            let impl_result = run_stf(impl_bin, &args.sub_transition, &input_path);
            let impl_output = match impl_result {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("step {step}: impl error: {e}");
                    divergences += 1;
                    continue;
                }
            };

            if let Some(diff) = json_diff("$", &jar_output, &impl_output) {
                eprintln!(
                    "DIVERGENCE at step {step} (seed {}): {diff}",
                    args.seed
                );
                // Save failing vector
                let fail_dir = tmp_dir.join("failures");
                fs::create_dir_all(&fail_dir).ok();
                let name = format!("fail-seed{}-step{step}", args.seed);
                fs::write(
                    fail_dir.join(format!("{name}.input.json")),
                    fs::read_to_string(&input_path).unwrap(),
                )
                .ok();
                fs::write(
                    fail_dir.join(format!("{name}.jar.json")),
                    serde_json::to_string_pretty(&jar_output).unwrap(),
                )
                .ok();
                fs::write(
                    fail_dir.join(format!("{name}.impl.json")),
                    serde_json::to_string_pretty(&impl_output).unwrap(),
                )
                .ok();
                divergences += 1;
            }
        }
    }

    if divergences > 0 {
        eprintln!(
            "FAILED: {divergences} divergences in {steps} steps (seed {})",
            args.seed
        );
        std::process::exit(1);
    } else {
        println!(
            "OK: {steps} steps, seed {}, sub-transition: {}",
            args.seed, args.sub_transition
        );
    }
}
