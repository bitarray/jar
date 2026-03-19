//! PVM benchmark: grey interpreter/recompiler vs polkavm interpreter/compiler.
//!
//! Four workloads:
//!   - fib: compute-intensive iterative Fibonacci (1M iterations)
//!   - hostcall: host-call-heavy (100K ecalli invocations)
//!   - sort: insertion sort of 1K u32 elements (compute + memory interleaved)
//!   - ecrecover: secp256k1 ECDSA public key recovery (crypto-heavy)
//!
//! ## Benchmark fairness
//!
//! Both grey and polkavm recompiler benchmarks include compilation + execution in
//! each iteration. This is the realistic scenario for JAM: each work-package
//! arrives as a blob that must be compiled and executed. Caching compiled code
//! across invocations is a separate optimization.
//!
//! The interpreter benchmarks also re-parse the blob each iteration for the same
//! reason.

use criterion::{criterion_group, criterion_main, Criterion};
use grey_bench::*;

const GAS_LIMIT: u64 = 100_000_000;

// ---------------------------------------------------------------------------
// Grey-PVM interpreter runner (parse + execute)
// ---------------------------------------------------------------------------

fn run_grey_interpreter(blob: &[u8]) -> (u64, u64) {
    let mut pvm = javm::program::initialize_program(blob, &[], GAS_LIMIT).unwrap();
    loop {
        let (exit, _) = pvm.run();
        match exit {
            javm::ExitReason::Halt => break,
            javm::ExitReason::HostCall(_) => continue,
            other => panic!("unexpected exit: {:?}", other),
        }
    }
    let result = pvm.registers[7]; // A0
    let consumed = GAS_LIMIT - pvm.gas;
    (result, consumed)
}

// ---------------------------------------------------------------------------
// Grey-PVM recompiler runner (compile + execute)
// ---------------------------------------------------------------------------

fn run_grey_recompiler(blob: &[u8]) -> (u64, u64) {
    let mut pvm =
        javm::recompiler::initialize_program_recompiled(blob, &[], GAS_LIMIT).unwrap();
    loop {
        match pvm.run() {
            javm::ExitReason::Halt => break,
            javm::ExitReason::HostCall(_) => continue,
            other => panic!("unexpected exit: {:?}", other),
        }
    }
    let result = pvm.registers()[7]; // A0
    let consumed = GAS_LIMIT - pvm.gas();
    (result, consumed)
}

// ---------------------------------------------------------------------------
// PolkaVM runners
// ---------------------------------------------------------------------------

use polkavm::{BackendKind, Config, Engine, GasMeteringKind, InterruptKind, Module, ModuleConfig, SandboxKind};
use polkavm_common::program::Reg as PReg;

fn polkavm_config(backend: BackendKind) -> Config {
    let mut config = Config::from_env().unwrap_or_else(|_| Config::new());
    config.set_backend(Some(backend));
    config.set_allow_experimental(true);
    // Don't override sandboxing if env explicitly set it
    if std::env::var_os("POLKAVM_SANDBOXING_ENABLED").is_none() {
        config.set_sandboxing_enabled(false);
    }
    #[cfg(feature = "polkavm-generic-sandbox")]
    if std::env::var_os("POLKAVM_SANDBOX").is_none() {
        config.set_sandbox(Some(SandboxKind::Generic));
    }
    config
}

fn try_make_polkavm_module(blob: &[u8], backend: BackendKind) -> Option<(Engine, Module)> {
    let config = polkavm_config(backend);
    let engine = match Engine::new(&config) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("polkavm Engine::new({backend:?}) failed: {e}");
            return None;
        }
    };

    let mut mc = ModuleConfig::new();
    mc.set_gas_metering(Some(GasMeteringKind::Sync));
    let module = Module::new(&engine, &mc, blob.to_vec().into()).ok()?;
    Some((engine, module))
}

/// Execute an already-compiled polkavm module (execution only, no compilation).
fn run_polkavm_module(module: &Module) -> (u64, i64) {
    let mut inst = module.instantiate().unwrap();
    inst.set_gas(GAS_LIMIT as i64);
    if let Some(export) = module.exports().next() {
        inst.set_next_program_counter(export.program_counter());
    }
    inst.set_reg(PReg::RA, 0xFFFF0000u64);
    inst.set_reg(PReg::SP, module.default_sp());
    loop {
        match inst.run().unwrap() {
            InterruptKind::Finished => break,
            InterruptKind::Ecalli(_) => continue,
            InterruptKind::Trap => panic!("polkavm trap"),
            InterruptKind::NotEnoughGas => panic!("polkavm out of gas"),
            other => panic!("polkavm unexpected: {:?}", other),
        }
    }
    (inst.reg(PReg::A0), inst.gas())
}

/// Compile + execute a polkavm blob from scratch (full pipeline, fair comparison).
fn run_polkavm_compile_and_run(blob: &[u8], engine: &Engine) -> (u64, i64) {
    let mut mc = ModuleConfig::new();
    mc.set_gas_metering(Some(GasMeteringKind::Sync));
    let module = Module::new(engine, &mc, blob.to_vec().into()).unwrap();
    run_polkavm_module(&module)
}

// ---------------------------------------------------------------------------
// Correctness validation
// ---------------------------------------------------------------------------

fn validate(name: &str, grey_blob: &[u8], pvm_blob: &[u8]) {
    let (gi_result, gi_gas) = run_grey_interpreter(grey_blob);

    let (_, pvm_module) = try_make_polkavm_module(pvm_blob, BackendKind::Interpreter)
        .expect("polkavm interpreter should always work");
    let (pvm_result, pvm_remaining) = run_polkavm_module(&pvm_module);
    let pvm_gas = GAS_LIMIT as i64 - pvm_remaining;
    eprintln!(
        "{name}: grey result={gi_result} gas={gi_gas}, polkavm result={pvm_result} gas={pvm_gas}"
    );
    assert_eq!(
        gi_result, pvm_result,
        "{name}: grey/polkavm result mismatch"
    );
    // Gas values differ: JAVM uses pipeline gas (JAR v0.8.0),
    // polkavm uses per-instruction gas (GP v0.7.2).
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_fib(c: &mut Criterion) {
    let grey_blob = grey_fib_blob(FIB_N);
    let pvm_blob = polkavm_fib_blob(FIB_N);

    validate("fib", &grey_blob, &pvm_blob);

    let (_, pvm_interp_mod) = try_make_polkavm_module(&pvm_blob, BackendKind::Interpreter)
        .expect("polkavm interpreter should always work");
    let pvm_compiler = try_make_polkavm_module(&pvm_blob, BackendKind::Compiler);
    if pvm_compiler.is_none() {
        eprintln!("polkavm compiler backend unavailable (sandbox/platform restriction), skipping");
    }

    let mut group = c.benchmark_group("fib");

    group.bench_function("grey-interpreter", |b| {
        b.iter(|| run_grey_interpreter(&grey_blob))
    });

    group.bench_function("grey-recompiler", |b| {
        b.iter(|| run_grey_recompiler(&grey_blob))
    });

    group.bench_function("polkavm-interpreter", |b| {
        b.iter(|| run_polkavm_module(&pvm_interp_mod))
    });

    if let Some((ref engine, ref pvm_mod)) = pvm_compiler {
        // Execution-only (pre-compiled module, amortized compilation cost)
        group.bench_function("polkavm-compiler-exec", |b| {
            b.iter(|| run_polkavm_module(pvm_mod))
        });
        // Compile + execute (fair comparison with grey-recompiler)
        group.bench_function("polkavm-compiler-full", |b| {
            b.iter(|| run_polkavm_compile_and_run(&pvm_blob, engine))
        });
    }

    group.finish();
}

fn bench_hostcall(c: &mut Criterion) {
    let grey_blob = grey_hostcall_blob(HOSTCALL_N);
    let pvm_blob = polkavm_hostcall_blob(HOSTCALL_N);

    validate("hostcall", &grey_blob, &pvm_blob);

    let (_, pvm_interp_mod) = try_make_polkavm_module(&pvm_blob, BackendKind::Interpreter)
        .expect("polkavm interpreter should always work");
    let pvm_compiler = try_make_polkavm_module(&pvm_blob, BackendKind::Compiler);

    let mut group = c.benchmark_group("hostcall");

    group.bench_function("grey-interpreter", |b| {
        b.iter(|| run_grey_interpreter(&grey_blob))
    });

    group.bench_function("grey-recompiler", |b| {
        b.iter(|| run_grey_recompiler(&grey_blob))
    });

    group.bench_function("polkavm-interpreter", |b| {
        b.iter(|| run_polkavm_module(&pvm_interp_mod))
    });

    if let Some((ref engine, ref pvm_mod)) = pvm_compiler {
        group.bench_function("polkavm-compiler-exec", |b| {
            b.iter(|| run_polkavm_module(pvm_mod))
        });
        group.bench_function("polkavm-compiler-full", |b| {
            b.iter(|| run_polkavm_compile_and_run(&pvm_blob, engine))
        });
    }

    group.finish();
}

fn bench_sort(c: &mut Criterion) {
    let grey_blob = grey_sort_blob(SORT_N);
    let pvm_blob = polkavm_sort_blob(SORT_N);

    validate("sort", &grey_blob, &pvm_blob);

    let (_, pvm_interp_mod) = try_make_polkavm_module(&pvm_blob, BackendKind::Interpreter)
        .expect("polkavm interpreter should always work");
    let pvm_compiler = try_make_polkavm_module(&pvm_blob, BackendKind::Compiler);

    let mut group = c.benchmark_group("sort");

    group.bench_function("grey-interpreter", |b| {
        b.iter(|| run_grey_interpreter(&grey_blob))
    });

    group.bench_function("grey-recompiler", |b| {
        b.iter(|| run_grey_recompiler(&grey_blob))
    });

    group.bench_function("polkavm-interpreter", |b| {
        b.iter(|| run_polkavm_module(&pvm_interp_mod))
    });

    if let Some((ref engine, ref pvm_mod)) = pvm_compiler {
        group.bench_function("polkavm-compiler-exec", |b| {
            b.iter(|| run_polkavm_module(pvm_mod))
        });
        group.bench_function("polkavm-compiler-full", |b| {
            b.iter(|| run_polkavm_compile_and_run(&pvm_blob, engine))
        });
    }

    group.finish();
}

fn bench_ecrecover(c: &mut Criterion) {
    let grey_blob = grey_ecrecover_blob();
    let pvm_blob = polkavm_ecrecover_blob();
    let ecrecover_gas: u64 = i64::MAX as u64;

    let pvm_compiler = try_make_polkavm_module(&pvm_blob, BackendKind::Compiler);

    let mut group = c.benchmark_group("ecrecover");
    group.sample_size(10); // ecrecover is slow — fewer samples

    // Native baseline: run k256 ecrecover directly on the host CPU
    group.bench_function("native", |b| {
        b.iter(|| {
            use k256::ecdsa::{Signature, RecoveryId, VerifyingKey};
            let msg: [u8; 32] = [
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
                0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
                0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            ];
            let sig_bytes: [u8; 64] = [
                0xff, 0x65, 0x1c, 0x65, 0xee, 0xde, 0xd4, 0x63,
                0x83, 0xa4, 0xbd, 0xcd, 0x91, 0x70, 0xff, 0x65,
                0x9a, 0x4f, 0x61, 0x7b, 0xb6, 0x58, 0xa4, 0x6d,
                0xd4, 0x56, 0xc5, 0x1e, 0xc8, 0xcc, 0x21, 0x1a,
                0x7d, 0xc4, 0xde, 0x91, 0xd0, 0xc8, 0x47, 0xbf,
                0x5d, 0xef, 0x99, 0x5b, 0xd0, 0x43, 0x65, 0x81,
                0x36, 0xfe, 0x21, 0x35, 0xaf, 0xe6, 0x92, 0x82,
                0xf7, 0xde, 0x87, 0x39, 0x90, 0xda, 0xcb, 0x77,
            ];
            let sig = Signature::from_slice(&sig_bytes).unwrap();
            let recid = RecoveryId::new(true, false);
            let key = VerifyingKey::recover_from_prehash(&msg, &sig, recid).unwrap();
            std::hint::black_box(key);
        })
    });

    group.bench_function("grey-interpreter", |b| {
        b.iter(|| {
            let mut pvm = javm::program::initialize_program(
                &grey_blob, &[], ecrecover_gas,
            ).unwrap();
            loop {
                let (exit, _) = pvm.run();
                match exit {
                    javm::ExitReason::Halt | javm::ExitReason::Panic => break,
                    javm::ExitReason::HostCall(_) => continue,
                    other => panic!("unexpected exit: {:?}", other),
                }
            }
            pvm.registers[7]
        })
    });

    group.bench_function("grey-recompiler", |b| {
        b.iter(|| {
            let mut pvm = javm::recompiler::initialize_program_recompiled(
                &grey_blob, &[], ecrecover_gas,
            ).unwrap();
            loop {
                match pvm.run() {
                    javm::ExitReason::Halt | javm::ExitReason::Panic => break,
                    javm::ExitReason::HostCall(_) => continue,
                    other => panic!("unexpected exit: {:?}", other),
                }
            }
            pvm.registers()[7]
        })
    });

    let pvm_interp = try_make_polkavm_module(&pvm_blob, BackendKind::Interpreter);
    if let Some((_, ref pvm_interp_mod)) = pvm_interp {
        group.bench_function("polkavm-interpreter", |b| {
            b.iter(|| {
                let mut inst = pvm_interp_mod.instantiate().unwrap();
                inst.set_gas(ecrecover_gas as i64);
                if let Some(export) = pvm_interp_mod.exports().next() {
                    inst.set_next_program_counter(export.program_counter());
                }
                inst.set_reg(PReg::RA, 0xFFFF0000u64);
                inst.set_reg(PReg::SP, pvm_interp_mod.default_sp());
                loop {
                    match inst.run().unwrap() {
                        InterruptKind::Finished => break,
                        InterruptKind::Ecalli(_) => continue,
                        InterruptKind::Trap => break,
                        InterruptKind::NotEnoughGas => panic!("polkavm out of gas"),
                        other => panic!("polkavm unexpected: {:?}", other),
                    }
                }
                inst.reg(PReg::A0)
            })
        });
    }

    if let Some((ref engine, ref pvm_mod)) = pvm_compiler {
        group.bench_function("polkavm-compiler-exec", |b| {
            b.iter(|| {
                let mut inst = pvm_mod.instantiate().unwrap();
                inst.set_gas(ecrecover_gas as i64);
                if let Some(export) = pvm_mod.exports().next() {
                    inst.set_next_program_counter(export.program_counter());
                }
                inst.set_reg(PReg::RA, 0xFFFF0000u64);
                inst.set_reg(PReg::SP, pvm_mod.default_sp());
                loop {
                    match inst.run().unwrap() {
                        InterruptKind::Finished => break,
                        InterruptKind::Ecalli(_) => continue,
                        InterruptKind::Trap => break, // exported functions TRAP on return
                        InterruptKind::NotEnoughGas => panic!("polkavm out of gas"),
                        other => panic!("polkavm unexpected: {:?}", other),
                    }
                }
                inst.reg(PReg::A0)
            })
        });
        group.bench_function("polkavm-compiler-full", |b| {
            b.iter(|| {
                let mut mc = ModuleConfig::new();
                mc.set_gas_metering(Some(GasMeteringKind::Sync));
                let module = Module::new(engine, &mc, pvm_blob.clone().into()).unwrap();
                let mut inst = module.instantiate().unwrap();
                inst.set_gas(ecrecover_gas as i64);
                if let Some(export) = module.exports().next() {
                    inst.set_next_program_counter(export.program_counter());
                }
                inst.set_reg(PReg::RA, 0xFFFF0000u64);
                inst.set_reg(PReg::SP, module.default_sp());
                loop {
                    match inst.run().unwrap() {
                        InterruptKind::Finished => break,
                        InterruptKind::Ecalli(_) => continue,
                        InterruptKind::Trap => break, // exported functions TRAP on return
                        InterruptKind::NotEnoughGas => panic!("polkavm out of gas"),
                        other => panic!("polkavm unexpected: {:?}", other),
                    }
                }
                inst.reg(PReg::A0)
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_fib, bench_hostcall, bench_sort, bench_ecrecover);
criterion_main!(benches);
