//! PVM benchmark: grey interpreter/recompiler vs polkavm interpreter/compiler.
//!
//! Three workloads:
//!   - fib: compute-intensive iterative Fibonacci (1M iterations)
//!   - hostcall: host-call-heavy (100K ecalli invocations)
//!   - sort: insertion sort of 1K u32 elements (compute + memory interleaved)
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
    let mut config = Config::new();
    config.set_backend(Some(backend));
    config.set_allow_experimental(true);
    config.set_sandboxing_enabled(false);
    #[cfg(feature = "polkavm-generic-sandbox")]
    config.set_sandbox(Some(SandboxKind::Generic));
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
    assert_eq!(
        gi_gas as i64, pvm_gas,
        "{name}: grey/polkavm gas mismatch"
    );
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

criterion_group!(benches, bench_fib, bench_hostcall, bench_sort);
criterion_main!(benches);
