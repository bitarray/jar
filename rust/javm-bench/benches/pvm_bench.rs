//! PVM benchmark: javm interpreter/recompiler vs polkavm interpreter/compiler.
//!
//! Eight workloads:
//!   - fib: compute-intensive iterative Fibonacci (1M iterations)
//!   - hostcall: host-call-heavy (100K ecalli invocations)
//!   - sort: insertion sort of 1K u32 elements (compute + memory interleaved)
//!   - sieve: Sieve of Eratosthenes up to 100K (memory + branching)
//!   - blake2b: Blake2b-256 hash of 1KB message (crypto)
//!   - keccak: Keccak-256 hash of 1KB message (crypto)
//!   - ed25519: Ed25519 signature verification (crypto)
//!   - ecrecover: secp256k1 ECDSA public key recovery (crypto-heavy)
//!
//! ## Benchmark fairness
//!
//! Both javm and polkavm recompiler benchmarks include compilation + execution in
//! each iteration. This is the realistic scenario for JAM: each work-package
//! arrives as a blob that must be compiled and executed. Caching compiled code
//! across invocations is a separate optimization.

use criterion::{Criterion, criterion_group, criterion_main};

/// Bench-local helper: build an InvocationKernel from a self-contained
/// JAR blob via the public two-step API (cap_table_from_blob +
/// new_from_artifacts). Replaces the retired
/// `InvocationKernel::new_with_backend(blob, gas, backend)`.
fn kernel_from_blob(
    blob: &[u8],
    gas: u64,
    backend: javm::PvmBackend,
) -> javm::kernel::InvocationKernel<u8> {
    let artifacts = javm::kernel::cap_table_from_blob::<u8>(blob, backend, None).unwrap();
    javm::kernel::InvocationKernel::new_from_artifacts(artifacts, gas, backend).unwrap()
}
use javm_bench::*;

// ---------------------------------------------------------------------------
// PolkaVM runners
// ---------------------------------------------------------------------------

use polkavm::{
    BackendKind, Config, Engine, GasMeteringKind, InterruptKind, Module, ModuleConfig, SandboxKind,
};
use polkavm_common::program::Reg as PReg;

fn polkavm_config(backend: BackendKind) -> Config {
    let mut config = Config::from_env().unwrap_or_else(|_| Config::new());
    config.set_backend(Some(backend));
    config.set_allow_experimental(true);
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

fn run_polkavm_compile_and_run(blob: &[u8], engine: &Engine) -> (u64, i64) {
    let mut mc = ModuleConfig::new();
    mc.set_gas_metering(Some(GasMeteringKind::Sync));
    let module = Module::new(engine, &mc, blob.to_vec().into()).unwrap();
    run_polkavm_module(&module)
}

// ---------------------------------------------------------------------------
// Correctness validation
// ---------------------------------------------------------------------------

fn validate(name: &str, javm_blob: &[u8], pvm_blob: &[u8]) {
    let (gi_result, gi_gas) = run_javm_interpreter(javm_blob, GAS_LIMIT);

    let (_, pvm_module) = try_make_polkavm_module(pvm_blob, BackendKind::Interpreter)
        .expect("polkavm interpreter should always work");
    let (pvm_result, pvm_remaining) = run_polkavm_module(&pvm_module);
    let pvm_gas = GAS_LIMIT as i64 - pvm_remaining;
    eprintln!(
        "{name}: javm result={gi_result} gas={gi_gas}, polkavm result={pvm_result} gas={pvm_gas}"
    );
    assert_eq!(
        gi_result as u32, pvm_result as u32,
        "{name}: javm/polkavm result mismatch (javm=0x{gi_result:X}, polkavm=0x{pvm_result:X})"
    );
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_standard(c: &mut Criterion, name: &str, javm_blob: &[u8], pvm_blob: &[u8]) {
    validate(name, javm_blob, pvm_blob);

    let (_, pvm_interp_mod) = try_make_polkavm_module(pvm_blob, BackendKind::Interpreter)
        .expect("polkavm interpreter should always work");
    let pvm_compiler = try_make_polkavm_module(pvm_blob, BackendKind::Compiler);

    let mut group = c.benchmark_group(name);

    group.bench_function("javm-interpreter", |b| {
        b.iter(|| run_javm_interpreter(javm_blob, GAS_LIMIT))
    });

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    group.bench_function("javm-recompiler", |b| {
        b.iter(|| run_javm_recompiler(javm_blob, GAS_LIMIT))
    });

    // Execution-only: compile in setup, measure only execution.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    group.bench_function("javm-recompiler-exec", |b| {
        b.iter_batched(
            || kernel_from_blob(javm_blob, GAS_LIMIT, javm::PvmBackend::ForceRecompiler),
            |mut kernel| {
                loop {
                    match kernel.run() {
                        javm::kernel::KernelResult::Halt(v) => break v,
                        javm::kernel::KernelResult::ProtocolCall { .. } => continue,
                        other => panic!("unexpected: {:?}", other),
                    }
                }
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("polkavm-interpreter", |b| {
        b.iter(|| run_polkavm_module(&pvm_interp_mod))
    });

    if let Some((ref engine, ref pvm_mod)) = pvm_compiler {
        group.bench_function("polkavm-compiler-exec", |b| {
            b.iter(|| run_polkavm_module(pvm_mod))
        });
        group.bench_function("polkavm-compiler-full", |b| {
            b.iter(|| run_polkavm_compile_and_run(pvm_blob, engine))
        });
    }

    group.finish();
}

fn bench_fib(c: &mut Criterion) {
    let javm_blob = javm_fib_blob(FIB_N);
    let pvm_blob = polkavm_fib_blob(FIB_N);
    bench_standard(c, "fib", &javm_blob, &pvm_blob);
}

fn bench_hostcall(c: &mut Criterion) {
    let javm_blob = javm_hostcall_blob(HOSTCALL_N);
    let pvm_blob = polkavm_hostcall_blob(HOSTCALL_N);
    bench_standard(c, "hostcall", &javm_blob, &pvm_blob);
}

fn bench_sort(c: &mut Criterion) {
    let javm_blob = javm_sort_blob(SORT_N);
    let pvm_blob = polkavm_sort_blob(SORT_N);
    bench_standard(c, "sort", &javm_blob, &pvm_blob);
}

fn bench_sieve(c: &mut Criterion) {
    bench_standard(c, "sieve", javm_sieve_blob(), polkavm_sieve_blob());
}

fn bench_blake2b(c: &mut Criterion) {
    bench_standard(c, "blake2b", javm_blake2b_blob(), polkavm_blake2b_blob());
}

fn bench_keccak(c: &mut Criterion) {
    bench_standard(c, "keccak", javm_keccak_blob(), polkavm_keccak_blob());
}

fn bench_ed25519(c: &mut Criterion) {
    bench_standard(c, "ed25519", javm_ed25519_blob(), polkavm_ed25519_blob());
}

fn bench_ecrecover(c: &mut Criterion) {
    let javm_blob = javm_ecrecover_blob();
    let pvm_blob = polkavm_ecrecover_blob();
    let ecrecover_gas: u64 = i64::MAX as u64;

    let pvm_compiler = try_make_polkavm_module(pvm_blob, BackendKind::Compiler);

    let mut group = c.benchmark_group("ecrecover");
    group.sample_size(10);

    // Native baseline
    group.bench_function("native", |b| {
        b.iter(|| {
            use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
            let msg: [u8; 32] = [
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                0x66, 0x77, 0x88, 0x99,
            ];
            let sig_bytes: [u8; 64] = [
                0xff, 0x65, 0x1c, 0x65, 0xee, 0xde, 0xd4, 0x63, 0x83, 0xa4, 0xbd, 0xcd, 0x91, 0x70,
                0xff, 0x65, 0x9a, 0x4f, 0x61, 0x7b, 0xb6, 0x58, 0xa4, 0x6d, 0xd4, 0x56, 0xc5, 0x1e,
                0xc8, 0xcc, 0x21, 0x1a, 0x7d, 0xc4, 0xde, 0x91, 0xd0, 0xc8, 0x47, 0xbf, 0x5d, 0xef,
                0x99, 0x5b, 0xd0, 0x43, 0x65, 0x81, 0x36, 0xfe, 0x21, 0x35, 0xaf, 0xe6, 0x92, 0x82,
                0xf7, 0xde, 0x87, 0x39, 0x90, 0xda, 0xcb, 0x77,
            ];
            let sig = Signature::from_slice(&sig_bytes).unwrap();
            let recid = RecoveryId::new(true, false);
            let key = VerifyingKey::recover_from_prehash(&msg, &sig, recid).unwrap();
            std::hint::black_box(key);
        })
    });

    group.bench_function("javm-interpreter", |b| {
        b.iter(|| {
            run_kernel_with_backend(javm_blob, ecrecover_gas, javm::PvmBackend::ForceInterpreter)
        })
    });

    group.bench_function("javm-recompiler", |b| {
        b.iter(|| {
            run_kernel_with_backend(javm_blob, ecrecover_gas, javm::PvmBackend::ForceRecompiler)
        })
    });

    // Compile-only: measure only kernel init (includes JIT compilation).
    group.bench_function("javm-recompiler-compile", |b| {
        b.iter(|| {
            std::hint::black_box(kernel_from_blob(
                javm_blob,
                ecrecover_gas,
                javm::PvmBackend::ForceRecompiler,
            ));
        })
    });

    // Execution-only: compile in setup, measure only execution.
    group.bench_function("javm-recompiler-exec", |b| {
        b.iter_batched(
            || kernel_from_blob(javm_blob, ecrecover_gas, javm::PvmBackend::ForceRecompiler),
            |mut kernel| {
                loop {
                    match kernel.run() {
                        javm::kernel::KernelResult::Halt(v) => break v,
                        javm::kernel::KernelResult::Panic => break 0,
                        javm::kernel::KernelResult::ProtocolCall { .. } => continue,
                        other => panic!("unexpected: {:?}", other),
                    }
                }
            },
            criterion::BatchSize::SmallInput,
        );
    });

    let pvm_interp = try_make_polkavm_module(pvm_blob, BackendKind::Interpreter);
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
                        InterruptKind::Trap => break,
                        InterruptKind::NotEnoughGas => panic!("polkavm out of gas"),
                        other => panic!("polkavm unexpected: {:?}", other),
                    }
                }
                inst.reg(PReg::A0)
            })
        });
        let pvm_config = polkavm_config(BackendKind::Compiler);
        group.bench_function("polkavm-compiler-compile", |b| {
            b.iter(|| {
                let engine = Engine::new(&pvm_config).unwrap();
                let mut mc = ModuleConfig::new();
                mc.set_gas_metering(Some(GasMeteringKind::Sync));
                std::hint::black_box(Module::new(&engine, &mc, pvm_blob.into()).unwrap());
            })
        });
        group.bench_function("polkavm-compiler-full", |b| {
            b.iter(|| {
                let mut mc = ModuleConfig::new();
                mc.set_gas_metering(Some(GasMeteringKind::Sync));
                let module = Module::new(engine, &mc, pvm_blob.into()).unwrap();
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
                        InterruptKind::Trap => break,
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

criterion_group!(
    benches,
    bench_fib,
    bench_hostcall,
    bench_sort,
    bench_sieve,
    bench_blake2b,
    bench_keccak,
    bench_ed25519,
    bench_ecrecover
);
criterion_main!(benches);
