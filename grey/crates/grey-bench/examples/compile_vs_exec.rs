/// Measure compile time vs execution time for sort benchmark.
/// Helps identify whether compilation or execution is the bottleneck.
use grey_bench::*;
use std::time::Instant;

const GAS_LIMIT: u64 = 100_000_000;
const ITERS: usize = 20;

fn median(v: &mut [u128]) -> u128 {
    v.sort();
    v[v.len() / 2]
}

fn main() {
    let sort_blob = grey_sort_blob(500);

    // --- Grey recompiler (via kernel) ---
    let mut compile_us = Vec::new();
    let mut exec_us = Vec::new();
    for _ in 0..ITERS {
        let t0 = Instant::now();
        let mut kernel = javm::kernel::InvocationKernel::new_with_backend(
            &sort_blob,
            &[],
            GAS_LIMIT,
            javm::PvmBackend::ForceRecompiler,
        )
        .unwrap();
        compile_us.push(t0.elapsed().as_micros());

        let t1 = Instant::now();
        loop {
            match kernel.run() {
                javm::kernel::KernelResult::Halt(_) => break,
                javm::kernel::KernelResult::ProtocolCall { .. } => continue,
                other => panic!("grey: {:?}", other),
            }
        }
        exec_us.push(t1.elapsed().as_micros());
    }
    let gc = median(&mut compile_us);
    let ge = median(&mut exec_us);
    eprintln!(
        "grey-recompiler  compile={gc:>6}µs  exec={ge:>6}µs  total={:>6}µs",
        gc + ge
    );

    // --- PolkaVM compiler ---
    let pvm_blob = polkavm_sort_blob(500);
    let mut config = polkavm::Config::from_env().unwrap_or_else(|_| polkavm::Config::new());
    config.set_backend(Some(polkavm::BackendKind::Compiler));
    config.set_allow_experimental(true);
    config.set_sandboxing_enabled(false);
    #[cfg(feature = "polkavm-generic-sandbox")]
    config.set_sandbox(Some(polkavm::SandboxKind::Generic));
    let engine = polkavm::Engine::new(&config).unwrap();

    let mut compile_us = Vec::new();
    let mut exec_us = Vec::new();
    for _ in 0..ITERS {
        let t0 = Instant::now();
        let mut mc = polkavm::ModuleConfig::new();
        mc.set_gas_metering(Some(polkavm::GasMeteringKind::Sync));
        let module = polkavm::Module::new(&engine, &mc, pvm_blob.clone().into()).unwrap();
        let mut inst = module.instantiate().unwrap();
        compile_us.push(t0.elapsed().as_micros());

        let t1 = Instant::now();
        inst.set_gas(GAS_LIMIT as i64);
        inst.set_next_program_counter(module.exports().next().unwrap().program_counter());
        inst.set_reg(polkavm::Reg::RA, 0xFFFF0000u64);
        inst.set_reg(polkavm::Reg::SP, module.default_sp());
        loop {
            match inst.run().unwrap() {
                polkavm::InterruptKind::Finished | polkavm::InterruptKind::Trap => break,
                polkavm::InterruptKind::Ecalli(_) => continue,
                other => panic!("polkavm: {:?}", other),
            }
        }
        exec_us.push(t1.elapsed().as_micros());
    }
    let pc = median(&mut compile_us);
    let pe = median(&mut exec_us);
    eprintln!(
        "polkavm-compiler compile={pc:>6}µs  exec={pe:>6}µs  total={:>6}µs",
        pc + pe
    );
}
