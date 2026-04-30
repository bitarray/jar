/// Dump native code for javm and polkavm programs for disassembly comparison.
///
/// Usage:
///   cargo run -p javm-bench --release --example dump_native
///   objdump -D -b binary -m i386:x86-64 /tmp/javm_sort.bin | less
///   objdump -D -b binary -m i386:x86-64 /tmp/polkavm_sort.bin | less
use javm_bench::*;

fn dump_polkavm(name: &str, blob: Vec<u8>) {
    let mut config = polkavm::Config::new();
    config.set_backend(Some(polkavm::BackendKind::Compiler));
    config.set_allow_experimental(true);
    config.set_sandboxing_enabled(false);
    #[cfg(feature = "polkavm-generic-sandbox")]
    config.set_sandbox(Some(polkavm::SandboxKind::Generic));
    let engine = polkavm::Engine::new(&config).unwrap();
    let mut mc = polkavm::ModuleConfig::new();
    mc.set_gas_metering(Some(polkavm::GasMeteringKind::Sync));
    let module = polkavm::Module::new(&engine, &mc, blob.into()).unwrap();
    let path = format!("/tmp/polkavm_{name}.bin");
    if let Some(code) = module.machine_code() {
        std::fs::write(&path, code).unwrap();
        eprintln!("polkavm {name}: {} bytes -> {path}", code.len());
    } else {
        eprintln!("polkavm {name}: no machine code available");
    }
}

fn dump_javm(name: &str, blob: &[u8]) {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let backend = javm::PvmBackend::ForceRecompiler;
        let artifacts = javm::kernel::cap_table_from_blob::<u8>(blob, backend, None).unwrap();
        let kernel: javm::kernel::InvocationKernel =
            javm::kernel::InvocationKernel::new_from_artifacts(artifacts, 100_000_000, backend)
                .unwrap();
        // Access the first CODE cap's native code
        if let Some(code_cap) = kernel.code_caps.first()
            && let javm::backend::CompiledProgram::Recompiler(ref compiled) = code_cap.compiled
        {
            let native = unsafe {
                std::slice::from_raw_parts(
                    compiled.native_code.ptr as *const u8,
                    compiled.native_code.len,
                )
            };
            let path = format!("/tmp/javm_{name}.bin");
            std::fs::write(&path, native).unwrap();
            eprintln!("javm {name}: {} bytes -> {path}", native.len());
        }
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let _ = blob;
        eprintln!("javm {name}: JIT recompiler not available on this platform");
    }
}

fn main() {
    let blob = javm_fib_blob(FIB_N);
    dump_javm("fib", &blob);
    dump_polkavm("fib", polkavm_fib_blob(FIB_N));

    let blob = javm_sort_blob(SORT_N);
    dump_javm("sort", &blob);
    dump_polkavm("sort", polkavm_sort_blob(SORT_N));

    dump_javm("ecrecover", javm_ecrecover_blob());
    dump_polkavm("ecrecover", polkavm_ecrecover_blob().to_vec());
}
