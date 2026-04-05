use grey_bench::*;

fn main() {
    let blob = grey_fib_blob(grey_bench::FIB_N);
    let gas: u64 = i64::MAX as u64;
    let (result, gas_used) =
        run_kernel_with_backend(&blob, gas, javm::PvmBackend::ForceInterpreter);
    eprintln!("result={result} gas_used={gas_used}");
}
