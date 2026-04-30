use javm_bench::*;

fn main() {
    let blob = javm_fib_blob(javm_bench::FIB_N);
    let gas: u64 = i64::MAX as u64;
    let (result, gas_used) =
        run_kernel_with_backend(&blob, gas, javm::PvmBackend::ForceInterpreter);
    eprintln!("result={result} gas_used={gas_used}");
}
