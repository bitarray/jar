#![cfg_attr(target_env = "javm", no_std)]
#![cfg_attr(target_env = "javm", no_main)]

#[cfg(target_env = "javm")]
javm_builtins::javm_entry!(javm_main);

#[cfg(target_env = "javm")]
#[no_mangle]
extern "C" fn javm_main() -> u32 {
    bench_fri_fold_tree::fri_fold_tree_bench()
}

#[cfg(not(target_env = "javm"))]
fn main() {}
