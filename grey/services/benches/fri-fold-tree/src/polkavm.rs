#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn fri_fold_tree_bench() -> u32 {
    crate::fri_fold_tree_bench()
}
