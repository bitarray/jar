#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn poly_eval_bench() -> u32 {
    crate::poly_eval_bench()
}
