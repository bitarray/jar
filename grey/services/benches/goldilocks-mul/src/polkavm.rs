#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn goldilocks_mul_bench() -> u32 {
    crate::goldilocks_mul_bench()
}
