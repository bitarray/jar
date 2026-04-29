#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn ecrecover_bench() -> u32 {
    crate::ecrecover_bench()
}
