#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn blake2b_bench() -> u32 {
    crate::blake2b_bench()
}
