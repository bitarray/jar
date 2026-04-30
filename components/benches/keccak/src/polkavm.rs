#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn keccak_bench() -> u32 {
    crate::keccak_bench()
}
