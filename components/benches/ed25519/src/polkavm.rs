#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn ed25519_verify_bench() -> u32 {
    crate::ed25519_verify_bench()
}
