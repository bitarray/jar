#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn mini_verifier_bench() -> u32 {
    crate::mini_verifier_bench()
}
