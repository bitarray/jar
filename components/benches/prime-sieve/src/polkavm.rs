#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn prime_sieve() -> u32 {
    crate::prime_sieve()
}
