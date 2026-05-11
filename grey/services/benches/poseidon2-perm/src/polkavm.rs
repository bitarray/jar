#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn poseidon2_perm_bench() -> u32 {
    crate::poseidon2_perm_bench()
}
