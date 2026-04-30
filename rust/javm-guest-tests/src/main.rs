#![cfg_attr(target_env = "javm", no_std)]
#![cfg_attr(target_env = "javm", no_main)]

#[cfg(target_env = "javm")]
javm_builtins::javm_entry!(javm_main);

#[cfg(target_env = "javm")]
#[no_mangle]
extern "C" fn javm_main(args_len: u64) -> u64 {
    let input = javm_builtins::map_args(args_len);
    let output_len = javm_guest_tests::dispatch(input);
    let output_ptr = javm_guest_tests::output_buffer() as u64;
    (output_ptr << 32) | (output_len as u64)
}

#[cfg(not(target_env = "javm"))]
fn main() {}
