//! Fuzz target: random PVM bytecode through the interpreter.
//!
//! Generates random code bytes and runs them as PVM programs to verify
//! the interpreter never panics or hits undefined behavior regardless
//! of input. The code is run with every-byte-is-instruction-start bitmask
//! (simplified mode) and a small gas limit to keep execution fast.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Split input: first byte controls memory size, rest is code
    let mem_pages = (data[0] as usize % 4) + 1; // 1-4 pages (4KB each)
    let code = &data[1..];
    if code.is_empty() {
        return;
    }

    let registers = [0u64; javm::PVM_REGISTER_COUNT];
    let flat_mem = vec![0u8; mem_pages * 4096];
    let gas = 10_000; // Small gas limit for fast iteration

    let mut interp = javm::interpreter::Interpreter::new_simple(
        code.to_vec(),
        registers,
        flat_mem,
        gas,
    );

    // Run to completion — should never panic
    let _result = interp.run();
});
