//! Differential fuzz target: interpreter vs recompiler.
//!
//! Wraps random bytes into a valid PVM blob, runs on both the interpreter
//! and recompiler backends via the kernel, and asserts that both produce
//! identical results (exit value and gas consumed).
//!
//! This catches semantic differences between the two PVM backends that
//! targeted unit tests might miss.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    // Split input: first byte controls heap pages, rest is code+bitmask
    let heap_pages = (data[0] as u32 % 4) + 1; // 1-4 pages
    let code_len = data.len() - 1;
    let code = &data[1..];

    // Build a bitmask: every other byte pattern from the code itself
    // to give the fuzzer control over basic block boundaries.
    let bitmask: Vec<u8> = code.iter().map(|b| if b & 1 == 1 { 1 } else { 0 }).collect();
    // Ensure first byte is always an instruction start
    let mut bitmask = bitmask;
    if !bitmask.is_empty() {
        bitmask[0] = 1;
    }

    // Build a valid PVM service blob
    let stack_pages = 1u32;
    let total = stack_pages + heap_pages + 4;
    let blob = javm_transpiler::emitter::build_service_program(
        code,
        &bitmask,
        &[], // jump_table
        &[], // ro_data
        &[], // rw_data
        stack_pages,
        heap_pages,
        total,
    );

    let gas = 50_000u64; // Small gas limit for fast iteration

    // Run on interpreter
    let interp_result = run_backend(&blob, gas, javm::PvmBackend::ForceInterpreter);

    // Run on recompiler
    let recomp_result = run_backend(&blob, gas, javm::PvmBackend::ForceRecompiler);

    // Compare results
    match (&interp_result, &recomp_result) {
        (Ok((iv, ig)), Ok((rv, rg))) => {
            assert_eq!(iv, rv, "exit value mismatch: interp={iv} recomp={rv}");
            assert_eq!(ig, rg, "gas mismatch: interp={ig} recomp={rg}");
        }
        // Both erroring (panic/oog/pagefault) is fine — just check they agree
        (Err(ie), Err(re)) => {
            assert_eq!(ie, re, "error mismatch: interp={ie:?} recomp={re:?}");
        }
        _ => {
            panic!(
                "backend disagree: interp={interp_result:?} recomp={recomp_result:?}, code_len={code_len}"
            );
        }
    }
});

#[derive(Debug, PartialEq, Eq)]
enum PvmError {
    Panic,
    OutOfGas,
    PageFault(u32),
    InitFailed,
}

fn run_backend(blob: &[u8], gas: u64, backend: javm::PvmBackend) -> Result<(u64, u64), PvmError> {
    let mut kernel = match javm::kernel::InvocationKernel::new_with_backend(blob, &[], gas, backend)
    {
        Ok(k) => k,
        Err(_) => return Err(PvmError::InitFailed),
    };

    loop {
        match kernel.run() {
            javm::kernel::KernelResult::Halt(v) => {
                return Ok((v, gas - kernel.active_gas()));
            }
            javm::kernel::KernelResult::Panic => return Err(PvmError::Panic),
            javm::kernel::KernelResult::OutOfGas => return Err(PvmError::OutOfGas),
            javm::kernel::KernelResult::PageFault(a) => {
                return Err(PvmError::PageFault(a));
            }
            javm::kernel::KernelResult::ProtocolCall { .. } => continue,
        }
    }
}
