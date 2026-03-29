//! Three-way comparison tests: host vs interpreter vs recompiler.
//!
//! Each test encodes `[test_id: u32 LE] [args...]`, runs on all three backends,
//! and asserts output + gas match.

include!(concat!(env!("OUT_DIR"), "/guest_blob.rs"));

/// Run a guest test on host, interpreter, and recompiler. Assert outputs match
/// and interpreter/recompiler gas costs are equal.
fn run_test(test_id: u32, args: &[u8]) {
    // Encode input
    let mut input = test_id.to_le_bytes().to_vec();
    input.extend_from_slice(args);

    // --- Host ---
    let host_len = javm_guest_tests::dispatch(&input);
    let host_output = unsafe { javm_guest_tests::read_output(host_len) }.to_vec();

    // --- Interpreter ---
    let gas = 100_000_000_000u64;
    let mut interp = javm::program::initialize_program(GUEST_TESTS_BLOB, &input, gas)
        .expect("blob should be loadable");
    loop {
        match interp.run().0 {
            javm::ExitReason::Halt => break,
            javm::ExitReason::Panic => {
                panic!("test {test_id}: interpreter panicked at PC={}", interp.pc)
            }
            javm::ExitReason::HostCall(_) => continue,
            other => panic!("test {test_id}: interpreter unexpected exit: {other:?}"),
        }
    }
    let interp_gas = gas - interp.gas;
    let packed = interp.registers[7];
    let interp_ptr = (packed >> 32) as usize;
    let interp_len = (packed & 0xFFFFFFFF) as usize;
    assert!(
        interp_ptr + interp_len <= interp.flat_mem.len(),
        "test {test_id}: interpreter output out of bounds: ptr={interp_ptr:#x} len={interp_len}"
    );
    let interp_output = interp.flat_mem[interp_ptr..interp_ptr + interp_len].to_vec();

    assert_eq!(
        host_output, interp_output,
        "test {test_id}: host vs interpreter output mismatch"
    );

    // --- Recompiler ---
    let mut recomp = javm::recompiler::initialize_program_recompiled(GUEST_TESTS_BLOB, &input, gas)
        .expect("recompiler should initialize");
    loop {
        match recomp.run() {
            javm::ExitReason::Halt => break,
            javm::ExitReason::Panic => panic!("test {test_id}: recompiler panicked"),
            javm::ExitReason::HostCall(_) => continue,
            other => panic!("test {test_id}: recompiler unexpected exit: {other:?}"),
        }
    }
    let recomp_gas = gas - recomp.gas();
    let packed = recomp.registers()[7];
    let recomp_ptr = (packed >> 32) as u32;
    let recomp_len = (packed & 0xFFFFFFFF) as u32;
    let recomp_output = recomp
        .read_bytes(recomp_ptr, recomp_len)
        .unwrap_or_else(|| {
            panic!("test {test_id}: read_bytes failed at ptr=0x{recomp_ptr:X} len={recomp_len}")
        });

    assert_eq!(
        host_output, recomp_output,
        "test {test_id}: host vs recompiler output mismatch"
    );
    assert_eq!(
        interp_gas, recomp_gas,
        "test {test_id}: gas mismatch: interpreter={interp_gas} recompiler={recomp_gas}"
    );
}

// -- Helpers ------------------------------------------------------------------

fn u64_pair(a: u64, b: u64) -> Vec<u8> {
    let mut v = a.to_le_bytes().to_vec();
    v.extend_from_slice(&b.to_le_bytes());
    v
}

fn u64_u32(val: u64, amt: u32) -> Vec<u8> {
    let mut v = val.to_le_bytes().to_vec();
    v.extend_from_slice(&amt.to_le_bytes());
    v
}

// -- Arithmetic tests ---------------------------------------------------------

#[test]
fn test_add_u64() {
    run_test(0, &u64_pair(3, 7));
    run_test(0, &u64_pair(u64::MAX, 1)); // overflow
    run_test(0, &u64_pair(0, 0));
    run_test(0, &u64_pair(0x8000000000000000, 0x8000000000000000));
}

#[test]
fn test_sub_u64() {
    run_test(1, &u64_pair(10, 3));
    run_test(1, &u64_pair(0, 1)); // underflow
    run_test(1, &u64_pair(u64::MAX, u64::MAX));
}

#[test]
fn test_mul_u64() {
    run_test(2, &u64_pair(6, 7));
    run_test(2, &u64_pair(u64::MAX, 2)); // overflow
    run_test(2, &u64_pair(0, 12345));
    run_test(2, &u64_pair(0x100000000, 0x100000000));
}

#[test]
fn test_mul_upper_uu() {
    run_test(3, &u64_pair(u64::MAX, u64::MAX));
    run_test(3, &u64_pair(u64::MAX, 2));
    run_test(3, &u64_pair(1 << 32, 1 << 32)); // product = 2^64, high = 1
    run_test(3, &u64_pair(0, u64::MAX));
}

#[test]
fn test_mul_upper_ss() {
    let neg1 = (-1i64) as u64;
    run_test(4, &u64_pair(neg1, neg1)); // (-1)*(-1) = 1, high = 0
    run_test(4, &u64_pair(neg1, 2)); // (-1)*2 = -2, high = -1
    run_test(4, &u64_pair(i64::MIN as u64, 2)); // MIN*2, high = -1
    run_test(4, &u64_pair(i64::MIN as u64, i64::MIN as u64));
}

#[test]
fn test_div_u64() {
    run_test(5, &u64_pair(42, 7));
    run_test(5, &u64_pair(100, 3)); // remainder
    run_test(5, &u64_pair(1, 0)); // div by zero → MAX
    run_test(5, &u64_pair(u64::MAX, 1));
}

#[test]
fn test_rem_u64() {
    run_test(6, &u64_pair(100, 3)); // 100 % 3 = 1
    run_test(6, &u64_pair(42, 7)); // exact
    run_test(6, &u64_pair(1, 0)); // rem by zero → a
}

#[test]
fn test_div_s64() {
    run_test(7, &u64_pair((-10i64) as u64, 3u64));
    run_test(7, &u64_pair(i64::MIN as u64, (-1i64) as u64)); // overflow
    run_test(7, &u64_pair(1, 0)); // div by zero
}

#[test]
fn test_rem_s64() {
    run_test(8, &u64_pair((-10i64) as u64, 3u64));
    run_test(8, &u64_pair(i64::MIN as u64, (-1i64) as u64)); // overflow → 0
    run_test(8, &u64_pair(1, 0)); // rem by zero → a
}

// -- Bitwise tests ------------------------------------------------------------

#[test]
fn test_shift_left() {
    run_test(10, &u64_u32(1, 0));
    run_test(10, &u64_u32(1, 63));
    run_test(10, &u64_u32(0x8000000000000000, 1)); // shifts out
    run_test(10, &u64_u32(u64::MAX, 32));
}

#[test]
fn test_shift_right_logical() {
    run_test(11, &u64_u32(0x8000000000000000, 63)); // → 1
    run_test(11, &u64_u32(u64::MAX, 32));
    run_test(11, &u64_u32(1, 0));
}

#[test]
fn test_shift_right_arithmetic() {
    run_test(12, &u64_u32(0x8000000000000000, 63)); // → all 1s
    run_test(12, &u64_u32(u64::MAX, 1)); // → still all 1s
    run_test(12, &u64_u32(0x4000000000000000, 1)); // positive → 0x2000...
}

#[test]
fn test_rotate_right() {
    run_test(13, &u64_u32(1, 1)); // → 0x8000000000000000
    run_test(13, &u64_u32(0x8000000000000000, 1)); // → 0x4000000000000000
    run_test(13, &u64_u32(0x8000000000000000, 63)); // RORI with shamt=63 (was buggy)
}

#[test]
fn test_and_or_xor() {
    run_test(14, &u64_pair(0xFF00FF00FF00FF00, 0x0F0F0F0F0F0F0F0F));
    run_test(15, &u64_pair(0xFF00FF00FF00FF00, 0x0F0F0F0F0F0F0F0F));
    run_test(16, &u64_pair(0xFF00FF00FF00FF00, 0x0F0F0F0F0F0F0F0F));
}

#[test]
fn test_clz_ctz() {
    run_test(17, &0u64.to_le_bytes()); // clz(0) = 64
    run_test(17, &1u64.to_le_bytes()); // clz(1) = 63
    run_test(17, &u64::MAX.to_le_bytes()); // clz(MAX) = 0
    run_test(18, &0u64.to_le_bytes()); // ctz(0) = 64
    run_test(18, &(1u64 << 63).to_le_bytes()); // ctz(2^63) = 63
    run_test(18, &2u64.to_le_bytes()); // ctz(2) = 1
}

#[test]
fn test_set_lt() {
    run_test(19, &u64_pair(1, 2)); // 1 < 2 unsigned → 1
    run_test(19, &u64_pair(2, 1)); // 2 < 1 → 0
    run_test(19, &u64_pair(u64::MAX, 0)); // MAX < 0 unsigned → 0
    run_test(20, &u64_pair((-1i64) as u64, 0)); // -1 < 0 signed → 1
    run_test(20, &u64_pair(0, (-1i64) as u64)); // 0 < -1 signed → 0
}

// -- Memory & control flow tests ----------------------------------------------

#[test]
fn test_memcpy() {
    run_test(30, b"hello world");
    run_test(30, &[0u8; 256]); // zeroes
    run_test(30, &(0..128).collect::<Vec<u8>>()); // sequential bytes
}

#[test]
fn test_sort_u32() {
    let unsorted: Vec<u8> = [5u32, 3, 8, 1, 4, 2, 7, 6]
        .iter()
        .flat_map(|x| x.to_le_bytes())
        .collect();
    run_test(31, &unsorted);

    // Already sorted
    let sorted: Vec<u8> = [1u32, 2, 3, 4]
        .iter()
        .flat_map(|x| x.to_le_bytes())
        .collect();
    run_test(31, &sorted);

    // Single element
    run_test(31, &1u32.to_le_bytes());
}

#[test]
fn test_fib() {
    run_test(32, &0u32.to_le_bytes()); // fib(0) = 0
    run_test(32, &1u32.to_le_bytes()); // fib(1) = 1
    run_test(32, &10u32.to_le_bytes()); // fib(10) = 55
    run_test(32, &50u32.to_le_bytes()); // fib(50) = 12586269025
}

// -- Crypto tests -------------------------------------------------------------

#[test]
fn test_blake2b_256() {
    run_test(40, b""); // empty message
    run_test(40, b"hello");
    run_test(40, &[0u8; 1024]); // 1KB of zeroes
}

#[test]
fn test_keccak_256() {
    run_test(41, b""); // empty message
    run_test(41, b"hello");
    run_test(41, &[0u8; 1024]);
}
