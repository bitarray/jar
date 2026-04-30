pub mod arithmetic;
pub mod bitwise;
pub mod crypto;
pub mod memory;

/// Dispatch to a test function by ID.
pub fn dispatch_by_id(test_id: u32, args: &[u8], output: &mut [u8]) -> usize {
    match test_id {
        0 => arithmetic::add_u64(args, output),
        1 => arithmetic::sub_u64(args, output),
        2 => arithmetic::mul_u64(args, output),
        3 => arithmetic::mul_upper_uu(args, output),
        4 => arithmetic::mul_upper_ss(args, output),
        5 => arithmetic::div_u64(args, output),
        6 => arithmetic::rem_u64(args, output),
        7 => arithmetic::div_s64(args, output),
        8 => arithmetic::rem_s64(args, output),
        10 => bitwise::shift_left(args, output),
        11 => bitwise::shift_right_logical(args, output),
        12 => bitwise::shift_right_arithmetic(args, output),
        13 => bitwise::rotate_right(args, output),
        14 => bitwise::and(args, output),
        15 => bitwise::or(args, output),
        16 => bitwise::xor(args, output),
        17 => bitwise::clz(args, output),
        18 => bitwise::ctz(args, output),
        19 => bitwise::set_lt_u(args, output),
        20 => bitwise::set_lt_s(args, output),
        30 => memory::memcpy_test(args, output),
        31 => memory::sort_u32(args, output),
        32 => memory::fib(args, output),
        40 => crypto::blake2b_256(args, output),
        41 => crypto::keccak_256(args, output),
        _ => 0,
    }
}
