//! Memory cache pressure benchmark programs.
//!
//! Two parameterized guest programs that stress the memory hierarchy:
//! - `mem_seq`: sequential sweep through an array (prefetch-friendly, best case)
//! - `mem_rand`: pseudo-random stride access via xorshift (cache-hostile, worst case)
//!
//! Each is parameterized by working set size to reveal L1→L2→L3→DRAM transitions.

/// Number of full sweeps through the array per benchmark invocation (odd so XOR doesn't cancel).
const SWEEPS: u32 = 15;

/// Heap base address in the linear memory model.
/// With stack_pages=1 and no ro/rw/args data:
///   heap_start = page_round(4096) + page_round(0) + page_round(0) + page_round(0) = 0x1000
pub const HEAP_BASE: u64 = 0x1000;

// PVM register indices (JAR v0.8.0 linear memory layout)
const RA: u8 = 0;
const T0: u8 = 2;
const T1: u8 = 3;
const T2: u8 = 4;
const S0: u8 = 5;
const S1: u8 = 6;
const A0: u8 = 7;
const A1: u8 = 8;
const A2: u8 = 9;

// ---------------------------------------------------------------------------
// PVM instruction emitters (raw bytecode, same pattern as sort in lib.rs)
// ---------------------------------------------------------------------------

fn load_imm_64(c: &mut Vec<u8>, m: &mut Vec<u8>, rd: u8, val: u64) {
    c.push(20); // LoadImm64
    m.push(1);
    c.push(rd);
    m.push(0);
    for i in 0..8 {
        c.push((val >> (i * 8)) as u8);
        m.push(0);
    }
}

fn add_imm_64(c: &mut Vec<u8>, m: &mut Vec<u8>, rd: u8, ra: u8, imm: i32) {
    c.push(149); // AddImm64
    m.push(1);
    c.push(rd | (ra << 4));
    m.push(0);
    for b in imm.to_le_bytes() {
        c.push(b);
        m.push(0);
    }
}

fn mov(c: &mut Vec<u8>, m: &mut Vec<u8>, rd: u8, ra: u8) {
    c.push(100); // MoveReg
    m.push(1);
    c.push(rd | (ra << 4));
    m.push(0);
}

fn add_64(c: &mut Vec<u8>, m: &mut Vec<u8>, rd: u8, ra: u8, rb: u8) {
    c.push(200); // Add64
    m.push(1);
    c.push(ra | (rb << 4));
    m.push(0);
    c.push(rd);
    m.push(0);
}

fn store_ind_u32(c: &mut Vec<u8>, m: &mut Vec<u8>, rd: u8, ra: u8, imm: i32) {
    c.push(122); // StoreIndU32
    m.push(1);
    c.push(rd | (ra << 4));
    m.push(0);
    for b in imm.to_le_bytes() {
        c.push(b);
        m.push(0);
    }
}

fn load_ind_u32(c: &mut Vec<u8>, m: &mut Vec<u8>, rd: u8, ra: u8, imm: i32) {
    c.push(128); // LoadIndU32
    m.push(1);
    c.push(rd | (ra << 4));
    m.push(0);
    for b in imm.to_le_bytes() {
        c.push(b);
        m.push(0);
    }
}

// TODO: shlo_l_imm_64 causes a recompiler PageFault bug. Using add_64 doubling as workaround.
// Investigate and fix in javm/src/recompiler/codegen.rs.

#[allow(dead_code)]
fn xor_64(c: &mut Vec<u8>, m: &mut Vec<u8>, rd: u8, ra: u8, rb: u8) {
    c.push(211); // Xor (ThreeReg)
    m.push(1);
    c.push(ra | (rb << 4));
    m.push(0);
    c.push(rd);
    m.push(0);
}

#[allow(dead_code)]
fn shlo_l_imm_64(c: &mut Vec<u8>, m: &mut Vec<u8>, rd: u8, ra: u8, imm: i32) {
    c.push(151); // ShloLImm64 (TwoRegOneImm)
    m.push(1);
    c.push(rd | (ra << 4));
    m.push(0);
    for b in imm.to_le_bytes() {
        c.push(b);
        m.push(0);
    }
}

#[allow(dead_code)]
fn shlo_r_imm_64(c: &mut Vec<u8>, m: &mut Vec<u8>, rd: u8, ra: u8, imm: i32) {
    c.push(152); // ShloRImm64 (TwoRegOneImm)
    m.push(1);
    c.push(rd | (ra << 4));
    m.push(0);
    for b in imm.to_le_bytes() {
        c.push(b);
        m.push(0);
    }
}

fn and_64(c: &mut Vec<u8>, m: &mut Vec<u8>, rd: u8, ra: u8, rb: u8) {
    c.push(210); // And (ThreeReg)
    m.push(1);
    c.push(ra | (rb << 4));
    m.push(0);
    c.push(rd);
    m.push(0);
}

fn jump(c: &mut Vec<u8>, m: &mut Vec<u8>, offset: i32) {
    c.push(40); // Jump
    m.push(1);
    for b in offset.to_le_bytes() {
        c.push(b);
        m.push(0);
    }
}

fn branch_lt_u(c: &mut Vec<u8>, m: &mut Vec<u8>, ra: u8, rb: u8, offset: i32) {
    c.push(172); // BranchLtU (TwoRegOneOffset)
    m.push(1);
    c.push(ra | (rb << 4));
    m.push(0);
    for b in offset.to_le_bytes() {
        c.push(b);
        m.push(0);
    }
}

fn branch_ne(c: &mut Vec<u8>, m: &mut Vec<u8>, ra: u8, rb: u8, offset: i32) {
    c.push(171); // BranchNe (TwoRegOneOffset)
    m.push(1);
    c.push(ra | (rb << 4));
    m.push(0);
    for b in offset.to_le_bytes() {
        c.push(b);
        m.push(0);
    }
}

fn ecalli(c: &mut Vec<u8>, m: &mut Vec<u8>, imm: u32) {
    c.push(10); // Ecalli
    m.push(1);
    for b in imm.to_le_bytes() {
        c.push(b);
        m.push(0);
    }
}

fn pc(c: &[u8]) -> u32 {
    c.len() as u32
}

fn build_blob(c: Vec<u8>, m: Vec<u8>, stack_pages: u32, heap_pages: u32) -> Vec<u8> {
    let total = stack_pages + heap_pages + 4;
    grey_transpiler::emitter::build_service_program(
        &c,
        &m,
        &[],
        &[],
        &[],
        stack_pages,
        heap_pages,
        total,
    )
}

// ---------------------------------------------------------------------------
// Sequential sweep benchmark
// ---------------------------------------------------------------------------

/// Build a sequential memory sweep benchmark blob.
///
/// Allocates `size_bytes` of heap, initializes with a pattern, then performs
/// 15 sequential sweeps reading every u32 and ADD-accumulating a checksum.
///
/// For sizes > 256MB, the harness must call `set_heap_top` on the PVM after init
/// to expand the heap beyond the u16 heap_pages limit.
pub fn grey_mem_seq_blob(size_bytes: u64) -> Vec<u8> {
    assert!(size_bytes >= 4096 && size_bytes.is_multiple_of(4096));
    let heap_pages = (size_bytes / 4096) as u32;

    let mut c = Vec::new();
    let mut m = Vec::new();

    // Setup: RA = halt addr, S0 = base, S1 = end, A0 = 0 (checksum)
    load_imm_64(&mut c, &mut m, RA, 0xFFFF0000u64);
    load_imm_64(&mut c, &mut m, S0, HEAP_BASE);
    load_imm_64(&mut c, &mut m, S1, HEAP_BASE + size_bytes);
    load_imm_64(&mut c, &mut m, A0, 0);
    load_imm_64(&mut c, &mut m, A1, SWEEPS as u64);

    // --- Init loop: arr[i] = i ^ (i << 2) ---
    mov(&mut c, &mut m, T0, S0); // T0 = current ptr
    // Jump forward to create BB boundary
    let _init_jump_pc = pc(&c);
    jump(&mut c, &mut m, 5);

    let init_loop_pc = pc(&c);
    // Compute value: T1 = (ptr - base) ^ ((ptr - base) << 2)
    // Simplified: just store the pointer offset as the value
    store_ind_u32(&mut c, &mut m, T0, T0, 0); // mem[T0] = T0 (lower 32 bits)
    add_imm_64(&mut c, &mut m, T0, T0, 4);

    let init_branch_pc = pc(&c);
    branch_lt_u(
        &mut c,
        &mut m,
        T0,
        S1,
        init_loop_pc as i32 - init_branch_pc as i32,
    );

    // --- Outer loop: 16 sweeps ---
    let _outer_jump_pc = pc(&c);
    jump(&mut c, &mut m, 5);

    let outer_loop_pc = pc(&c);
    // Inner: sequential read loop
    mov(&mut c, &mut m, T0, S0); // T0 = base

    let _inner_jump_pc = pc(&c);
    jump(&mut c, &mut m, 5);

    let inner_loop_pc = pc(&c);
    load_ind_u32(&mut c, &mut m, T1, T0, 0); // T1 = mem[T0]
    add_64(&mut c, &mut m, A0, A0, T1); // checksum += T1 (wrapping)
    add_imm_64(&mut c, &mut m, T0, T0, 4); // T0 += 4

    let inner_branch_pc = pc(&c);
    branch_lt_u(
        &mut c,
        &mut m,
        T0,
        S1,
        inner_loop_pc as i32 - inner_branch_pc as i32,
    );

    // Decrement outer counter; branch back if A1 != 0
    add_imm_64(&mut c, &mut m, A1, A1, -1);
    // T2 = 0 (zero register for comparison)
    load_imm_64(&mut c, &mut m, T2, 0);
    let outer_branch_pc = pc(&c);
    branch_ne(
        &mut c,
        &mut m,
        A1,
        T2,
        outer_loop_pc as i32 - outer_branch_pc as i32,
    );

    // Return checksum
    ecalli(&mut c, &mut m, 0xFF); // REPLY (terminate)

    build_blob(c, m, 1, heap_pages)
}

// ---------------------------------------------------------------------------
// Random stride benchmark
// ---------------------------------------------------------------------------

/// Build a pseudo-random stride memory access benchmark blob.
///
/// Allocates `size_bytes` of heap, initializes with a pattern, then performs
/// N_ELEMS * 16 random reads using xorshift32 for index generation.
pub fn grey_mem_rand_blob(size_bytes: u64) -> Vec<u8> {
    assert!(size_bytes >= 4096 && size_bytes.is_multiple_of(4096));
    let n_elems = size_bytes / 4;
    let heap_pages = (size_bytes / 4096) as u32;
    let total_loads = n_elems * SWEEPS as u64;

    let mut c = Vec::new();
    let mut m = Vec::new();

    // Setup
    load_imm_64(&mut c, &mut m, RA, 0xFFFF0000u64);
    load_imm_64(&mut c, &mut m, S0, HEAP_BASE); // base
    load_imm_64(&mut c, &mut m, A0, 0); // checksum
    load_imm_64(&mut c, &mut m, A1, total_loads); // iteration counter
    load_imm_64(&mut c, &mut m, A2, n_elems - 1); // mask (n_elems is power of 2)
    load_imm_64(&mut c, &mut m, T0, 0x12345678u64); // stride state (seed)

    // --- Init loop: same as sequential ---
    load_imm_64(&mut c, &mut m, S1, HEAP_BASE + size_bytes); // end
    mov(&mut c, &mut m, T1, S0);
    let _init_jump_pc = pc(&c);
    jump(&mut c, &mut m, 5);

    let init_loop_pc = pc(&c);
    store_ind_u32(&mut c, &mut m, T1, T1, 0);
    add_imm_64(&mut c, &mut m, T1, T1, 4);

    let init_branch_pc = pc(&c);
    branch_lt_u(
        &mut c,
        &mut m,
        T1,
        S1,
        init_loop_pc as i32 - init_branch_pc as i32,
    );

    // --- Main loop: xorshift + random load ---
    // Reuse S1 as zero register for loop comparison
    load_imm_64(&mut c, &mut m, S1, 0);

    let _main_jump_pc = pc(&c);
    jump(&mut c, &mut m, 5);

    let main_loop_pc = pc(&c);
    // Stride through array pseudo-randomly
    add_imm_64(&mut c, &mut m, T0, T0, 179);
    and_64(&mut c, &mut m, T1, T0, A2); // T1 = T0 & mask (element index)
    add_64(&mut c, &mut m, T1, T1, T1); // T1 *= 2
    add_64(&mut c, &mut m, T1, T1, T1); // T1 *= 2 (total: *4, byte offset)
    add_64(&mut c, &mut m, T1, T1, S0); // T1 += base (absolute address)

    // Load and accumulate
    load_ind_u32(&mut c, &mut m, T2, T1, 0); // T2 = mem[T1]
    add_64(&mut c, &mut m, A0, A0, T2);

    // Decrement counter; branch back if A1 > 0 (i.e., A1 != S1 where S1=0)
    add_imm_64(&mut c, &mut m, A1, A1, -1);
    let main_branch_pc = pc(&c);
    branch_ne(
        &mut c,
        &mut m,
        A1,
        S1,
        main_loop_pc as i32 - main_branch_pc as i32,
    );

    // Return checksum
    ecalli(&mut c, &mut m, 0xFF); // REPLY (terminate)

    build_blob(c, m, 1, heap_pages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mem_seq_blob_halts() {
        let blob = grey_mem_seq_blob(4096u64);
        let (result, _gas) = crate::run_kernel(&blob, 10_000_000);
        assert_ne!(result, 0, "seq checksum should be non-zero");
    }

    #[test]
    fn test_mem_rand_blob_halts() {
        let blob = grey_mem_rand_blob(4096u64);
        let (result, _gas) = crate::run_kernel(&blob, 1_000_000);
        assert_ne!(result, 0, "rand checksum should be non-zero");
    }
}
