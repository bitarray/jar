//! PVM benchmark programs and helpers.
//!
//! Provides guest programs for benchmarking:
//! - `fib`: compute-intensive iterative Fibonacci
//! - `hostcall`: host-call-heavy with many ecalli invocations
//! - `sort`: insertion sort (compute + memory interleaved)
//! - `mem`: memory cache pressure (sequential + random access patterns)
//!
//! Each program is available in both grey-pvm blob format and polkavm blob format.

pub mod mem;

use grey_transpiler::assembler::{Assembler, Reg};

// ---------------------------------------------------------------------------
// Shared PVM runners
// ---------------------------------------------------------------------------

/// Default gas limit for standard benchmarks.
pub const GAS_LIMIT: u64 = 100_000_000;

/// Run a grey-pvm blob on the interpreter (parse + execute). Returns (result, gas_consumed).
pub fn run_grey_interpreter(blob: &[u8], gas: u64) -> (u64, u64) {
    let mut pvm = javm::program::initialize_program(blob, &[], gas).unwrap();
    loop {
        let (exit, _) = pvm.run();
        match exit {
            javm::ExitReason::Halt => break,
            javm::ExitReason::HostCall(_) => continue,
            other => panic!("unexpected exit: {:?}", other),
        }
    }
    (pvm.registers[7], gas - pvm.gas)
}

/// Run a grey-pvm blob on the recompiler (compile + execute). Returns (result, gas_consumed).
pub fn run_grey_recompiler(blob: &[u8], gas: u64) -> (u64, u64) {
    let mut pvm = javm::recompiler::initialize_program_recompiled(blob, &[], gas).unwrap();
    loop {
        match pvm.run() {
            javm::ExitReason::Halt => break,
            javm::ExitReason::HostCall(_) => continue,
            other => panic!("unexpected exit: {:?}", other),
        }
    }
    (pvm.registers()[7], gas - pvm.gas())
}

/// Number of Fibonacci iterations for the compute benchmark.
pub const FIB_N: u64 = 1_000_000;

/// Number of host-call rounds for the host-call benchmark.
pub const HOSTCALL_N: u64 = 100_000;

/// Number of u32 elements to sort.
pub const SORT_N: u32 = 1_000;

// ---------------------------------------------------------------------------
// Grey-PVM blob builders (using grey-transpiler assembler)
// ---------------------------------------------------------------------------

/// Build a compute-intensive Fibonacci program as a grey-pvm standard blob.
///
/// Computes fib(N) iteratively:
///   T0=0, T1=1, T2=counter
///   loop: S0 = T0+T1; T0=T1; T1=S0; T2++; if T2<N goto loop
///   result in A0 = T1
///   halt
pub fn grey_fib_blob(n: u64) -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_pages(1);
    asm.set_heap_pages(0);

    asm.load_imm_64(Reg::RA, 0xFFFF0000u64); // halt address (linear layout doesn't pre-set RA)
    asm.load_imm_64(Reg::T0, 0); // fib_prev = 0
    asm.load_imm_64(Reg::T1, 1); // fib_curr = 1
    asm.load_imm_64(Reg::T2, 0); // counter = 0
    asm.load_imm_64(Reg::S1, n); // N

    // Jump forward to the loop body — this is a terminator, so the next
    // instruction becomes a basic-block start that the backward branch can
    // target.
    let jump_pc = asm.current_offset();
    asm.jump(5); // jump offset = 5 bytes (size of the jump instruction itself)

    let loop_pc = asm.current_offset();
    assert_eq!(loop_pc, jump_pc + 5); // sanity check
    asm.add_64(Reg::S0, Reg::T0, Reg::T1); // temp = prev + curr
    asm.move_reg(Reg::T0, Reg::T1); // prev = curr
    asm.move_reg(Reg::T1, Reg::S0); // curr = temp
    asm.add_imm_64(Reg::T2, Reg::T2, 1); // counter++

    let branch_pc = asm.current_offset();
    let rel_offset = (loop_pc as i64) - (branch_pc as i64);
    emit_branch_lt_u(&mut asm, Reg::T2, Reg::S1, rel_offset as i32);

    asm.move_reg(Reg::A0, Reg::T1);
    // Halt: jump_ind RA, 0 (RA=0xFFFF0000 from standard init)
    asm.jump_ind(Reg::RA, 0);

    asm.build()
}

/// Build a host-call-heavy program as a grey-pvm standard blob.
///
/// Repeatedly calls ecalli(0) N times, then halts.
pub fn grey_hostcall_blob(n: u64) -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_pages(1);
    asm.set_heap_pages(0);

    asm.load_imm_64(Reg::RA, 0xFFFF0000u64); // halt address
    asm.load_imm_64(Reg::T0, 0);
    asm.load_imm_64(Reg::S1, n);

    // Jump forward to create a BB boundary for the loop target
    let jump_pc = asm.current_offset();
    asm.jump(5);

    let loop_pc = asm.current_offset();
    assert_eq!(loop_pc, jump_pc + 5);
    asm.ecalli(0);
    asm.add_imm_64(Reg::T0, Reg::T0, 1);

    let branch_pc = asm.current_offset();
    let rel_offset = (loop_pc as i64) - (branch_pc as i64);
    emit_branch_lt_u(&mut asm, Reg::T0, Reg::S1, rel_offset as i32);

    asm.move_reg(Reg::A0, Reg::T0);
    asm.jump_ind(Reg::RA, 0);

    asm.build()
}

/// Build an insertion-sort program as a grey-pvm standard blob.
///
/// Sorts an array of `n` u32 elements on the stack using insertion sort.
/// The array is initialized with a descending sequence (worst case):
///   `arr[i]` = n - i  →  `[n, n-1, n-2, ..., 2, 1]`
///
/// After sorting, result = `arr[0]` (should be 1).
///
/// This exercises realistic compute+memory interleaving:
///   - Inner loop: load, compare, store (memory) + index arithmetic (ALU)
///   - Outer loop: load key element, scan backwards, insert
///   - O(n²) comparisons and O(n²) memory moves for worst-case input
pub fn grey_sort_blob(n: u32) -> Vec<u8> {
    let array_bytes = n * 4;
    let stack_bytes = 4096 + array_bytes;
    let stack_pages = stack_bytes.div_ceil(4096);

    let mut c = Vec::new(); // code bytes
    let mut m = Vec::new(); // bitmask

    // Register assignments
    // In JAR v1 linear memory: φ[0]=RA (halt addr), φ[1]=SP
    const RA: u8 = 0; // return address (φ[0] = 0xFFFF0000 from init)
    const SP: u8 = 1; // stack pointer (φ[1] = s from init)
    const S0: u8 = 5; // array base
    const S1: u8 = 6; // n
    const T0: u8 = 2; // i (outer loop / init)
    const T1: u8 = 3; // j (inner loop)
    const T2: u8 = 4; // key
    const A0: u8 = 7; // temp / result
    const A1: u8 = 8; // scratch
    const A2: u8 = 9; // address scratch

    // === Emit helpers (inline for raw byte control) ===

    fn load_imm_64(c: &mut Vec<u8>, m: &mut Vec<u8>, rd: u8, val: u64) {
        c.push(20);
        m.push(1);
        c.push(rd);
        m.push(0);
        for i in 0..8 {
            c.push((val >> (i * 8)) as u8);
            m.push(0);
        }
    }
    fn add_imm_64(c: &mut Vec<u8>, m: &mut Vec<u8>, rd: u8, ra: u8, imm: i32) {
        c.push(149);
        m.push(1);
        c.push(rd | (ra << 4));
        m.push(0);
        for b in imm.to_le_bytes() {
            c.push(b);
            m.push(0);
        }
    }
    fn mov(c: &mut Vec<u8>, m: &mut Vec<u8>, rd: u8, ra: u8) {
        c.push(100);
        m.push(1);
        c.push(rd | (ra << 4));
        m.push(0);
    }
    fn sub_64(c: &mut Vec<u8>, m: &mut Vec<u8>, rd: u8, ra: u8, rb: u8) {
        c.push(201);
        m.push(1);
        c.push(ra | (rb << 4));
        m.push(0);
        c.push(rd);
        m.push(0);
    }
    fn add_64(c: &mut Vec<u8>, m: &mut Vec<u8>, rd: u8, ra: u8, rb: u8) {
        c.push(200);
        m.push(1);
        c.push(ra | (rb << 4));
        m.push(0);
        c.push(rd);
        m.push(0);
    }
    fn store_ind_u32(c: &mut Vec<u8>, m: &mut Vec<u8>, rd: u8, ra: u8, imm: i32) {
        c.push(122);
        m.push(1);
        c.push(rd | (ra << 4));
        m.push(0);
        for b in imm.to_le_bytes() {
            c.push(b);
            m.push(0);
        }
    }
    fn load_ind_u32(c: &mut Vec<u8>, m: &mut Vec<u8>, rd: u8, ra: u8, imm: i32) {
        c.push(128);
        m.push(1);
        c.push(rd | (ra << 4));
        m.push(0);
        for b in imm.to_le_bytes() {
            c.push(b);
            m.push(0);
        }
    }
    fn jump(c: &mut Vec<u8>, m: &mut Vec<u8>, offset: i32) {
        c.push(40);
        m.push(1);
        for b in offset.to_le_bytes() {
            c.push(b);
            m.push(0);
        }
    }
    fn jump_ind(c: &mut Vec<u8>, m: &mut Vec<u8>, rd: u8, imm: i32) {
        c.push(50);
        m.push(1);
        c.push(rd);
        m.push(0);
        for b in imm.to_le_bytes() {
            c.push(b);
            m.push(0);
        }
    }
    fn branch_lt_u(c: &mut Vec<u8>, m: &mut Vec<u8>, ra: u8, rb: u8, offset: i32) {
        c.push(172);
        m.push(1);
        c.push(ra | (rb << 4));
        m.push(0);
        for b in offset.to_le_bytes() {
            c.push(b);
            m.push(0);
        }
    }
    fn branch_lt_s_imm(c: &mut Vec<u8>, m: &mut Vec<u8>, rd: u8, imm: i32, offset: i32) {
        c.push(87);
        m.push(1);
        c.push(rd | (4 << 4));
        m.push(0);
        for b in imm.to_le_bytes() {
            c.push(b);
            m.push(0);
        }
        for b in offset.to_le_bytes() {
            c.push(b);
            m.push(0);
        }
    }
    // === INIT: set up array on stack ===
    // RA (φ[0]) is already 0xFFFF0000 from initialize_program
    load_imm_64(&mut c, &mut m, S1, n as u64);
    add_imm_64(&mut c, &mut m, SP, SP, -(array_bytes as i32));
    mov(&mut c, &mut m, S0, SP);
    load_imm_64(&mut c, &mut m, T0, 0); // i = 0

    let init_jump_pc = c.len();
    jump(&mut c, &mut m, 5); // → init_loop BB
    let init_loop_pc = c.len();
    assert_eq!(init_loop_pc, init_jump_pc + 5);

    // init_loop: arr[i] = n - i
    sub_64(&mut c, &mut m, T1, S1, T0); // T1 = n - i
    add_64(&mut c, &mut m, A1, T0, T0); // A1 = i*2
    add_64(&mut c, &mut m, A1, A1, A1); // A1 = i*4
    add_64(&mut c, &mut m, A2, S0, A1); // A2 = &arr[i]
    store_ind_u32(&mut c, &mut m, T1, A2, 0);
    add_imm_64(&mut c, &mut m, T0, T0, 1); // i++
    let br = c.len();
    branch_lt_u(&mut c, &mut m, T0, S1, (init_loop_pc as i32) - (br as i32));

    // === INSERTION SORT ===
    //
    // Control flow (avoids forward branches by restructuring inner loop):
    //
    //   outer_loop:                    ← BB (backward branch target)
    //     key = arr[i]; j = i-1
    //     jump inner_test
    //   inner_loop:                    ← BB (backward branch target)
    //     arr[j+1] = arr[j]; j--
    //   inner_test:                    ← BB (jump target from outer_loop)
    //     if j < 0 goto insert         (forward branch — patched)
    //     load arr[j]
    //     if key < arr[j] goto inner_loop   (backward branch)
    //   insert:                        ← falls through from inner_test
    //     arr[j+1] = key; i++
    //     if i < n goto outer_loop     (backward branch)

    load_imm_64(&mut c, &mut m, T0, 1); // i = 1

    let _outer_jump_pc = c.len();
    jump(&mut c, &mut m, 5); // → outer_loop BB
    let outer_loop_pc = c.len();

    // Load key = arr[i]
    add_64(&mut c, &mut m, A1, T0, T0); // A1 = i*2
    add_64(&mut c, &mut m, A1, A1, A1); // A1 = i*4
    add_64(&mut c, &mut m, A2, S0, A1); // A2 = &arr[i]
    load_ind_u32(&mut c, &mut m, T2, A2, 0); // key = arr[i]
    add_imm_64(&mut c, &mut m, T1, T0, -1); // j = i - 1

    // Jump forward to inner_test
    let inner_entry_pc = c.len();
    jump(&mut c, &mut m, 0); // placeholder — will patch

    // inner_loop: shift element right, decrement j
    let inner_loop_pc = c.len();
    // At this point A0 = arr[j] (loaded in inner_test), A2 = &arr[j]
    store_ind_u32(&mut c, &mut m, A0, A2, 4); // arr[j+1] = arr[j]
    add_imm_64(&mut c, &mut m, T1, T1, -1); // j--
    // Fallthrough (opcode 1) — terminates this BB so inner_test is a BB start
    c.push(1);
    m.push(1);

    // inner_test: check j >= 0, load arr[j], compare
    let inner_test_pc = c.len();

    // if j < 0 goto insert (forward branch — will patch offset)
    let j_check_pc = c.len();
    branch_lt_s_imm(&mut c, &mut m, T1, 0, 0); // placeholder offset
    // BranchLtSImm size = 1 + 1 + 4 + 4 = 10 bytes

    // Load arr[j]
    add_64(&mut c, &mut m, A1, T1, T1); // A1 = j*2
    add_64(&mut c, &mut m, A1, A1, A1); // A1 = j*4
    add_64(&mut c, &mut m, A2, S0, A1); // A2 = &arr[j]
    load_ind_u32(&mut c, &mut m, A0, A2, 0); // A0 = arr[j]

    // if key < arr[j] → inner_loop (backward branch)
    let cmp_pc = c.len();
    branch_lt_u(
        &mut c,
        &mut m,
        T2,
        A0,
        (inner_loop_pc as i32) - (cmp_pc as i32),
    );

    // === INSERT: arr[j+1] = key ===
    let insert_pc = c.len();
    add_imm_64(&mut c, &mut m, A1, T1, 1); // A1 = j+1
    add_64(&mut c, &mut m, A1, A1, A1); // A1 = (j+1)*2
    add_64(&mut c, &mut m, A1, A1, A1); // A1 = (j+1)*4
    add_64(&mut c, &mut m, A2, S0, A1); // A2 = &arr[j+1]
    store_ind_u32(&mut c, &mut m, T2, A2, 0); // arr[j+1] = key
    add_imm_64(&mut c, &mut m, T0, T0, 1); // i++
    let outer_br = c.len();
    branch_lt_u(
        &mut c,
        &mut m,
        T0,
        S1,
        (outer_loop_pc as i32) - (outer_br as i32),
    );

    // === DONE ===
    load_ind_u32(&mut c, &mut m, A0, S0, 0); // result = arr[0] (should be 1)
    jump_ind(&mut c, &mut m, RA, 0); // halt

    // === Patch forward jumps ===
    // 1. inner_entry jump → inner_test
    let offset = (inner_test_pc as i32) - (inner_entry_pc as i32);
    c[inner_entry_pc + 1..inner_entry_pc + 5].copy_from_slice(&offset.to_le_bytes());

    // 2. j < 0 branch → insert (BranchLtSImm: opcode(1) + reg(1) + imm(4) + offset(4))
    let offset = (insert_pc as i32) - (j_check_pc as i32);
    c[j_check_pc + 6..j_check_pc + 10].copy_from_slice(&offset.to_le_bytes());

    grey_transpiler::emitter::build_standard_program(&[], &[], 0, 0, stack_pages, &c, &m, &[])
}

fn emit_branch_lt_u(asm: &mut Assembler, ra: Reg, rb: Reg, rel_offset: i32) {
    asm.emit_raw(172, true);
    asm.emit_raw((ra as u8) | ((rb as u8) << 4), false);
    let bytes = rel_offset.to_le_bytes();
    for &b in &bytes {
        asm.emit_raw(b, false);
    }
}

// ---------------------------------------------------------------------------
// PolkaVM blob builders (using polkavm-common ProgramBlobBuilder)
// ---------------------------------------------------------------------------

use polkavm_common::program::{Instruction as PInst, Reg as PReg};
use polkavm_common::writer::ProgramBlobBuilder;

fn pr(reg: PReg) -> polkavm_common::program::RawReg {
    reg.into()
}

/// Build the same Fibonacci program as a polkavm blob.
pub fn polkavm_fib_blob(n: u64) -> Vec<u8> {
    let isa = polkavm_common::program::InstructionSetKind::JamV1;
    let mut builder = ProgramBlobBuilder::new(isa);
    builder.set_stack_size(4096);

    let code = vec![
        // BB0: init
        PInst::load_imm64(pr(PReg::T0), 0),
        PInst::load_imm64(pr(PReg::T1), 1),
        PInst::load_imm64(pr(PReg::T2), 0),
        PInst::load_imm64(pr(PReg::S1), n),
        PInst::jump(1),
        // BB1: loop body
        PInst::add_64(pr(PReg::S0), pr(PReg::T0), pr(PReg::T1)),
        PInst::move_reg(pr(PReg::T0), pr(PReg::T1)),
        PInst::move_reg(pr(PReg::T1), pr(PReg::S0)),
        PInst::add_imm_64(pr(PReg::T2), pr(PReg::T2), 1),
        PInst::branch_less_unsigned(pr(PReg::T2), pr(PReg::S1), 1),
        // BB2: done
        PInst::move_reg(pr(PReg::A0), pr(PReg::T1)),
        PInst::jump_indirect(pr(PReg::RA), 0),
    ];

    builder.set_code(&code, &[]);
    builder.add_export_by_basic_block(0, b"main");
    builder.to_vec().expect("failed to build polkavm fib blob")
}

/// Build the same insertion-sort program as a polkavm blob.
pub fn polkavm_sort_blob(n: u32) -> Vec<u8> {
    let array_bytes = n * 4;
    let stack_size = 4096 + array_bytes;
    let isa = polkavm_common::program::InstructionSetKind::JamV1;
    let mut builder = ProgramBlobBuilder::new(isa);
    builder.set_stack_size(stack_size);

    // PolkaVM uses basic-block indices for branch targets.
    // BB layout:
    //   BB0: init constants, jump BB1
    //   BB1: init_loop body, branch_lt_u → BB1 (back), fallthrough → BB2
    //   BB2: set i=1, jump BB3
    //   BB3: outer_loop: load key, j=i-1, jump BB5 (inner_test)
    //   BB4: inner_loop: shift right, j--, fallthrough → BB5
    //   BB5: inner_test: if j<0 → BB6, load arr[j], if key<arr[j] → BB4, fallthrough → BB6
    //   BB6: insert: arr[j+1]=key, i++, branch_lt_u → BB3, fallthrough → BB7
    //   BB7: done: load result, halt

    let code = vec![
        // BB0: init
        PInst::load_imm64(pr(PReg::S1), n as u64), // S1 = n
        PInst::add_imm_64(pr(PReg::SP), pr(PReg::SP), (-(array_bytes as i32)) as u32),
        PInst::move_reg(pr(PReg::S0), pr(PReg::SP)), // S0 = array base
        PInst::load_imm64(pr(PReg::T0), 0),          // i = 0
        PInst::jump(1),                              // → BB1
        // BB1: init_loop
        PInst::sub_64(pr(PReg::T1), pr(PReg::S1), pr(PReg::T0)), // T1 = n - i
        PInst::add_64(pr(PReg::A1), pr(PReg::T0), pr(PReg::T0)), // A1 = i*2
        PInst::add_64(pr(PReg::A1), pr(PReg::A1), pr(PReg::A1)), // A1 = i*4
        PInst::add_64(pr(PReg::A2), pr(PReg::S0), pr(PReg::A1)), // A2 = &arr[i]
        PInst::store_indirect_u32(pr(PReg::T1), pr(PReg::A2), 0),
        PInst::add_imm_64(pr(PReg::T0), pr(PReg::T0), 1), // i++
        PInst::branch_less_unsigned(pr(PReg::T0), pr(PReg::S1), 1), // if i<n → BB1
        // BB2: setup sort
        PInst::load_imm64(pr(PReg::T0), 1), // i = 1
        PInst::jump(3),                     // → BB3
        // BB3: outer_loop — load key, setup j
        PInst::add_64(pr(PReg::A1), pr(PReg::T0), pr(PReg::T0)),
        PInst::add_64(pr(PReg::A1), pr(PReg::A1), pr(PReg::A1)),
        PInst::add_64(pr(PReg::A2), pr(PReg::S0), pr(PReg::A1)),
        PInst::load_indirect_u32(pr(PReg::T2), pr(PReg::A2), 0), // key = arr[i]
        PInst::add_imm_64(pr(PReg::T1), pr(PReg::T0), (-1i32) as u32), // j = i-1
        PInst::jump(5),                                          // → BB5 (inner_test)
        // BB4: inner_loop — shift right, j--
        PInst::store_indirect_u32(pr(PReg::A0), pr(PReg::A2), 4), // arr[j+1] = arr[j]
        PInst::add_imm_64(pr(PReg::T1), pr(PReg::T1), (-1i32) as u32), // j--
        PInst::fallthrough,                                       // end BB4 → BB5
        // BB5: inner_test
        PInst::branch_less_signed_imm(pr(PReg::T1), 0, 7), // if j<0 → BB7 (insert)
        PInst::add_64(pr(PReg::A1), pr(PReg::T1), pr(PReg::T1)),
        PInst::add_64(pr(PReg::A1), pr(PReg::A1), pr(PReg::A1)),
        PInst::add_64(pr(PReg::A2), pr(PReg::S0), pr(PReg::A1)),
        PInst::load_indirect_u32(pr(PReg::A0), pr(PReg::A2), 0), // A0 = arr[j]
        PInst::branch_less_unsigned(pr(PReg::T2), pr(PReg::A0), 4), // if key<arr[j] → BB4
        // BB6: insert
        PInst::add_imm_64(pr(PReg::A1), pr(PReg::T1), 1), // A1 = j+1
        PInst::add_64(pr(PReg::A1), pr(PReg::A1), pr(PReg::A1)),
        PInst::add_64(pr(PReg::A1), pr(PReg::A1), pr(PReg::A1)),
        PInst::add_64(pr(PReg::A2), pr(PReg::S0), pr(PReg::A1)),
        PInst::store_indirect_u32(pr(PReg::T2), pr(PReg::A2), 0), // arr[j+1] = key
        PInst::add_imm_64(pr(PReg::T0), pr(PReg::T0), 1),         // i++
        PInst::branch_less_unsigned(pr(PReg::T0), pr(PReg::S1), 3), // if i<n → BB3
        // BB7: done
        PInst::load_indirect_u32(pr(PReg::A0), pr(PReg::S0), 0), // result = arr[0]
        PInst::jump_indirect(pr(PReg::RA), 0),                   // halt
    ];

    builder.set_code(&code, &[]);
    builder.add_export_by_basic_block(0, b"main");
    builder.to_vec().expect("failed to build polkavm sort blob")
}

/// Build the same host-call-heavy program as a polkavm blob.
pub fn polkavm_hostcall_blob(n: u64) -> Vec<u8> {
    let isa = polkavm_common::program::InstructionSetKind::JamV1;
    let mut builder = ProgramBlobBuilder::new(isa);
    builder.set_stack_size(4096);
    builder.add_import(b"host_gas");

    let code = vec![
        // BB0: init
        PInst::load_imm64(pr(PReg::T0), 0),
        PInst::load_imm64(pr(PReg::S1), n),
        PInst::jump(1),
        // BB1: loop
        PInst::ecalli(0),
        PInst::add_imm_64(pr(PReg::T0), pr(PReg::T0), 1),
        PInst::branch_less_unsigned(pr(PReg::T0), pr(PReg::S1), 1),
        // BB2: done
        PInst::move_reg(pr(PReg::A0), pr(PReg::T0)),
        PInst::jump_indirect(pr(PReg::RA), 0),
    ];

    builder.set_code(&code, &[]);
    builder.add_export_by_basic_block(0, b"main");
    builder
        .to_vec()
        .expect("failed to build polkavm hostcall blob")
}

// ---------------------------------------------------------------------------
// Ecrecover benchmark: secp256k1 ECDSA public key recovery (k256 crate)
// ELFs are auto-built by build.rs via build-javm and build-pvm crates.
// ---------------------------------------------------------------------------

include!(concat!(env!("OUT_DIR"), "/guest_blobs.rs"));

/// Grey PVM blob for ecrecover (pre-built and transpiled at compile time).
pub fn grey_ecrecover_blob() -> &'static [u8] {
    GREY_ECRECOVER_BLOB
}

/// PolkaVM blob for ecrecover (pre-built and linked at compile time).
pub fn polkavm_ecrecover_blob() -> &'static [u8] {
    POLKAVM_ECRECOVER_BLOB
}

/// Grey PVM blob for prime sieve (pre-built and transpiled at compile time).
pub fn grey_sieve_blob() -> &'static [u8] {
    GREY_SIEVE_BLOB
}

/// PolkaVM blob for prime sieve (pre-built and linked at compile time).
pub fn polkavm_sieve_blob() -> &'static [u8] {
    POLKAVM_SIEVE_BLOB
}

pub fn grey_ed25519_blob() -> &'static [u8] {
    GREY_ED25519_BLOB
}
pub fn polkavm_ed25519_blob() -> &'static [u8] {
    POLKAVM_ED25519_BLOB
}
pub fn grey_blake2b_blob() -> &'static [u8] {
    GREY_BLAKE2B_BLOB
}
pub fn polkavm_blake2b_blob() -> &'static [u8] {
    POLKAVM_BLAKE2B_BLOB
}
pub fn grey_keccak_blob() -> &'static [u8] {
    GREY_KECCAK_BLOB
}
pub fn polkavm_keccak_blob() -> &'static [u8] {
    POLKAVM_KECCAK_BLOB
}

/// Grey PVM service blob for sample-service (refine at PC=0, accumulate at PC=5).
pub fn sample_service_blob() -> &'static [u8] {
    SAMPLE_SERVICE_BLOB
}

#[cfg(test)]
mod tests_sort {
    use super::*;

    #[test]
    fn test_grey_sort_small() {
        let blob = grey_sort_blob(5);
        let mut pvm = javm::program::initialize_program(&blob, &[], 10_000_000).unwrap();
        pvm.tracing_enabled = true;
        loop {
            let (exit, _) = pvm.run();
            match exit {
                javm::ExitReason::Halt => {
                    eprintln!("HALT! result = {}", pvm.registers[7]);
                    assert_eq!(pvm.registers[7], 1, "arr[0] should be 1 after sorting");
                    return;
                }
                javm::ExitReason::HostCall(_) => continue,
                other => {
                    eprintln!("Exit: {:?} at PC={}", other, pvm.pc);
                    let len = pvm.pc_trace.len();
                    let start = len.saturating_sub(30);
                    for (pc, opcode) in &pvm.pc_trace[start..] {
                        eprintln!("  PC={} opcode={}", pc, opcode);
                    }
                    eprintln!("Registers: {:?}", &pvm.registers);
                    panic!("unexpected exit: {:?}", other);
                }
            }
        }
    }

    #[test]
    fn test_ecrecover_code_size() {
        let grey_blob = grey_ecrecover_blob();
        let grey_pvm = javm::program::initialize_program(grey_blob, &[], 1000).unwrap();
        let grey_inst_count: usize = grey_pvm.bitmask.iter().filter(|&&b| b == 1).count();
        eprintln!(
            "Grey PVM:  code={} bytes, {} instructions",
            grey_pvm.code.len(),
            grey_inst_count
        );

        let pvm_blob = polkavm_ecrecover_blob();
        eprintln!("PolkaVM:   blob={} bytes", pvm_blob.len());
    }

    #[test]
    fn test_grey_ecrecover() {
        let blob = grey_ecrecover_blob();
        let mut pvm = javm::program::initialize_program(blob, &[], 100_000_000_000).unwrap();
        loop {
            let (exit, _) = pvm.run();
            match exit {
                javm::ExitReason::Halt => {
                    let gas_used = 100_000_000_000u64 - pvm.gas;
                    eprintln!("ecrecover: a0={} gas_used={}", pvm.registers[7], gas_used);
                    assert!(
                        gas_used > 1_000_000,
                        "ecrecover should use >1M gas, got {gas_used}"
                    );
                    assert_eq!(pvm.registers[7], 1, "ecrecover should return 1 (success)");
                    return;
                }
                javm::ExitReason::Panic => {
                    panic!(
                        "ecrecover panicked at PC={} gas_remaining={}",
                        pvm.pc, pvm.gas
                    );
                }
                javm::ExitReason::HostCall(_) => continue,
                other => panic!("unexpected exit: {:?}", other),
            }
        }
    }

    /// Run blob on both interpreter and recompiler, assert a0 and gas match.
    fn assert_interp_recomp(blob: &[u8], expected_a0: u64, min_gas: u64, name: &str) {
        let gas = 100_000_000_000u64;

        // Run interpreter
        let mut interp = javm::program::initialize_program(blob, &[], gas).unwrap();
        loop {
            match interp.run().0 {
                javm::ExitReason::Halt => break,
                javm::ExitReason::Panic => {
                    panic!("{name}: interpreter panicked at PC={}", interp.pc)
                }
                javm::ExitReason::HostCall(_) => continue,
                other => panic!("{name}: interpreter unexpected exit: {other:?}"),
            }
        }
        let interp_gas = gas - interp.gas;
        let interp_a0 = interp.registers[7];

        assert_eq!(interp_a0, expected_a0, "{name}: interpreter a0 mismatch");

        // Run recompiler
        let mut recomp = javm::recompiler::initialize_program_recompiled(blob, &[], gas).unwrap();
        loop {
            match recomp.run() {
                javm::ExitReason::Halt => break,
                javm::ExitReason::Panic => panic!("{name}: recompiler panicked"),
                javm::ExitReason::HostCall(_) => continue,
                other => panic!("{name}: recompiler unexpected exit: {other:?}"),
            }
        }
        let recomp_gas = gas - recomp.gas();
        let recomp_a0 = recomp.registers()[7];

        assert_eq!(recomp_a0, interp_a0, "{name}: recompiler a0 mismatch");
        assert!(
            interp_gas > min_gas,
            "{name}: should use >{min_gas} gas, got {interp_gas}"
        );
        assert_eq!(
            interp_gas, recomp_gas,
            "{name}: gas mismatch: interpreter={interp_gas} recompiler={recomp_gas}"
        );
    }

    #[test]
    fn test_grey_ecrecover_recompiler() {
        assert_interp_recomp(grey_ecrecover_blob(), 1, 100_000, "ecrecover");
    }

    #[test]
    fn test_grey_prime_sieve_recompiler() {
        assert_interp_recomp(grey_sieve_blob(), 9592, 100_000, "prime_sieve");
    }

    #[test]
    fn test_grey_ed25519_recompiler() {
        assert_interp_recomp(grey_ed25519_blob(), 1, 1_000, "ed25519");
    }

    #[test]
    fn test_grey_blake2b_recompiler() {
        // blake2b-256 of [0x00..0xFF]*4: first 4 bytes LE = 0xEE1F55F1, sign-extended on rv64
        assert_interp_recomp(grey_blake2b_blob(), 0xFFFFFFFFEE1F55F1, 10_000, "blake2b");
    }

    #[test]
    fn test_grey_keccak_recompiler() {
        // keccak-256 of [0x00..0xFF]*4: first 4 bytes LE = 0x39E50259
        assert_interp_recomp(grey_keccak_blob(), 0x39E50259, 10_000, "keccak");
    }

    #[test]
    fn test_sample_service_loadable() {
        let blob = sample_service_blob();
        assert!(!blob.is_empty());
        let pvm = javm::program::initialize_program(blob, &[], 10_000);
        assert!(
            pvm.is_some(),
            "sample service blob should be loadable by PVM"
        );
    }

    #[test]
    fn test_sample_service_refine_halts() {
        let blob = sample_service_blob();
        let mut pvm =
            javm::program::initialize_program(blob, &[], 10_000).expect("blob should be loadable");
        let (result, _gas) = pvm.run();
        assert!(
            result == javm::ExitReason::Halt || result == javm::ExitReason::Panic,
            "refine should halt or panic; got {:?}",
            result
        );
    }

    #[test]
    fn test_sample_service_accumulate_host_write() {
        let blob = sample_service_blob();
        let mut pvm =
            javm::program::initialize_program(blob, &[], 10_000).expect("blob should be loadable");
        pvm.pc = 5;
        let (result, _gas) = pvm.run();
        match result {
            javm::ExitReason::HostCall(id) => {
                assert_eq!(id, 4, "expected host_write (ID=4), got ID={}", id);
            }
            other => panic!("expected HostCall(4), got {:?}", other),
        }
    }
}
