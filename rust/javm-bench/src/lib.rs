//! PVM benchmark programs and helpers.
//!
//! Provides guest programs for benchmarking:
//! - `fib`: compute-intensive iterative Fibonacci
//! - `hostcall`: host-call-heavy with many ecalli invocations
//! - `sort`: insertion sort (compute + memory interleaved)
//! - `mem`: memory cache pressure (sequential + random access patterns)
//!
//! Each program is available in both javm blob format and polkavm blob format.

pub mod mem;

use javm_transpiler::assembler::{Assembler, Reg};

// ---------------------------------------------------------------------------
// Shared PVM runners
// ---------------------------------------------------------------------------

/// Default gas limit for standard benchmarks.
pub const GAS_LIMIT: u64 = 100_000_000;

/// Run a javm blob on the kernel. Returns (result, gas_consumed).
pub fn run_kernel(blob: &[u8], gas: u64) -> (u64, u64) {
    run_kernel_with_backend(blob, gas, javm::PvmBackend::Default)
}

/// Run a javm blob on the kernel with a specific backend. Returns (result, gas_consumed).
pub fn run_kernel_with_backend(blob: &[u8], gas: u64, backend: javm::PvmBackend) -> (u64, u64) {
    let mut kernel = javm::kernel::InvocationKernel::new_with_backend(blob, &[], gas, backend)
        .expect("kernel init failed");
    loop {
        match kernel.run() {
            javm::kernel::KernelResult::Halt(v) => return (v, gas - kernel.active_gas()),
            javm::kernel::KernelResult::Panic => {
                let vm = &kernel.vm_arena.vm(kernel.active_vm);
                panic!("kernel panicked at PC={} gas={}", vm.pc, vm.gas());
            }
            javm::kernel::KernelResult::OutOfGas => panic!("kernel out of gas"),
            javm::kernel::KernelResult::PageFault(a) => {
                let vm = &kernel.vm_arena.vm(kernel.active_vm);
                panic!("kernel page fault at {a:#x} PC={} gas={}", vm.pc, vm.gas());
            }
            javm::kernel::KernelResult::ProtocolCall { .. } => continue,
        }
    }
}

/// Run a javm blob on the interpreter (via kernel). Returns (result, gas_consumed).
pub fn run_javm_interpreter(blob: &[u8], gas: u64) -> (u64, u64) {
    run_kernel_with_backend(blob, gas, javm::PvmBackend::ForceInterpreter)
}

/// Run a javm blob on the recompiler (via kernel). Returns (result, gas_consumed).
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn run_javm_recompiler(blob: &[u8], gas: u64) -> (u64, u64) {
    run_kernel_with_backend(blob, gas, javm::PvmBackend::ForceRecompiler)
}

/// Number of Fibonacci iterations for the compute benchmark.
pub const FIB_N: u64 = 1_000_000;

/// Number of host-call rounds for the host-call benchmark.
pub const HOSTCALL_N: u64 = 100_000;

/// Number of u32 elements to sort.
pub const SORT_N: u32 = 1_000;

// ---------------------------------------------------------------------------
// javm blob builders (using javm-transpiler assembler)
// ---------------------------------------------------------------------------

/// Build a compute-intensive Fibonacci program as a javm standard blob.
///
/// Computes fib(N) iteratively:
///   T0=0, T1=1, T2=counter
///   loop: S0 = T0+T1; T0=T1; T1=S0; T2++; if T2<N goto loop
///   result in A0 = T1
///   halt
pub fn javm_fib_blob(n: u64) -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_pages(1);
    asm.set_heap_pages(0);

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
    // Terminate via REPLY (IPC slot 0)
    asm.ecalli(0x00);

    asm.build()
}

/// Build a host-call-heavy program as a javm standard blob.
///
/// Repeatedly calls ecalli(1) (GAS) N times, then halts.
pub fn javm_hostcall_blob(n: u64) -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_pages(1);
    asm.set_heap_pages(0);

    asm.load_imm_64(Reg::T0, 0);
    asm.load_imm_64(Reg::S1, n);

    // Jump forward to create a BB boundary for the loop target
    let jump_pc = asm.current_offset();
    asm.jump(5);

    let loop_pc = asm.current_offset();
    assert_eq!(loop_pc, jump_pc + 5);
    asm.ecalli(1); // GAS (protocol cap slot 1, not IPC slot 0)
    asm.add_imm_64(Reg::T0, Reg::T0, 1);

    let branch_pc = asm.current_offset();
    let rel_offset = (loop_pc as i64) - (branch_pc as i64);
    emit_branch_lt_u(&mut asm, Reg::T0, Reg::S1, rel_offset as i32);

    asm.move_reg(Reg::A0, Reg::T0);
    asm.ecalli(0x00); // REPLY (IPC slot 0)

    asm.build()
}

/// Build an insertion-sort program as a javm standard blob.
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
pub fn javm_sort_blob(n: u32) -> Vec<u8> {
    let array_bytes = n * 4;
    let stack_bytes = 4096 + array_bytes;
    let stack_pages = stack_bytes.div_ceil(4096);

    let mut c = Vec::new(); // code bytes
    let mut m = Vec::new(); // bitmask

    // Register assignments
    const SP: u8 = 1; // stack pointer
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
    fn ecalli(c: &mut Vec<u8>, m: &mut Vec<u8>, imm: u32) {
        c.push(10); // ecalli opcode
        m.push(1);
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
    // Set SP to top of stack (v2: stack mapped at page 0, SP = stack_pages * 4096)
    load_imm_64(&mut c, &mut m, SP, (stack_pages * 4096) as u64);
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
    ecalli(&mut c, &mut m, 0x00); // REPLY (IPC slot 0)

    // === Patch forward jumps ===
    // 1. inner_entry jump → inner_test
    let offset = (inner_test_pc as i32) - (inner_entry_pc as i32);
    c[inner_entry_pc + 1..inner_entry_pc + 5].copy_from_slice(&offset.to_le_bytes());

    // 2. j < 0 branch → insert (BranchLtSImm: opcode(1) + reg(1) + imm(4) + offset(4))
    let offset = (insert_pc as i32) - (j_check_pc as i32);
    c[j_check_pc + 6..j_check_pc + 10].copy_from_slice(&offset.to_le_bytes());

    javm_transpiler::emitter::build_service_program(
        &c,
        &m,
        &[],
        &[],
        &[],
        stack_pages,
        0,
        stack_pages + 4,
    )
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

/// javm blob for ecrecover (pre-built and transpiled at compile time).
pub fn javm_ecrecover_blob() -> &'static [u8] {
    JAVM_ECRECOVER_BLOB
}

/// PolkaVM blob for ecrecover (pre-built and linked at compile time).
pub fn polkavm_ecrecover_blob() -> &'static [u8] {
    POLKAVM_ECRECOVER_BLOB
}

/// javm blob for prime sieve (pre-built and transpiled at compile time).
pub fn javm_sieve_blob() -> &'static [u8] {
    JAVM_SIEVE_BLOB
}

/// PolkaVM blob for prime sieve (pre-built and linked at compile time).
pub fn polkavm_sieve_blob() -> &'static [u8] {
    POLKAVM_SIEVE_BLOB
}

pub fn javm_ed25519_blob() -> &'static [u8] {
    JAVM_ED25519_BLOB
}
pub fn polkavm_ed25519_blob() -> &'static [u8] {
    POLKAVM_ED25519_BLOB
}
pub fn javm_blake2b_blob() -> &'static [u8] {
    JAVM_BLAKE2B_BLOB
}
pub fn polkavm_blake2b_blob() -> &'static [u8] {
    POLKAVM_BLAKE2B_BLOB
}
pub fn javm_keccak_blob() -> &'static [u8] {
    JAVM_KECCAK_BLOB
}
pub fn polkavm_keccak_blob() -> &'static [u8] {
    POLKAVM_KECCAK_BLOB
}

// ---------------------------------------------------------------------------
// Sub-VM benchmark: recursive fibonacci via CALL(CODE) + CALL(HANDLE)
// ---------------------------------------------------------------------------

/// Default N for recursive fib benchmark. fib(20) = 6765, creates ~21890 VMs.
pub const FIB_RECUR_N: u64 = 20;

/// Build a recursive fibonacci PVM blob that exercises CALL(CODE) and CALL(HANDLE).
///
/// Each invocation reads N from φ\[7\]. If N < 2, REPLY(N). Otherwise:
/// CREATE two child VMs (CALL CODE), CALL each with N-1 and N-2, REPLY(sum).
///
/// CODE cap is at slot 32 (within CREATE bitmask range). Children inherit it
/// via the bitmask, so recursive creation works without COPY+GRANT.
///
/// memory_pages=0: no UNTYPED, no stack, no heap. Pure register computation.
pub fn javm_fib_recur_blob() -> Vec<u8> {
    use javm::cap::Access;
    use javm::program::{CapEntryType, CapManifestEntry, build_blob};

    // Build PVM code using raw byte emission (need precise control over offsets)
    let mut code = Vec::new();
    let mut bitmask = Vec::new();

    let push_inst = |c: &mut Vec<u8>, m: &mut Vec<u8>, byte: u8| {
        c.push(byte);
        m.push(1);
    };
    let push_data = |c: &mut Vec<u8>, m: &mut Vec<u8>, byte: u8| {
        c.push(byte);
        m.push(0);
    };

    // PC 0: branch_lt_u_imm A0, 2, offset=82 (10 bytes)
    // If N < 2, jump to reply at PC=82 (post-fallthrough = gas block start)
    push_inst(&mut code, &mut bitmask, 83); // opcode: branch_lt_u_imm
    let reg_byte = (Reg::A0 as u8) | (4 << 4); // rA=A0, lX=4
    push_data(&mut code, &mut bitmask, reg_byte);
    // imm = 2 (4 bytes LE)
    for &b in &2i32.to_le_bytes() {
        push_data(&mut code, &mut bitmask, b);
    }
    // offset = 94 (4 bytes LE, signed relative to PC=0, target = reply at PC 94)
    for &b in &94i32.to_le_bytes() {
        push_data(&mut code, &mut bitmask, b);
    }

    // PC 10: move_reg S0, A0 (2 bytes) — save N
    push_inst(&mut code, &mut bitmask, 100);
    push_data(
        &mut code,
        &mut bitmask,
        (Reg::S0 as u8) | ((Reg::A0 as u8) << 4),
    );

    // CREATE child1: φ[7]=bitmask(1<<32), φ[12]=dst_slot(64)
    // PC 12: load_imm_64 A0, 1<<32 (10 bytes) — bitmask: bit 32 = CODE cap
    push_inst(&mut code, &mut bitmask, 20);
    push_data(&mut code, &mut bitmask, Reg::A0 as u8);
    for i in 0..8 {
        push_data(&mut code, &mut bitmask, ((1u64 << 32) >> (i * 8)) as u8);
    }

    // PC 22: load_imm A5, 64 (6 bytes) — dst_slot = 64 for HANDLE
    push_inst(&mut code, &mut bitmask, 51);
    push_data(&mut code, &mut bitmask, Reg::A5 as u8);
    for &b in &64i32.to_le_bytes() {
        push_data(&mut code, &mut bitmask, b);
    }

    // PC 28: ecalli(32) (5 bytes) — CREATE child1 → handle at slot 64
    push_inst(&mut code, &mut bitmask, 10);
    for &b in &32u32.to_le_bytes() {
        push_data(&mut code, &mut bitmask, b);
    }

    // CREATE child2: φ[7]=bitmask(1<<32), φ[12]=dst_slot(65)
    // PC 33: load_imm_64 A0, 1<<32 (10 bytes) — bitmask
    push_inst(&mut code, &mut bitmask, 20);
    push_data(&mut code, &mut bitmask, Reg::A0 as u8);
    for i in 0..8 {
        push_data(&mut code, &mut bitmask, ((1u64 << 32) >> (i * 8)) as u8);
    }

    // PC 43: load_imm A5, 65 (6 bytes) — dst_slot = 65 for HANDLE
    push_inst(&mut code, &mut bitmask, 51);
    push_data(&mut code, &mut bitmask, Reg::A5 as u8);
    for &b in &65i32.to_le_bytes() {
        push_data(&mut code, &mut bitmask, b);
    }

    // PC 49: ecalli(32) (5 bytes) — CREATE child2 → handle at slot 65
    push_inst(&mut code, &mut bitmask, 10);
    for &b in &32u32.to_le_bytes() {
        push_data(&mut code, &mut bitmask, b);
    }

    // CALL child1 with N-1: φ[7]=N-1, φ[12]=0 (no IPC cap)
    // PC 54: add_imm_64 A0, S0, -1 (6 bytes) — A0 = N-1
    push_inst(&mut code, &mut bitmask, 149);
    push_data(
        &mut code,
        &mut bitmask,
        (Reg::A0 as u8) | ((Reg::S0 as u8) << 4),
    );
    for &b in &(-1i32).to_le_bytes() {
        push_data(&mut code, &mut bitmask, b);
    }

    // PC 60: load_imm A5, 0 (6 bytes) — φ[12] = 0 (no IPC cap, slot 0 = IPC itself)
    push_inst(&mut code, &mut bitmask, 51);
    push_data(&mut code, &mut bitmask, Reg::A5 as u8);
    for &b in &0i32.to_le_bytes() {
        push_data(&mut code, &mut bitmask, b);
    }

    // PC 66: ecalli(64) (5 bytes) — CALL child1 with N-1
    push_inst(&mut code, &mut bitmask, 10);
    for &b in &64u32.to_le_bytes() {
        push_data(&mut code, &mut bitmask, b);
    }

    // PC 71: move_reg S1, A0 (2 bytes) — save fib(N-1)
    push_inst(&mut code, &mut bitmask, 100);
    push_data(
        &mut code,
        &mut bitmask,
        (Reg::S1 as u8) | ((Reg::A0 as u8) << 4),
    );

    // CALL child2 with N-2: φ[7]=N-2, φ[12]=0 (no IPC cap)
    // PC 73: add_imm_64 A0, S0, -2 (6 bytes) — A0 = N-2
    push_inst(&mut code, &mut bitmask, 149);
    push_data(
        &mut code,
        &mut bitmask,
        (Reg::A0 as u8) | ((Reg::S0 as u8) << 4),
    );
    for &b in &(-2i32).to_le_bytes() {
        push_data(&mut code, &mut bitmask, b);
    }

    // PC 79: load_imm A5, 0 (6 bytes) — φ[12] = 0 (no IPC cap)
    push_inst(&mut code, &mut bitmask, 51);
    push_data(&mut code, &mut bitmask, Reg::A5 as u8);
    for &b in &0i32.to_le_bytes() {
        push_data(&mut code, &mut bitmask, b);
    }

    // PC 85: ecalli(65) (5 bytes) — CALL child2 with N-2
    push_inst(&mut code, &mut bitmask, 10);
    for &b in &65u32.to_le_bytes() {
        push_data(&mut code, &mut bitmask, b);
    }

    // PC 90: add_64 A0, S1, A0 (3 bytes) — fib(N-1) + fib(N-2)
    push_inst(&mut code, &mut bitmask, 200);
    push_data(
        &mut code,
        &mut bitmask,
        (Reg::S1 as u8) | ((Reg::A0 as u8) << 4),
    );
    push_data(&mut code, &mut bitmask, Reg::A0 as u8);

    // PC 93: fallthrough (1 byte) — terminator so PC 94 is a gas block start
    push_inst(&mut code, &mut bitmask, 1);

    // PC 94: ecalli(0x00) (5 bytes) — REPLY(A0) (IPC slot 0)
    push_inst(&mut code, &mut bitmask, 10);
    for &b in &0x00u32.to_le_bytes() {
        push_data(&mut code, &mut bitmask, b);
    }

    // PC 99: trap (1 byte) — sentinel for recompiler (never reached)
    push_inst(&mut code, &mut bitmask, 0);

    assert_eq!(code.len(), 100, "fib_recur code should be 100 bytes");

    // Build code sub-blob: jump_len(4) + entry_size(1) + code_len(4) + code + packed_bitmask
    let mut code_data = Vec::new();
    code_data.extend_from_slice(&0u32.to_le_bytes()); // jump_len = 0 (no jump table)
    code_data.push(1u8); // entry_size = 1
    code_data.extend_from_slice(&(code.len() as u32).to_le_bytes());
    code_data.extend_from_slice(&code);
    // Pack bitmask (8 bits per byte, LSB first)
    let packed_len = code.len().div_ceil(8);
    let mut packed = vec![0u8; packed_len];
    for (i, &b) in bitmask.iter().enumerate() {
        if b != 0 {
            packed[i / 8] |= 1 << (i % 8);
        }
    }
    code_data.extend_from_slice(&packed);

    // Build blob with CODE cap at slot 32, memory_pages=0
    let caps = vec![CapManifestEntry {
        cap_index: 32,
        cap_type: CapEntryType::Code,
        base_page: 0,
        page_count: 0,
        init_access: Access::RO,
        data_offset: 0,
        data_len: code_data.len() as u32,
    }];
    build_blob(0, 32, &caps, &code_data)
}

/// Run the fib_recur benchmark with a specific backend.
/// Sets φ\[7\]=N after kernel init, runs until REPLY.
pub fn run_fib_recur_with_backend(
    blob: &[u8],
    n: u64,
    gas: u64,
    backend: javm::PvmBackend,
) -> (u64, u64, usize) {
    use javm::kernel::{InvocationKernel, KernelResult};
    use javm::vm_pool::VmState;

    let mut kernel = InvocationKernel::new_with_backend(blob, &[], gas, backend)
        .expect("fib_recur kernel init failed");
    kernel.vm_arena.vm_mut(0).set_reg(7, n);
    let _ = kernel.vm_arena.vm_mut(0).transition(VmState::Running);

    match kernel.run() {
        KernelResult::Halt(v) => {
            let gas_used = gas - kernel.active_gas();
            let vm_count = kernel.vm_arena.len();
            (v, gas_used, vm_count)
        }
        KernelResult::Panic => {
            let vm = &kernel.vm_arena.vm(kernel.active_vm);
            panic!(
                "fib_recur panicked: vm={} pc={} gas={}",
                kernel.active_vm,
                vm.pc,
                vm.gas()
            );
        }
        KernelResult::OutOfGas => panic!("fib_recur out of gas"),
        KernelResult::PageFault(a) => panic!("fib_recur page fault at {a:#x}"),
        KernelResult::ProtocolCall { slot } => {
            panic!("fib_recur unexpected protocol call slot={slot}")
        }
    }
}

#[cfg(test)]
mod tests_fib_recur {
    use super::*;

    #[test]
    fn test_fib_recur_base_cases() {
        let blob = javm_fib_recur_blob();
        let gas = 100_000_000u64;
        let (r0, _, _) = run_fib_recur_with_backend(&blob, 0, gas, javm::PvmBackend::Default);
        assert_eq!(r0, 0, "fib(0) should be 0");
        let (r1, _, _) = run_fib_recur_with_backend(&blob, 1, gas, javm::PvmBackend::Default);
        assert_eq!(r1, 1, "fib(1) should be 1");
    }

    #[test]
    fn test_fib_recur_sequence() {
        let blob = javm_fib_recur_blob();
        let gas = 1_000_000_000u64;
        let expected = [0u64, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144];
        for (n, &expect) in expected.iter().enumerate() {
            let (result, _, _) =
                run_fib_recur_with_backend(&blob, n as u64, gas, javm::PvmBackend::Default);
            assert_eq!(result, expect, "fib({n}) should be {expect}, got {result}");
        }
    }

    #[test]
    fn test_fib_recur_15() {
        let blob = javm_fib_recur_blob();
        let gas = 1_000_000_000u64;
        let (result, gas_used, vm_count) =
            run_fib_recur_with_backend(&blob, 15, gas, javm::PvmBackend::Default);
        assert_eq!(result, 610, "fib(15) should be 610");
        eprintln!("fib_recur(15): result={result} gas_used={gas_used} vms={vm_count}");
    }

    #[test]
    fn test_fib_recur_20() {
        let blob = javm_fib_recur_blob();
        let gas = 10_000_000_000u64;
        let (result, gas_used, vm_count) =
            run_fib_recur_with_backend(&blob, 20, gas, javm::PvmBackend::Default);
        assert_eq!(result, 6765, "fib(20) should be 6765");
        eprintln!("fib_recur(20): result={result} gas_used={gas_used} vms={vm_count}");
    }

    #[test]
    fn test_fib_recur_22() {
        let blob = javm_fib_recur_blob();
        let gas = 100_000_000_000u64;
        // fib(22) = 17711, creates 57313 VMs — near MAX_VMS (u16::MAX = 65535)
        let (result, gas_used, vm_count) =
            run_fib_recur_with_backend(&blob, 22, gas, javm::PvmBackend::ForceInterpreter);
        assert_eq!(result, 17711, "fib(22) should be 17711");
        eprintln!("fib_recur(22): result={result} gas={gas_used} vms={vm_count}");
    }

    #[test]
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn test_fib_recur_interpreter_recompiler_match() {
        let blob = javm_fib_recur_blob();
        let gas = 1_000_000_000u64;
        let (i_result, i_gas, i_vms) =
            run_fib_recur_with_backend(&blob, 10, gas, javm::PvmBackend::ForceInterpreter);
        let (r_result, r_gas, r_vms) =
            run_fib_recur_with_backend(&blob, 10, gas, javm::PvmBackend::ForceRecompiler);
        assert_eq!(i_result, 55, "fib(10) should be 55");
        assert_eq!(i_result, r_result, "interpreter/recompiler result mismatch");
        assert_eq!(i_gas, r_gas, "interpreter/recompiler gas mismatch");
        assert_eq!(i_vms, r_vms, "interpreter/recompiler VM count mismatch");
        eprintln!("fib_recur(10): result={i_result} gas={i_gas} vms={i_vms}");
    }
}

#[cfg(test)]
mod tests_sort {
    use super::*;

    #[test]
    fn test_javm_sort_small() {
        let blob = javm_sort_blob(5);
        let (result, _gas) = run_kernel(&blob, 10_000_000);
        assert_eq!(result, 1, "arr[0] should be 1 after sorting");
    }

    #[test]
    fn test_ecrecover_code_size() {
        let blob = javm_ecrecover_blob();
        // Parse the v2 blob to inspect code structure
        let parsed = javm::program::parse_blob(blob).expect("should parse v2 blob");
        let code_cap = parsed
            .caps
            .iter()
            .find(|c| c.cap_type == javm::program::CapEntryType::Code);
        if let Some(cc) = code_cap {
            let code_data = javm::program::cap_data(cc, parsed.data_section);
            if let Some(code_blob) = javm::program::parse_code_blob(code_data) {
                let inst_count: usize = code_blob.bitmask.iter().filter(|&&b| b == 1).count();
                eprintln!(
                    "javm:  code={} bytes, {} instructions",
                    code_blob.code.len(),
                    inst_count
                );
            }
        }
        let pvm_blob = polkavm_ecrecover_blob();
        eprintln!("PolkaVM:   blob={} bytes", pvm_blob.len());
    }

    #[test]
    fn test_javm_ecrecover() {
        let gas = 100_000_000_000u64;
        let (result, gas_used) = run_kernel(javm_ecrecover_blob(), gas);
        eprintln!("ecrecover: a0={result} gas_used={gas_used}");
        assert!(
            gas_used > 1_000_000,
            "ecrecover should use >1M gas, got {gas_used}"
        );
        assert_eq!(result, 1, "ecrecover should return 1 (success)");
    }

    /// Run blob on both interpreter and recompiler (via kernel), assert a0 and gas match.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn assert_interp_recomp(blob: &[u8], expected_a0: u64, min_gas: u64, name: &str) {
        let gas = 100_000_000_000u64;

        let (interp_a0, interp_gas) = run_javm_interpreter(blob, gas);
        assert_eq!(interp_a0, expected_a0, "{name}: interpreter a0 mismatch");

        let (recomp_a0, recomp_gas) = run_javm_recompiler(blob, gas);
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
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn test_javm_ecrecover_recompiler() {
        assert_interp_recomp(javm_ecrecover_blob(), 1, 100_000, "ecrecover");
    }

    #[test]
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn test_javm_prime_sieve_recompiler() {
        assert_interp_recomp(javm_sieve_blob(), 9592, 100_000, "prime_sieve");
    }

    #[test]
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn test_javm_ed25519_recompiler() {
        assert_interp_recomp(javm_ed25519_blob(), 1, 1_000, "ed25519");
    }

    #[test]
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn test_javm_blake2b_recompiler() {
        // blake2b-256 of [0x00..0xFF]*4: first 4 bytes LE = 0xEE1F55F1, sign-extended on rv64
        assert_interp_recomp(javm_blake2b_blob(), 0xFFFFFFFFEE1F55F1, 10_000, "blake2b");
    }

    #[test]
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn test_javm_keccak_recompiler() {
        // keccak-256 of [0x00..0xFF]*4: first 4 bytes LE = 0x39E50259
        assert_interp_recomp(javm_keccak_blob(), 0x39E50259, 10_000, "keccak");
    }
}
