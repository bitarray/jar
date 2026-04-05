//! Per-basic-block gas cost model (JAR v0.8.0).
//!
//! Simulates a CPU pipeline to compute gas cost for a basic block.
//! Cost = max(simulation_cycles - 3, 1).
//!
//! Pipeline model:
//! - Reorder buffer: max 32 entries
//! - 4 decode slots per cycle, 5 dispatch slots per cycle
//! - Execution units: ALU:4, LOAD:4, STORE:4, MUL:1, DIV:1

use alloc::{vec, vec::Vec};

// --- Data structures ---

#[derive(Clone, Copy, Default, Debug)]
struct ExecUnits {
    alu: u8,
    load: u8,
    store: u8,
    mul: u8,
    div: u8,
}

impl ExecUnits {
    fn can_satisfy(self, req: ExecUnits) -> bool {
        self.alu >= req.alu
            && self.load >= req.load
            && self.store >= req.store
            && self.mul >= req.mul
            && self.div >= req.div
    }
    fn sub(self, req: ExecUnits) -> ExecUnits {
        ExecUnits {
            alu: self.alu - req.alu,
            load: self.load - req.load,
            store: self.store - req.store,
            mul: self.mul - req.mul,
            div: self.div - req.div,
        }
    }
    const RESET: ExecUnits = ExecUnits {
        alu: 4,
        load: 4,
        store: 4,
        mul: 1,
        div: 1,
    };
    const ALU: ExecUnits = ExecUnits {
        alu: 1,
        load: 0,
        store: 0,
        mul: 0,
        div: 0,
    };
    const LOAD: ExecUnits = ExecUnits {
        alu: 1,
        load: 1,
        store: 0,
        mul: 0,
        div: 0,
    };
    const STORE: ExecUnits = ExecUnits {
        alu: 1,
        load: 0,
        store: 1,
        mul: 0,
        div: 0,
    };
    const MUL: ExecUnits = ExecUnits {
        alu: 1,
        load: 0,
        store: 0,
        mul: 1,
        div: 0,
    };
    const DIV: ExecUnits = ExecUnits {
        alu: 1,
        load: 0,
        store: 0,
        mul: 0,
        div: 1,
    };
    const NONE: ExecUnits = ExecUnits {
        alu: 0,
        load: 0,
        store: 0,
        mul: 0,
        div: 0,
    };
    fn _to_eu_byte(self) -> u8 {
        if self.div > 0 {
            5
        } else if self.mul > 0 {
            4
        } else if self.store > 0 {
            3
        } else if self.load > 0 {
            2
        } else if self.alu > 0 {
            1
        } else {
            0
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum RobState {
    Wait,
    Exe,
    Fin,
}

#[derive(Clone, Copy)]
struct RobEntry {
    state: RobState,
    cycles_left: u32,
    deps: [u8; 4], // ROB indices this depends on (0xFF = unused)
    dep_count: u8,
    dest_regs: RegSet,
    exec_units: ExecUnits,
}

struct SimState {
    ip: Option<usize>, // instruction pointer (None = done decoding)
    cycles: u32,
    decode_slots: u8,      // remaining per cycle (reset to 4)
    dispatch_slots: u8,    // remaining per cycle (reset to 5)
    exec_units: ExecUnits, // remaining per cycle
    rob: Vec<RobEntry>,
}

// --- Instruction cost analysis ---

/// Fixed-capacity register set (max 3 registers, no heap allocation).
#[derive(Clone, Copy, Default, Debug)]
struct RegSet {
    regs: [u8; 3],
    len: u8,
}

impl RegSet {
    const EMPTY: Self = Self {
        regs: [0; 3],
        len: 0,
    };
    fn one(r: u8) -> Self {
        Self {
            regs: [r, 0, 0],
            len: 1,
        }
    }
    fn two(a: u8, b: u8) -> Self {
        Self {
            regs: [a, b, 0],
            len: 2,
        }
    }
    #[inline]
    fn contains(&self, r: u8) -> bool {
        (self.len >= 1 && self.regs[0] == r)
            || (self.len >= 2 && self.regs[1] == r)
            || (self.len >= 3 && self.regs[2] == r)
    }
    #[inline]
    fn iter(&self) -> impl Iterator<Item = &u8> {
        self.regs[..self.len as usize].iter()
    }
}

struct InstrCost {
    cycles: u32,
    decode_slots: u8,
    exec_units: ExecUnits,
    dest_regs: RegSet,
    src_regs: RegSet,
    is_terminator: bool,
    is_move_reg: bool,
}

fn dst_overlaps_src(dst: u8, srcs: &RegSet) -> bool {
    srcs.contains(dst)
}

/// Branch cost: 1 if target is unlikely(2) or trap(0), else 20.
fn branch_cost(code: &[u8], bitmask: &[u8], target: usize) -> u32 {
    if target < code.len() && target < bitmask.len() && bitmask[target] == 1 {
        let opcode = code[target];
        if opcode == 0 || opcode == 2 { 1 } else { 20 }
    } else {
        20
    }
}

/// Extract register A (first register in instruction encoding).
fn reg_a(code: &[u8], pc: usize) -> u8 {
    if pc + 1 < code.len() {
        code[pc + 1] & 0x0F
    } else {
        0
    }
}
/// Extract register B (second register, upper nibble of byte after opcode).
fn reg_b(code: &[u8], pc: usize) -> u8 {
    if pc + 1 < code.len() {
        (code[pc + 1] >> 4) & 0x0F
    } else {
        0
    }
}
/// Extract register D (third register encoding for 3-reg instructions).
fn reg_d(code: &[u8], pc: usize) -> u8 {
    if pc + 2 < code.len() {
        code[pc + 2] & 0x0F
    } else {
        0
    }
}

/// Compute skip distance (bytes to next instruction start).
pub fn skip_distance(bitmask: &[u8], pc: usize) -> usize {
    for j in 0..25 {
        let idx = pc + 1 + j;
        let bit = if idx < bitmask.len() { bitmask[idx] } else { 1 };
        if bit == 1 {
            return j;
        }
    }
    24
}

/// Extract branch target from reg+imm+offset instruction.
fn extract_branch_target(code: &[u8], bitmask: &[u8], pc: usize) -> usize {
    let skip = skip_distance(bitmask, pc);
    // Target offset is encoded in the last bytes of the instruction
    // For OneRegImmOffset: layout is [opcode, ra|imm_lo, imm_hi..., offset_bytes]
    // The offset is a signed value relative to the instruction start
    let instr_len = 1 + skip;
    if instr_len >= 3 && pc + instr_len <= code.len() {
        // Decode offset from the last portion of the instruction
        // For A.5.8 format: opcode + reg_nibble + immediate + offset
        // The offset part depends on skip length
        let raw = crate::args::decode_args(
            code,
            pc,
            skip,
            crate::instruction::InstructionCategory::OneRegImmOffset,
        );
        if let crate::args::Args::RegImmOffset { offset, .. } = raw {
            return offset as usize;
        }
    }
    pc // fallback
}

/// Extract branch target from two-reg+offset instruction.
fn extract_two_reg_branch_target(code: &[u8], bitmask: &[u8], pc: usize) -> usize {
    let skip = skip_distance(bitmask, pc);
    let raw = crate::args::decode_args(
        code,
        pc,
        skip,
        crate::instruction::InstructionCategory::TwoRegOneOffset,
    );
    if let crate::args::Args::TwoRegOffset { offset, .. } = raw {
        return offset as usize;
    }
    pc
}

/// Instruction cost lookup based on opcode.
fn instruction_cost(code: &[u8], bitmask: &[u8], pc: usize) -> InstrCost {
    let opcode = if pc < code.len() { code[pc] } else { 0 };
    let ra = reg_a(code, pc);
    let rb = reg_b(code, pc);
    let rd = reg_d(code, pc);

    let mk = |cy: u32, dc: u8, eu: ExecUnits, dst: RegSet, src: RegSet| -> InstrCost {
        InstrCost {
            cycles: cy,
            decode_slots: dc,
            exec_units: eu,
            dest_regs: dst,
            src_regs: src,
            is_terminator: false,
            is_move_reg: false,
        }
    };
    let mkt = |cy: u32, dc: u8, eu: ExecUnits, dst: RegSet, src: RegSet| -> InstrCost {
        InstrCost {
            cycles: cy,
            decode_slots: dc,
            exec_units: eu,
            dest_regs: dst,
            src_regs: src,
            is_terminator: true,
            is_move_reg: false,
        }
    };
    let e = RegSet::EMPTY;
    let r1 = RegSet::one;
    let r2 = RegSet::two;

    match opcode {
        // No-arg
        0 => mkt(2, 1, ExecUnits::NONE, e, e),   // trap
        1 => mkt(2, 1, ExecUnits::NONE, e, e),   // fallthrough
        2 => mkt(40, 1, ExecUnits::NONE, e, e),  // unlikely
        10 => mkt(100, 4, ExecUnits::ALU, e, e), // ecalli

        // Control flow
        40 => mkt(15, 1, ExecUnits::ALU, e, e), // jump
        80 => {
            // load_imm_jump
            let skip = skip_distance(bitmask, pc);
            let raw = crate::args::decode_args(
                code,
                pc,
                skip,
                crate::instruction::InstructionCategory::OneRegImmOffset,
            );
            let r = if let crate::args::Args::RegImmOffset { ra: r, .. } = raw {
                r as u8
            } else {
                ra
            };
            mkt(15, 1, ExecUnits::ALU, r1(r), e)
        }
        50 => mkt(22, 1, ExecUnits::ALU, e, e), // jump_ind
        180 => mkt(22, 1, ExecUnits::ALU, r1(ra), r1(rb)), // load_imm_jump_ind

        // Loads (reg+imm and two-reg+imm variants)
        52..=58 => mk(25, 1, ExecUnits::LOAD, r1(ra), r1(rb)),
        124..=130 => mk(25, 1, ExecUnits::LOAD, r1(ra), r1(rb)),

        // Stores (reg+imm variants)
        59..=62 => mk(25, 1, ExecUnits::STORE, e, r2(ra, rb)),
        // Stores (two-reg+imm)
        120..=123 => mk(25, 1, ExecUnits::STORE, e, r2(ra, rb)),
        // Store immediates (two-imm)
        30..=33 => mk(25, 1, ExecUnits::STORE, e, e),
        // Store imm indirect (reg+two-imm)
        70..=73 => mk(25, 1, ExecUnits::STORE, e, r1(ra)),

        // Load immediates
        51 => mk(1, 1, ExecUnits::NONE, r1(ra), e), // load_imm
        20 => mk(1, 2, ExecUnits::NONE, r1(ra), e), // load_imm_64

        // move_reg: decoded in frontend, no ROB entry
        100 => InstrCost {
            cycles: 0,
            decode_slots: 1,
            exec_units: ExecUnits::NONE,
            dest_regs: r1(ra),
            src_regs: r1(rb),
            is_terminator: false,
            is_move_reg: true,
        },

        // sbrk (101): removed in jar080, but cost it anyway for simulation
        101 => mk(2, 1, ExecUnits::NONE, e, e),

        // Branches (reg + imm + offset)
        81..=90 => {
            let target = extract_branch_target(code, bitmask, pc);
            let bc = branch_cost(code, bitmask, target);
            mkt(bc, 1, ExecUnits::ALU, e, r1(ra))
        }

        // Branches (two-reg + offset)
        170..=175 => {
            let target = extract_two_reg_branch_target(code, bitmask, pc);
            let bc = branch_cost(code, bitmask, target);
            mkt(bc, 1, ExecUnits::ALU, e, r2(ra, rb))
        }

        // ALU 64-bit 3-reg: add_64(200), sub_64(201), and(210), xor(211), or(212)
        200 | 201 | 210 | 211 | 212 => {
            let dc = if dst_overlaps_src(ra, &r2(rb, rd)) {
                1
            } else {
                2
            };
            mk(1, dc, ExecUnits::ALU, r1(ra), r2(rb, rd))
        }
        // ALU 32-bit 3-reg: add_32(190), sub_32(191)
        190 | 191 => {
            let dc = if dst_overlaps_src(ra, &r2(rb, rd)) {
                2
            } else {
                3
            };
            mk(2, dc, ExecUnits::ALU, r1(ra), r2(rb, rd))
        }

        // ALU 2-op imm 64-bit
        132 | 133 | 134 | 149 | 151 | 152 | 153 | 158 | 110 => {
            let dc = if dst_overlaps_src(ra, &r1(rb)) { 1 } else { 2 };
            mk(1, dc, ExecUnits::ALU, r1(ra), r1(rb))
        }
        // ALU 2-op imm 32-bit
        131 | 138 | 139 | 140 | 160 => {
            let dc = if dst_overlaps_src(ra, &r1(rb)) { 2 } else { 3 };
            mk(2, dc, ExecUnits::ALU, r1(ra), r1(rb))
        }

        // Trivial 2-op 1-cycle: popcount, clz, sign_extend, zero_extend
        102 | 103 | 104 | 105 | 108 | 109 => mk(1, 1, ExecUnits::ALU, r1(ra), r1(rb)),
        // Trivial 2-op 2-cycle: ctz
        106 | 107 => mk(2, 1, ExecUnits::ALU, r1(ra), r1(rb)),
        // reverse_bytes
        111 => mk(1, 1, ExecUnits::ALU, r1(ra), r1(rb)),

        // Shifts 64-bit 3-reg
        207 | 208 | 209 | 220 | 222 => {
            let dc = if rb == ra { 2 } else { 3 };
            mk(1, dc, ExecUnits::ALU, r1(ra), r2(rb, rd))
        }
        // Shifts 32-bit 3-reg
        197 | 198 | 199 | 221 | 223 => {
            let dc = if rb == ra { 3 } else { 4 };
            mk(2, dc, ExecUnits::ALU, r1(ra), r2(rb, rd))
        }
        // Shift alt 64-bit
        155 | 156 | 157 | 159 => mk(1, 3, ExecUnits::ALU, r1(ra), r1(rb)),
        // Shift alt 32-bit
        144 | 145 | 146 | 161 => mk(2, 4, ExecUnits::ALU, r1(ra), r1(rb)),

        // Comparisons (3-reg)
        216 | 217 => mk(3, 3, ExecUnits::ALU, r1(ra), r2(rb, rd)),
        // Comparisons (imm)
        136 | 137 | 142 | 143 => mk(3, 3, ExecUnits::ALU, r1(ra), r1(rb)),

        // Conditional moves (3-reg)
        218 | 219 => mk(2, 2, ExecUnits::ALU, r1(ra), r2(rb, rd)),
        // Conditional moves (imm)
        147 | 148 => mk(2, 3, ExecUnits::ALU, r1(ra), r1(rb)),

        // Min/Max
        227..=230 => {
            let dc = if dst_overlaps_src(ra, &r2(rb, rd)) {
                2
            } else {
                3
            };
            mk(3, dc, ExecUnits::ALU, r1(ra), r2(rb, rd))
        }
        // and_inv, or_inv
        224 | 225 => mk(2, 3, ExecUnits::ALU, r1(ra), r2(rb, rd)),
        // xnor
        226 => {
            let dc = if dst_overlaps_src(ra, &r2(rb, rd)) {
                2
            } else {
                3
            };
            mk(2, dc, ExecUnits::ALU, r1(ra), r2(rb, rd))
        }

        // neg_add_imm_64
        154 => mk(2, 3, ExecUnits::ALU, r1(ra), r1(rb)),
        // neg_add_imm_32
        141 => mk(3, 4, ExecUnits::ALU, r1(ra), r1(rb)),

        // Multiply 64-bit (3-reg)
        202 => {
            let dc = if dst_overlaps_src(ra, &r2(rb, rd)) {
                1
            } else {
                2
            };
            mk(3, dc, ExecUnits::MUL, r1(ra), r2(rb, rd))
        }
        // mul_imm_64
        150 => {
            let dc = if dst_overlaps_src(ra, &r1(rb)) { 1 } else { 2 };
            mk(3, dc, ExecUnits::MUL, r1(ra), r1(rb))
        }
        // Multiply 32-bit (3-reg)
        192 => {
            let dc = if dst_overlaps_src(ra, &r2(rb, rd)) {
                2
            } else {
                3
            };
            mk(4, dc, ExecUnits::MUL, r1(ra), r2(rb, rd))
        }
        // mul_imm_32
        135 => {
            let dc = if dst_overlaps_src(ra, &r1(rb)) { 2 } else { 3 };
            mk(4, dc, ExecUnits::MUL, r1(ra), r1(rb))
        }

        // Multiply upper (SS, UU)
        213 | 214 => mk(4, 4, ExecUnits::MUL, r1(ra), r2(rb, rd)),
        // Multiply upper (SU)
        215 => mk(6, 4, ExecUnits::MUL, r1(ra), r2(rb, rd)),

        // Divide (all variants)
        193 | 194 | 195 | 196 | 203 | 204 | 205 | 206 => {
            mk(60, 4, ExecUnits::DIV, r1(ra), r2(rb, rd))
        }

        // Rotate 64-bit (3-reg)
        // Already covered by shifts above (220, 222 = RotL64, RotR64)

        // Rotate 32-bit (3-reg)
        // Already covered by shifts above (221, 223 = RotL32, RotR32)

        // Rotate imm
        // Already covered by shift alt above

        // Default: unknown opcode
        _ => mk(1, 1, ExecUnits::NONE, e, e),
    }
}

// --- Simulation ---

fn all_deps_finished(rob: &[RobEntry], entry: &RobEntry) -> bool {
    for i in 0..entry.dep_count as usize {
        let idx = entry.deps[i] as usize;
        if idx < rob.len() && rob[idx].state != RobState::Fin {
            return false;
        }
    }
    true
}

fn find_ready_entry(rob: &[RobEntry], exec_units: ExecUnits) -> Option<usize> {
    for (i, entry) in rob.iter().enumerate() {
        if entry.state == RobState::Wait
            && all_deps_finished(rob, entry)
            && exec_units.can_satisfy(entry.exec_units)
        {
            return Some(i);
        }
    }
    None
}

fn rob_all_finished(rob: &[RobEntry]) -> bool {
    rob.iter().all(|e| e.state == RobState::Fin)
}

/// Run the pipeline simulation for a basic block starting at `start_pc`.
/// If `trace` is true, print every action for debugging.
fn gas_sim_traced(code: &[u8], bitmask: &[u8], start_pc: usize, trace: bool) -> u32 {
    let mut s = SimState {
        ip: Some(start_pc),
        cycles: 0,
        decode_slots: 4,
        dispatch_slots: 5,
        exec_units: ExecUnits::RESET,
        rob: Vec::with_capacity(32),
    };

    for iter in 0..100_000 {
        // Priority 1: Decode
        if s.ip.is_some() && s.decode_slots > 0 && s.rob.len() < 32 {
            let pc = s.ip.unwrap();
            let cost = instruction_cost(code, bitmask, pc);
            let mut deps = [0xFF_u8; 4];
            let mut dep_count = 0u8;
            for (i, e) in s.rob.iter().enumerate() {
                if e.state != RobState::Fin
                    && e.dest_regs.iter().any(|dr| cost.src_regs.contains(*dr))
                    && dep_count < 4
                {
                    deps[dep_count as usize] = i as u8;
                    dep_count += 1;
                }
            }
            s.decode_slots = s.decode_slots.saturating_sub(cost.decode_slots);
            let next_ip = if cost.is_terminator {
                None
            } else {
                let skip = skip_distance(bitmask, pc);
                let npc = pc + 1 + skip;
                if npc < code.len() { Some(npc) } else { None }
            };
            #[cfg(feature = "std")]
            if trace {
                let op = crate::instruction::Opcode::from_byte(code[pc])
                    .map(|o| alloc::format!("{:?}", o))
                    .unwrap_or("?".into());
                eprintln!(
                    "  [{}] DECODE pc={} {} cy={} dec={} rob_idx={} deps={:?} move={} term={} slots_left={}",
                    iter,
                    pc,
                    op,
                    cost.cycles,
                    cost.decode_slots,
                    s.rob.len(),
                    &deps[..dep_count as usize],
                    cost.is_move_reg,
                    cost.is_terminator,
                    s.decode_slots
                );
            }
            if cost.is_move_reg {
                s.ip = next_ip;
            } else {
                s.rob.push(RobEntry {
                    state: RobState::Wait,
                    cycles_left: cost.cycles,
                    deps,
                    dep_count,
                    dest_regs: cost.dest_regs,
                    exec_units: cost.exec_units,
                });
                s.ip = next_ip;
            }
            continue;
        }

        // Priority 2: Dispatch
        if s.dispatch_slots > 0
            && let Some(idx) = find_ready_entry(&s.rob, s.exec_units)
        {
            let eu = s.rob[idx].exec_units;
            #[cfg(feature = "std")]
            if trace {
                eprintln!(
                    "  [{}] DISPATCH rob[{}] cy={} dispatch_left={}",
                    iter,
                    idx,
                    s.rob[idx].cycles_left,
                    s.dispatch_slots - 1
                );
            }
            s.rob[idx].state = RobState::Exe;
            s.dispatch_slots -= 1;
            s.exec_units = s.exec_units.sub(eu);
            continue;
        }

        // Priority 3: Done
        if s.ip.is_none() && rob_all_finished(&s.rob) {
            #[cfg(feature = "std")]
            if trace {
                eprintln!("  [{}] DONE cycles={}", iter, s.cycles);
            }
            break;
        }

        // Priority 4: Advance cycle
        #[cfg(feature = "std")]
        if trace {
            let states: Vec<alloc::string::String> = s
                .rob
                .iter()
                .enumerate()
                .map(|(i, e)| {
                    let st = match e.state {
                        RobState::Wait => "W",
                        RobState::Exe => "E",
                        RobState::Fin => "F",
                    };
                    alloc::format!(
                        "{}:{}{}",
                        i,
                        st,
                        if e.state == RobState::Exe {
                            alloc::format!("({})", e.cycles_left)
                        } else {
                            alloc::string::String::new()
                        }
                    )
                })
                .collect();
            eprintln!(
                "  [{}] ADVANCE cycle {} → {} rob=[{}]",
                iter,
                s.cycles,
                s.cycles + 1,
                states.join(", ")
            );
        }
        for entry in s.rob.iter_mut() {
            if entry.state == RobState::Exe {
                if entry.cycles_left <= 1 {
                    entry.state = RobState::Fin;
                    entry.cycles_left = 0;
                } else {
                    entry.cycles_left -= 1;
                }
            }
        }
        s.cycles += 1;
        s.decode_slots = 4;
        s.dispatch_slots = 5;
        s.exec_units = ExecUnits::RESET;
    }

    s.cycles
}

fn gas_sim(code: &[u8], bitmask: &[u8], start_pc: usize) -> u32 {
    gas_sim_traced(code, bitmask, start_pc, false)
}

/// Compute gas cost for a basic block starting at `start_pc`.
/// Returns max(simulation_cycles - 3, 1).
pub fn gas_cost_for_block(code: &[u8], bitmask: &[u8], start_pc: usize) -> u64 {
    let cycles = gas_sim(code, bitmask, start_pc);
    if cycles > 3 { (cycles - 3) as u64 } else { 1 }
}

#[cfg(feature = "std")]
/// Compute gas cost for a block given as a slice of pre-decoded instructions.
/// This avoids re-parsing raw code+bitmask.
pub fn gas_cost_for_block_decoded(
    instrs: &[crate::recompiler::predecode::PreDecodedInst],
    code: &[u8],
    bitmask: &[u8],
) -> u64 {
    let cycles = gas_sim_decoded(instrs, code, bitmask);
    if cycles > 3 { (cycles - 3) as u64 } else { 1 }
}

#[cfg(feature = "std")]
/// Pipeline simulation from pre-decoded instructions (no raw byte re-parsing).
fn gas_sim_decoded(
    instrs: &[crate::recompiler::predecode::PreDecodedInst],
    code: &[u8],
    bitmask: &[u8],
) -> u32 {
    use crate::args::Args;

    let mut s = SimState {
        ip: Some(0), // index into instrs
        cycles: 0,
        decode_slots: 4,
        dispatch_slots: 5,
        exec_units: ExecUnits::RESET,
        rob: Vec::with_capacity(32),
    };

    for _ in 0..100_000 {
        if let Some(idx) = s.ip
            && idx < instrs.len()
            && s.decode_slots > 0
            && s.rob.len() < 32
        {
            let instr = &instrs[idx];
            let opcode_byte = instr.opcode as u8;

            // Extract register fields from decoded args
            let (ra, rb, rd) = match instr.args {
                Args::ThreeReg { ra, rb, rd } => (ra as u8, rb as u8, rd as u8),
                Args::TwoReg { rd: d, ra: a } => (a as u8, 0xFF, d as u8),
                Args::TwoRegImm { ra, rb, .. }
                | Args::TwoRegOffset { ra, rb, .. }
                | Args::TwoRegTwoImm { ra, rb, .. } => (ra as u8, rb as u8, 0xFF),
                Args::RegImm { ra, .. }
                | Args::RegExtImm { ra, .. }
                | Args::RegTwoImm { ra, .. }
                | Args::RegImmOffset { ra, .. } => (ra as u8, 0xFF, 0xFF),
                _ => (0xFF, 0xFF, 0xFF),
            };

            // Compute instruction cost using the same logic but with decoded regs
            let cost = instruction_cost_fast(opcode_byte, ra, rb, rd, instr, code, bitmask);

            let mut deps = [0xFF_u8; 4];
            let mut dep_count = 0u8;
            for (i, e) in s.rob.iter().enumerate() {
                if e.state != RobState::Fin
                    && e.dest_regs.iter().any(|dr| cost.src_regs.contains(*dr))
                    && dep_count < 4
                {
                    deps[dep_count as usize] = i as u8;
                    dep_count += 1;
                }
            }

            s.decode_slots = s.decode_slots.saturating_sub(cost.decode_slots);
            let next_ip = if cost.is_terminator {
                None
            } else {
                Some(idx + 1)
            };

            if cost.is_move_reg {
                s.ip = next_ip;
            } else {
                s.rob.push(RobEntry {
                    state: RobState::Wait,
                    cycles_left: cost.cycles,
                    deps,
                    dep_count,
                    dest_regs: cost.dest_regs,
                    exec_units: cost.exec_units,
                });
                s.ip = next_ip;
            }
            continue;
        }

        if s.dispatch_slots > 0
            && let Some(idx) = find_ready_entry(&s.rob, s.exec_units)
        {
            let eu = s.rob[idx].exec_units;
            s.rob[idx].state = RobState::Exe;
            s.dispatch_slots -= 1;
            s.exec_units = s.exec_units.sub(eu);
            continue;
        }

        if s.ip.is_none_or(|i| i >= instrs.len()) && rob_all_finished(&s.rob) {
            break;
        }

        for entry in s.rob.iter_mut() {
            if entry.state == RobState::Exe {
                if entry.cycles_left <= 1 {
                    entry.state = RobState::Fin;
                    entry.cycles_left = 0;
                } else {
                    entry.cycles_left -= 1;
                }
            }
        }
        s.cycles += 1;
        s.decode_slots = 4;
        s.dispatch_slots = 5;
        s.exec_units = ExecUnits::RESET;
    }

    s.cycles
}

#[cfg(feature = "std")]
/// Fast instruction cost lookup using pre-decoded register fields.
/// Avoids re-parsing code bytes for register extraction.
fn instruction_cost_fast(
    opcode: u8,
    ra: u8,
    rb: u8,
    rd: u8,
    instr: &crate::recompiler::predecode::PreDecodedInst,
    code: &[u8],
    bitmask: &[u8],
) -> InstrCost {
    let mk = |cy: u32, dc: u8, eu: ExecUnits, dst: RegSet, src: RegSet| -> InstrCost {
        InstrCost {
            cycles: cy,
            decode_slots: dc,
            exec_units: eu,
            dest_regs: dst,
            src_regs: src,
            is_terminator: false,
            is_move_reg: false,
        }
    };
    let mkt = |cy: u32, dc: u8, eu: ExecUnits, dst: RegSet, src: RegSet| -> InstrCost {
        InstrCost {
            cycles: cy,
            decode_slots: dc,
            exec_units: eu,
            dest_regs: dst,
            src_regs: src,
            is_terminator: true,
            is_move_reg: false,
        }
    };
    let e = RegSet::EMPTY;
    let r1 = RegSet::one;
    let r2 = RegSet::two;

    match opcode {
        0 => mkt(2, 1, ExecUnits::NONE, e, e),
        1 => mkt(2, 1, ExecUnits::NONE, e, e),
        2 => mkt(40, 1, ExecUnits::NONE, e, e),
        10 => mkt(100, 4, ExecUnits::ALU, e, e),
        40 => mkt(15, 1, ExecUnits::ALU, e, e),
        80 => mkt(15, 1, ExecUnits::ALU, r1(ra), e),
        50 => mkt(22, 1, ExecUnits::ALU, e, e),
        180 => mkt(22, 1, ExecUnits::ALU, r1(ra), r1(rb)),
        52..=58 => mk(25, 1, ExecUnits::LOAD, r1(ra), r1(rb)),
        124..=130 => mk(25, 1, ExecUnits::LOAD, r1(ra), r1(rb)),
        59..=62 => mk(25, 1, ExecUnits::STORE, e, r2(ra, rb)),
        120..=123 => mk(25, 1, ExecUnits::STORE, e, r2(ra, rb)),
        30..=33 => mk(25, 1, ExecUnits::STORE, e, e),
        70..=73 => mk(25, 1, ExecUnits::STORE, e, r1(ra)),
        51 => mk(1, 1, ExecUnits::NONE, r1(ra), e),
        20 => mk(1, 2, ExecUnits::NONE, r1(ra), e),
        100 => InstrCost {
            cycles: 0,
            decode_slots: 1,
            exec_units: ExecUnits::NONE,
            dest_regs: r1(ra),
            src_regs: r1(rb),
            is_terminator: false,
            is_move_reg: true,
        },
        101 => mk(2, 1, ExecUnits::NONE, e, e),
        81..=90 => {
            // Use pre-decoded offset for branch target
            let target = match instr.args {
                crate::args::Args::RegImmOffset { offset, .. } => offset as usize,
                _ => instr.pc as usize,
            };
            let bc = branch_cost(code, bitmask, target);
            mkt(bc, 1, ExecUnits::ALU, e, r1(ra))
        }
        170..=175 => {
            let target = match instr.args {
                crate::args::Args::TwoRegOffset { offset, .. } => offset as usize,
                _ => instr.pc as usize,
            };
            let bc = branch_cost(code, bitmask, target);
            mkt(bc, 1, ExecUnits::ALU, e, r2(ra, rb))
        }
        200 | 201 | 210 | 211 | 212 => {
            let dc = if dst_overlaps_src(ra, &r2(rb, rd)) {
                1
            } else {
                2
            };
            mk(1, dc, ExecUnits::ALU, r1(ra), r2(rb, rd))
        }
        190 | 191 => {
            let dc = if dst_overlaps_src(ra, &r2(rb, rd)) {
                2
            } else {
                3
            };
            mk(2, dc, ExecUnits::ALU, r1(ra), r2(rb, rd))
        }
        132 | 133 | 134 | 149 | 151 | 152 | 153 | 158 | 110 => {
            let dc = if dst_overlaps_src(ra, &r1(rb)) { 1 } else { 2 };
            mk(1, dc, ExecUnits::ALU, r1(ra), r1(rb))
        }
        131 | 138 | 139 | 140 | 160 => {
            let dc = if dst_overlaps_src(ra, &r1(rb)) { 2 } else { 3 };
            mk(2, dc, ExecUnits::ALU, r1(ra), r1(rb))
        }
        102 | 103 | 104 | 105 | 108 | 109 => mk(1, 1, ExecUnits::ALU, r1(ra), r1(rb)),
        106 | 107 => mk(2, 1, ExecUnits::ALU, r1(ra), r1(rb)),
        111 => mk(1, 1, ExecUnits::ALU, r1(ra), r1(rb)),
        207 | 208 | 209 | 220 | 222 => {
            let dc = if rb == ra { 2 } else { 3 };
            mk(1, dc, ExecUnits::ALU, r1(ra), r2(rb, rd))
        }
        197 | 198 | 199 | 221 | 223 => {
            let dc = if rb == ra { 3 } else { 4 };
            mk(2, dc, ExecUnits::ALU, r1(ra), r2(rb, rd))
        }
        155 | 156 | 157 | 159 => mk(1, 3, ExecUnits::ALU, r1(ra), r1(rb)),
        144 | 145 | 146 | 161 => mk(2, 4, ExecUnits::ALU, r1(ra), r1(rb)),
        216 | 217 => mk(3, 3, ExecUnits::ALU, r1(ra), r2(rb, rd)),
        136 | 137 | 142 | 143 => mk(3, 3, ExecUnits::ALU, r1(ra), r1(rb)),
        218 | 219 => mk(2, 2, ExecUnits::ALU, r1(ra), r2(rb, rd)),
        147 | 148 => mk(2, 3, ExecUnits::ALU, r1(ra), r1(rb)),
        227..=230 => {
            let dc = if dst_overlaps_src(ra, &r2(rb, rd)) {
                2
            } else {
                3
            };
            mk(3, dc, ExecUnits::ALU, r1(ra), r2(rb, rd))
        }
        224 | 225 => mk(2, 3, ExecUnits::ALU, r1(ra), r2(rb, rd)),
        226 => {
            let dc = if dst_overlaps_src(ra, &r2(rb, rd)) {
                2
            } else {
                3
            };
            mk(2, dc, ExecUnits::ALU, r1(ra), r2(rb, rd))
        }
        154 => mk(2, 3, ExecUnits::ALU, r1(ra), r1(rb)),
        141 => mk(3, 4, ExecUnits::ALU, r1(ra), r1(rb)),
        202 => {
            let dc = if dst_overlaps_src(ra, &r2(rb, rd)) {
                1
            } else {
                2
            };
            mk(3, dc, ExecUnits::MUL, r1(ra), r2(rb, rd))
        }
        150 => {
            let dc = if dst_overlaps_src(ra, &r1(rb)) { 1 } else { 2 };
            mk(3, dc, ExecUnits::MUL, r1(ra), r1(rb))
        }
        192 => {
            let dc = if dst_overlaps_src(ra, &r2(rb, rd)) {
                2
            } else {
                3
            };
            mk(4, dc, ExecUnits::MUL, r1(ra), r2(rb, rd))
        }
        135 => {
            let dc = if dst_overlaps_src(ra, &r1(rb)) { 2 } else { 3 };
            mk(4, dc, ExecUnits::MUL, r1(ra), r1(rb))
        }
        213 | 214 => mk(4, 4, ExecUnits::MUL, r1(ra), r2(rb, rd)),
        215 => mk(6, 4, ExecUnits::MUL, r1(ra), r2(rb, rd)),
        193 | 194 | 195 | 196 | 203 | 204 | 205 | 206 => {
            mk(60, 4, ExecUnits::DIV, r1(ra), r2(rb, rd))
        }
        _ => mk(1, 1, ExecUnits::NONE, e, e),
    }
}

/// Compute block gas costs for all gas block starts in the program.
/// Gas block starts are {PC=0} ∪ {post-terminator PCs} (branch targets excluded).
/// Returns a Vec indexed by PC: `block_gas_costs[pc]` = cost if pc is a gas block start, 0 otherwise.
pub fn compute_block_gas_costs(code: &[u8], bitmask: &[u8]) -> Vec<u64> {
    let mut costs = vec![0u64; code.len()];
    let bb_starts = crate::interpreter::compute_gas_block_starts(code, bitmask);
    for (pc, &is_start) in bb_starts.iter().enumerate() {
        if is_start {
            costs[pc] = gas_cost_for_block(code, bitmask, pc);
        }
    }
    costs
}

// ============================================================================
// Fast bitmask-based pipeline simulator (safe Rust, zero heap allocation)
// ============================================================================

/// Compact instruction cost for the fast simulator.
#[derive(Clone, Copy, Debug, Default)]
pub struct FastCost {
    pub cycles: u8,
    pub decode_slots: u8,
    /// 0=none, 1=alu, 2=load(+alu), 3=store(+alu), 4=mul(+alu), 5=div(+alu)
    pub exec_unit: u8,
    pub src_mask: u16,
    pub dst_mask: u16,
    pub is_terminator: bool,
    pub is_move_reg: bool,
}

const EU_NONE: u8 = 0;
const EU_ALU: u8 = 1;
const EU_LOAD: u8 = 2;
const EU_STORE: u8 = 3;
const EU_MUL: u8 = 4;
const EU_DIV: u8 = 5;

#[inline(always)]
fn reg_bit(r: u8) -> u16 {
    // PVM clamps registers to 0-12; raw nibble 13/14/15 all map to register 12.
    1u16 << r.min(12)
}

/// Extract branch target from raw code bytes (for gas cost computation).
/// Works for both OneRegImmOffset and TwoRegOneOffset categories.
fn extract_branch_target_raw(code: &[u8], bitmask: &[u8], pc: usize) -> usize {
    let skip = {
        let mut s = 0;
        for j in 0..25 {
            let idx = pc + 1 + j;
            if idx >= bitmask.len() || bitmask[idx] == 1 {
                s = j;
                break;
            }
        }
        s
    };
    let opcode = code[pc];
    // For branches, use the existing decode_args to get the offset
    let cat = crate::instruction::Opcode::from_byte(opcode)
        .map(|o| o.category())
        .unwrap_or(crate::instruction::InstructionCategory::NoArgs);
    let args = crate::args::decode_args(code, pc, skip, cat);
    match args {
        crate::args::Args::RegImmOffset { offset, .. } => offset as usize,
        crate::args::Args::TwoRegOffset { offset, .. } => offset as usize,
        crate::args::Args::Offset { offset } => offset as usize,
        _ => pc,
    }
}

/// Compute FastCost from raw register bytes (no Args enum needed).
/// For branches, extracts target from raw code bytes.
/// Default load/store latency (L2 cache hit baseline).
pub const DEFAULT_MEM_CYCLES: u8 = 25;

#[allow(clippy::too_many_arguments)]
pub fn fast_cost_from_raw(
    opcode_byte: u8,
    ra: u8,
    rb: u8,
    rd: u8,
    pc: u32,
    code: &[u8],
    bitmask: &[u8],
    mem_cycles: u8,
) -> FastCost {
    let r1 = |r: u8| reg_bit(r);
    let r2 = |a: u8, b: u8| reg_bit(a) | reg_bit(b);
    let dst_src_overlap = |dst: u8, s: u16| (reg_bit(dst) & s) != 0;

    let opcode = opcode_byte;
    match opcode {
        // No-arg terminators
        0 => FastCost {
            cycles: 2,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: true,
            is_move_reg: false,
        },
        1 => FastCost {
            cycles: 2,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: true,
            is_move_reg: false,
        },
        2 => FastCost {
            cycles: 40,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: true,
            is_move_reg: false,
        },
        10 => FastCost {
            cycles: 100,
            decode_slots: 4,
            exec_unit: EU_ALU,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: true,
            is_move_reg: false,
        },

        // Control flow
        40 => FastCost {
            cycles: 15,
            decode_slots: 1,
            exec_unit: EU_ALU,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: true,
            is_move_reg: false,
        },
        80 => FastCost {
            cycles: 15,
            decode_slots: 1,
            exec_unit: EU_ALU,
            src_mask: 0,
            dst_mask: r1(ra),
            is_terminator: true,
            is_move_reg: false,
        },
        50 => FastCost {
            cycles: 22,
            decode_slots: 1,
            exec_unit: EU_ALU,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: true,
            is_move_reg: false,
        },
        180 => FastCost {
            cycles: 22,
            decode_slots: 1,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: true,
            is_move_reg: false,
        },

        // Loads
        52..=58 => FastCost {
            cycles: mem_cycles,
            decode_slots: 1,
            exec_unit: EU_LOAD,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        124..=130 => FastCost {
            cycles: mem_cycles,
            decode_slots: 1,
            exec_unit: EU_LOAD,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Stores
        59..=62 => FastCost {
            cycles: mem_cycles,
            decode_slots: 1,
            exec_unit: EU_STORE,
            src_mask: r2(ra, rb),
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },
        120..=123 => FastCost {
            cycles: mem_cycles,
            decode_slots: 1,
            exec_unit: EU_STORE,
            src_mask: r2(ra, rb),
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },
        30..=33 => FastCost {
            cycles: mem_cycles,
            decode_slots: 1,
            exec_unit: EU_STORE,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },
        70..=73 => FastCost {
            cycles: mem_cycles,
            decode_slots: 1,
            exec_unit: EU_STORE,
            src_mask: r1(ra),
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },

        // Load immediates
        51 => FastCost {
            cycles: 1,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        20 => FastCost {
            cycles: 1,
            decode_slots: 2,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // move_reg — no ROB entry
        100 => FastCost {
            cycles: 0,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: true,
        },

        101 => FastCost {
            cycles: 2,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },

        // Branches (reg+imm+offset)
        81..=90 => {
            let target = extract_branch_target_raw(code, bitmask, pc as usize);
            let bc = branch_cost(code, bitmask, target);
            FastCost {
                cycles: bc as u8,
                decode_slots: 1,
                exec_unit: EU_ALU,
                src_mask: r1(ra),
                dst_mask: 0,
                is_terminator: true,
                is_move_reg: false,
            }
        }
        // Branches (two-reg+offset)
        170..=175 => {
            let target = extract_branch_target_raw(code, bitmask, pc as usize);
            let bc = branch_cost(code, bitmask, target);
            FastCost {
                cycles: bc as u8,
                decode_slots: 1,
                exec_unit: EU_ALU,
                src_mask: r2(ra, rb),
                dst_mask: 0,
                is_terminator: true,
                is_move_reg: false,
            }
        }

        // ALU 64-bit 3-reg
        200 | 201 | 210 | 211 | 212 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 1 } else { 2 };
            FastCost {
                cycles: 1,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: s,
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // ALU 32-bit 3-reg
        190 | 191 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 2 } else { 3 };
            FastCost {
                cycles: 2,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: s,
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // ALU 2-op imm 64-bit
        132 | 133 | 134 | 149 | 151 | 152 | 153 | 158 | 110 => {
            let dc = if dst_src_overlap(ra, r1(rb)) { 1 } else { 2 };
            FastCost {
                cycles: 1,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: r1(rb),
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // ALU 2-op imm 32-bit
        131 | 138 | 139 | 140 | 160 => {
            let dc = if dst_src_overlap(ra, r1(rb)) { 2 } else { 3 };
            FastCost {
                cycles: 2,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: r1(rb),
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // Trivial 2-op: popcount, clz, sign_extend, zero_extend, reverse_bytes
        102 | 103 | 104 | 105 | 108 | 109 | 111 => FastCost {
            cycles: 1,
            decode_slots: 1,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        // ctz
        106 | 107 => FastCost {
            cycles: 2,
            decode_slots: 1,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Shifts 64-bit 3-reg
        207 | 208 | 209 | 220 | 222 => {
            let dc = if rb == ra { 2 } else { 3 };
            FastCost {
                cycles: 1,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: r2(rb, rd),
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // Shifts 32-bit 3-reg
        197 | 198 | 199 | 221 | 223 => {
            let dc = if rb == ra { 3 } else { 4 };
            FastCost {
                cycles: 2,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: r2(rb, rd),
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // Shift alt 64-bit
        155 | 156 | 157 | 159 => FastCost {
            cycles: 1,
            decode_slots: 3,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        // Shift alt 32-bit
        144 | 145 | 146 | 161 => FastCost {
            cycles: 2,
            decode_slots: 4,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Comparisons 3-reg
        216 | 217 => FastCost {
            cycles: 3,
            decode_slots: 3,
            exec_unit: EU_ALU,
            src_mask: r2(rb, rd),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        // Comparisons imm
        136 | 137 | 142 | 143 => FastCost {
            cycles: 3,
            decode_slots: 3,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Conditional moves 3-reg
        218 | 219 => FastCost {
            cycles: 2,
            decode_slots: 2,
            exec_unit: EU_ALU,
            src_mask: r2(rb, rd),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        // Conditional moves imm
        147 | 148 => FastCost {
            cycles: 2,
            decode_slots: 3,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Min/Max
        227..=230 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 2 } else { 3 };
            FastCost {
                cycles: 3,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: s,
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // and_inv, or_inv
        224 | 225 => FastCost {
            cycles: 2,
            decode_slots: 3,
            exec_unit: EU_ALU,
            src_mask: r2(rb, rd),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        // xnor
        226 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 2 } else { 3 };
            FastCost {
                cycles: 2,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: s,
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // neg_add_imm
        154 => FastCost {
            cycles: 2,
            decode_slots: 3,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        141 => FastCost {
            cycles: 3,
            decode_slots: 4,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Multiply 64-bit 3-reg
        202 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 1 } else { 2 };
            FastCost {
                cycles: 3,
                decode_slots: dc,
                exec_unit: EU_MUL,
                src_mask: s,
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // mul_imm_64
        150 => {
            let dc = if dst_src_overlap(ra, r1(rb)) { 1 } else { 2 };
            FastCost {
                cycles: 3,
                decode_slots: dc,
                exec_unit: EU_MUL,
                src_mask: r1(rb),
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // Multiply 32-bit 3-reg
        192 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 2 } else { 3 };
            FastCost {
                cycles: 4,
                decode_slots: dc,
                exec_unit: EU_MUL,
                src_mask: s,
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // mul_imm_32
        135 => {
            let dc = if dst_src_overlap(ra, r1(rb)) { 2 } else { 3 };
            FastCost {
                cycles: 4,
                decode_slots: dc,
                exec_unit: EU_MUL,
                src_mask: r1(rb),
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // Multiply upper
        213 | 214 => FastCost {
            cycles: 4,
            decode_slots: 4,
            exec_unit: EU_MUL,
            src_mask: r2(rb, rd),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        215 => FastCost {
            cycles: 6,
            decode_slots: 4,
            exec_unit: EU_MUL,
            src_mask: r2(rb, rd),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Divide
        193 | 194 | 195 | 196 | 203 | 204 | 205 | 206 => FastCost {
            cycles: 60,
            decode_slots: 4,
            exec_unit: EU_DIV,
            src_mask: r2(rb, rd),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Default
        _ => FastCost {
            cycles: 1,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },
    }
}

/// Compute FastCost using pre-decoded branch target from Args.
///
/// For non-branch instructions, identical to `fast_cost_from_raw`. For branches,
/// avoids the redundant `extract_branch_target_raw` call which re-computes skip
/// distances and re-decodes args just to extract the branch offset.
#[inline(always)]
pub fn fast_cost_from_decoded(
    opcode_byte: u8,
    args: &crate::args::Args,
    pc: u32,
    code: &[u8],
    bitmask: &[u8],
    mem_cycles: u8,
) -> FastCost {
    use crate::args::Args;

    // Use raw byte positions for register fields (same as fast_cost_from_raw).
    // The raw nibble positions don't correspond to semantic arg names — the
    // mapping varies by instruction format — so we read directly from code[].
    let pcu = pc as usize;
    let ra = if pcu + 1 < code.len() {
        code[pcu + 1] & 0x0F
    } else {
        0xFF
    };
    let rb = if pcu + 1 < code.len() {
        (code[pcu + 1] >> 4) & 0x0F
    } else {
        0xFF
    };
    let rd = if pcu + 2 < code.len() {
        code[pcu + 2] & 0x0F
    } else {
        0xFF
    };

    // Extract branch target from already-decoded offset (the main optimization:
    // avoids extract_branch_target_raw which does skip computation + decode_args)
    let branch_target = match args {
        Args::RegImmOffset { offset, .. } => *offset as usize,
        Args::TwoRegOffset { offset, .. } => *offset as usize,
        Args::Offset { offset } => *offset as usize,
        _ => pcu,
    };

    let r1 = |r: u8| reg_bit(r);
    let r2 = |a: u8, b: u8| reg_bit(a) | reg_bit(b);
    let dst_src_overlap = |dst: u8, s: u16| (reg_bit(dst) & s) != 0;

    let opcode = opcode_byte;
    match opcode {
        // No-arg terminators
        0 => FastCost {
            cycles: 2,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: true,
            is_move_reg: false,
        },
        1 => FastCost {
            cycles: 2,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: true,
            is_move_reg: false,
        },
        2 => FastCost {
            cycles: 40,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: true,
            is_move_reg: false,
        },
        10 => FastCost {
            cycles: 100,
            decode_slots: 4,
            exec_unit: EU_ALU,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: true,
            is_move_reg: false,
        },

        // Control flow
        40 => FastCost {
            cycles: 15,
            decode_slots: 1,
            exec_unit: EU_ALU,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: true,
            is_move_reg: false,
        },
        80 => FastCost {
            cycles: 15,
            decode_slots: 1,
            exec_unit: EU_ALU,
            src_mask: 0,
            dst_mask: r1(ra),
            is_terminator: true,
            is_move_reg: false,
        },
        50 => FastCost {
            cycles: 22,
            decode_slots: 1,
            exec_unit: EU_ALU,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: true,
            is_move_reg: false,
        },
        180 => FastCost {
            cycles: 22,
            decode_slots: 1,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: true,
            is_move_reg: false,
        },

        // Loads
        52..=58 => FastCost {
            cycles: mem_cycles,
            decode_slots: 1,
            exec_unit: EU_LOAD,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        124..=130 => FastCost {
            cycles: mem_cycles,
            decode_slots: 1,
            exec_unit: EU_LOAD,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Stores
        59..=62 => FastCost {
            cycles: mem_cycles,
            decode_slots: 1,
            exec_unit: EU_STORE,
            src_mask: r2(ra, rb),
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },
        120..=123 => FastCost {
            cycles: mem_cycles,
            decode_slots: 1,
            exec_unit: EU_STORE,
            src_mask: r2(ra, rb),
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },
        30..=33 => FastCost {
            cycles: mem_cycles,
            decode_slots: 1,
            exec_unit: EU_STORE,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },
        70..=73 => FastCost {
            cycles: mem_cycles,
            decode_slots: 1,
            exec_unit: EU_STORE,
            src_mask: r1(ra),
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },

        // Load immediates
        51 => FastCost {
            cycles: 1,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        20 => FastCost {
            cycles: 1,
            decode_slots: 2,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // move_reg — no ROB entry
        100 => FastCost {
            cycles: 0,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: true,
        },

        101 => FastCost {
            cycles: 2,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },

        // Branches (reg+imm+offset) — uses pre-decoded branch target
        81..=90 => {
            let bc = branch_cost(code, bitmask, branch_target);
            FastCost {
                cycles: bc as u8,
                decode_slots: 1,
                exec_unit: EU_ALU,
                src_mask: r1(ra),
                dst_mask: 0,
                is_terminator: true,
                is_move_reg: false,
            }
        }
        // Branches (two-reg+offset) — uses pre-decoded branch target
        170..=175 => {
            let bc = branch_cost(code, bitmask, branch_target);
            FastCost {
                cycles: bc as u8,
                decode_slots: 1,
                exec_unit: EU_ALU,
                src_mask: r2(ra, rb),
                dst_mask: 0,
                is_terminator: true,
                is_move_reg: false,
            }
        }

        // ALU 64-bit 3-reg
        200 | 201 | 210 | 211 | 212 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 1 } else { 2 };
            FastCost {
                cycles: 1,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: s,
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // ALU 32-bit 3-reg
        190 | 191 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 2 } else { 3 };
            FastCost {
                cycles: 2,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: s,
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // ALU 2-op imm 64-bit
        132 | 133 | 134 | 149 | 151 | 152 | 153 | 158 | 110 => {
            let dc = if dst_src_overlap(ra, r1(rb)) { 1 } else { 2 };
            FastCost {
                cycles: 1,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: r1(rb),
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // ALU 2-op imm 32-bit
        131 | 138 | 139 | 140 | 160 => {
            let dc = if dst_src_overlap(ra, r1(rb)) { 2 } else { 3 };
            FastCost {
                cycles: 2,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: r1(rb),
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // Trivial 2-op: popcount, clz, sign_extend, zero_extend, reverse_bytes
        102 | 103 | 104 | 105 | 108 | 109 | 111 => FastCost {
            cycles: 1,
            decode_slots: 1,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        // ctz
        106 | 107 => FastCost {
            cycles: 2,
            decode_slots: 1,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Shifts 64-bit 3-reg
        207 | 208 | 209 | 220 | 222 => {
            let dc = if rb == ra { 2 } else { 3 };
            FastCost {
                cycles: 1,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: r2(rb, rd),
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // Shifts 32-bit 3-reg
        197 | 198 | 199 | 221 | 223 => {
            let dc = if rb == ra { 3 } else { 4 };
            FastCost {
                cycles: 2,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: r2(rb, rd),
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // Shift alt 64-bit
        155 | 156 | 157 | 159 => FastCost {
            cycles: 1,
            decode_slots: 3,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        // Shift alt 32-bit
        144 | 145 | 146 | 161 => FastCost {
            cycles: 2,
            decode_slots: 4,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Comparisons 3-reg
        216 | 217 => FastCost {
            cycles: 3,
            decode_slots: 3,
            exec_unit: EU_ALU,
            src_mask: r2(rb, rd),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        // Comparisons imm
        136 | 137 | 142 | 143 => FastCost {
            cycles: 3,
            decode_slots: 3,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Conditional moves 3-reg
        218 | 219 => FastCost {
            cycles: 2,
            decode_slots: 2,
            exec_unit: EU_ALU,
            src_mask: r2(rb, rd),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        // Conditional moves imm
        147 | 148 => FastCost {
            cycles: 2,
            decode_slots: 3,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Min/Max
        227..=230 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 2 } else { 3 };
            FastCost {
                cycles: 3,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: s,
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // and_inv, or_inv
        224 | 225 => FastCost {
            cycles: 2,
            decode_slots: 3,
            exec_unit: EU_ALU,
            src_mask: r2(rb, rd),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        // xnor
        226 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 2 } else { 3 };
            FastCost {
                cycles: 2,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: s,
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // neg_add_imm
        154 => FastCost {
            cycles: 2,
            decode_slots: 3,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        141 => FastCost {
            cycles: 3,
            decode_slots: 4,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Multiply 64-bit 3-reg
        202 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 1 } else { 2 };
            FastCost {
                cycles: 3,
                decode_slots: dc,
                exec_unit: EU_MUL,
                src_mask: s,
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // mul_imm_64
        150 => {
            let dc = if dst_src_overlap(ra, r1(rb)) { 1 } else { 2 };
            FastCost {
                cycles: 3,
                decode_slots: dc,
                exec_unit: EU_MUL,
                src_mask: r1(rb),
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // Multiply 32-bit 3-reg
        192 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 2 } else { 3 };
            FastCost {
                cycles: 4,
                decode_slots: dc,
                exec_unit: EU_MUL,
                src_mask: s,
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // mul_imm_32
        135 => {
            let dc = if dst_src_overlap(ra, r1(rb)) { 2 } else { 3 };
            FastCost {
                cycles: 4,
                decode_slots: dc,
                exec_unit: EU_MUL,
                src_mask: r1(rb),
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // Multiply upper
        213 | 214 => FastCost {
            cycles: 4,
            decode_slots: 4,
            exec_unit: EU_MUL,
            src_mask: r2(rb, rd),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        215 => FastCost {
            cycles: 6,
            decode_slots: 4,
            exec_unit: EU_MUL,
            src_mask: r2(rb, rd),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Divide
        193 | 194 | 195 | 196 | 203 | 204 | 205 | 206 => FastCost {
            cycles: 60,
            decode_slots: 4,
            exec_unit: EU_DIV,
            src_mask: r2(rb, rd),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Default
        _ => FastCost {
            cycles: 1,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },
    }
}

// === Gas cost lookup table ===
// Replaces the 256-arm match in fast_cost_from_decoded with a single array
// lookup + lightweight mask computation. Eliminates branch-heavy dispatch.

/// Register pattern encoding for the lookup table.
/// Describes which raw register fields contribute to src_mask and dst_mask.
#[derive(Clone, Copy)]
struct GasCostEntry {
    cycles: u8,
    /// Base decode_slots (before overlap adjustment).
    decode_slots: u8,
    exec_unit: u8,
    /// Source mask pattern: 0=none, 1=ra, 2=rb, 3=ra|rb, 4=rb|rd, 5=ra(store-imm)
    src_pat: u8,
    /// Destination mask pattern: 0=none, 1=ra, 2=rd
    dst_pat: u8,
    flags: u8, // bit0=terminator, bit1=move_reg, bit2=needs_branch_cost, bit3=overlap_adjust
    /// For overlap_adjust: decode_slots_if_overlap (lower) and decode_slots_no_overlap (upper nibble)
    overlap_slots: u8,
}

const F_TERM: u8 = 1;
const F_MOVE: u8 = 2;
const F_BRANCH: u8 = 4;
const F_OVERLAP: u8 = 8;
const F_BRANCH2: u8 = 16; // two-reg branch (src=ra|rb)
const F_SHIFT_OVERLAP: u8 = 32; // shift: overlap is rb==ra, not dst_src_overlap

const fn gc(
    cycles: u8,
    decode_slots: u8,
    exec_unit: u8,
    src_pat: u8,
    dst_pat: u8,
    flags: u8,
) -> GasCostEntry {
    GasCostEntry {
        cycles,
        decode_slots,
        exec_unit,
        src_pat,
        dst_pat,
        flags,
        overlap_slots: 0,
    }
}
const fn gc_ov(
    cycles: u8,
    overlap_if: u8,
    overlap_no: u8,
    exec_unit: u8,
    src_pat: u8,
    dst_pat: u8,
    flags: u8,
) -> GasCostEntry {
    GasCostEntry {
        cycles,
        decode_slots: 0,
        exec_unit,
        src_pat,
        dst_pat,
        flags: flags | F_OVERLAP,
        overlap_slots: overlap_if | (overlap_no << 4),
    }
}

static GAS_COST_LUT: [GasCostEntry; 256] = {
    let d = gc(1, 1, EU_NONE, 0, 0, 0); // default
    let mut t = [d; 256];
    // No-arg terminators
    t[0] = gc(2, 1, EU_NONE, 0, 0, F_TERM);
    t[1] = gc(2, 1, EU_NONE, 0, 0, F_TERM);
    t[2] = gc(40, 1, EU_NONE, 0, 0, F_TERM);
    t[10] = gc(100, 4, EU_ALU, 0, 0, F_TERM);
    // Control flow
    t[40] = gc(15, 1, EU_ALU, 0, 0, F_TERM);
    t[80] = gc(15, 1, EU_ALU, 0, 1, F_TERM); // dst=ra
    t[50] = gc(22, 1, EU_ALU, 0, 0, F_TERM);
    t[180] = gc(22, 1, EU_ALU, 2, 1, F_TERM); // src=rb, dst=ra
    // Loads (src=rb, dst=ra)
    let mut i = 52;
    while i <= 58 {
        t[i] = gc(25, 1, EU_LOAD, 2, 1, 0);
        i += 1;
    }
    i = 124;
    while i <= 130 {
        t[i] = gc(25, 1, EU_LOAD, 2, 1, 0);
        i += 1;
    }
    // Stores (src=ra|rb, dst=none)
    i = 59;
    while i <= 62 {
        t[i] = gc(25, 1, EU_STORE, 3, 0, 0);
        i += 1;
    }
    i = 120;
    while i <= 123 {
        t[i] = gc(25, 1, EU_STORE, 3, 0, 0);
        i += 1;
    }
    i = 30;
    while i <= 33 {
        t[i] = gc(25, 1, EU_STORE, 0, 0, 0);
        i += 1;
    }
    i = 70;
    while i <= 73 {
        t[i] = gc(25, 1, EU_STORE, 1, 0, 0);
        i += 1;
    } // src=ra
    // Load immediates
    t[51] = gc(1, 1, EU_NONE, 0, 1, 0);
    t[20] = gc(1, 2, EU_NONE, 0, 1, 0);
    // move_reg
    t[100] = gc(0, 1, EU_NONE, 2, 1, F_MOVE); // src=rb, dst=ra
    t[101] = gc(2, 1, EU_NONE, 0, 0, 0); // nop
    // Branches (reg+imm+offset) — needs branch_cost
    i = 81;
    while i <= 90 {
        t[i] = gc(0, 1, EU_ALU, 1, 0, F_TERM | F_BRANCH);
        i += 1;
    } // src=ra
    // Branches (two-reg+offset)
    i = 170;
    while i <= 175 {
        t[i] = gc(0, 1, EU_ALU, 3, 0, F_TERM | F_BRANCH2);
        i += 1;
    } // src=ra|rb
    // ALU 64-bit 3-reg (src=rb|rd, dst=ra, overlap adjust)
    t[200] = gc_ov(1, 1, 2, EU_ALU, 4, 1, 0);
    t[201] = gc_ov(1, 1, 2, EU_ALU, 4, 1, 0);
    t[210] = gc_ov(1, 1, 2, EU_ALU, 4, 1, 0);
    t[211] = gc_ov(1, 1, 2, EU_ALU, 4, 1, 0);
    t[212] = gc_ov(1, 1, 2, EU_ALU, 4, 1, 0);
    // ALU 32-bit 3-reg
    t[190] = gc_ov(2, 2, 3, EU_ALU, 4, 1, 0);
    t[191] = gc_ov(2, 2, 3, EU_ALU, 4, 1, 0);
    // ALU 2-op imm 64-bit (src=rb, dst=ra, overlap adjust)
    {
        let e = gc_ov(1, 1, 2, EU_ALU, 2, 1, 0);
        t[132] = e;
        t[133] = e;
        t[134] = e;
        t[149] = e;
        t[151] = e;
        t[152] = e;
        t[153] = e;
        t[158] = e;
        t[110] = e;
    }
    // ALU 2-op imm 32-bit
    {
        let e = gc_ov(2, 2, 3, EU_ALU, 2, 1, 0);
        t[131] = e;
        t[138] = e;
        t[139] = e;
        t[140] = e;
        t[160] = e;
    }
    // Trivial 2-op (src=rb, dst=ra)
    {
        let e = gc(1, 1, EU_ALU, 2, 1, 0);
        t[102] = e;
        t[103] = e;
        t[104] = e;
        t[105] = e;
        t[108] = e;
        t[109] = e;
        t[111] = e;
    }
    // ctz
    t[106] = gc(2, 1, EU_ALU, 2, 1, 0);
    t[107] = gc(2, 1, EU_ALU, 2, 1, 0);
    // Shifts 64-bit 3-reg (src=rb|rd, dst=ra, shift overlap: rb==ra)
    {
        let e = gc_ov(1, 2, 3, EU_ALU, 4, 1, F_SHIFT_OVERLAP);
        t[207] = e;
        t[208] = e;
        t[209] = e;
        t[220] = e;
        t[222] = e;
    }
    // Shifts 32-bit 3-reg
    {
        let e = gc_ov(2, 3, 4, EU_ALU, 4, 1, F_SHIFT_OVERLAP);
        t[197] = e;
        t[198] = e;
        t[199] = e;
        t[221] = e;
        t[223] = e;
    }
    // Shift alt 64-bit
    {
        let e = gc(1, 3, EU_ALU, 2, 1, 0);
        t[155] = e;
        t[156] = e;
        t[157] = e;
        t[159] = e;
    }
    // Shift alt 32-bit
    {
        let e = gc(2, 4, EU_ALU, 2, 1, 0);
        t[144] = e;
        t[145] = e;
        t[146] = e;
        t[161] = e;
    }
    // Comparisons 3-reg (src=rb|rd, dst=ra)
    t[216] = gc(3, 3, EU_ALU, 4, 1, 0);
    t[217] = gc(3, 3, EU_ALU, 4, 1, 0);
    // Comparisons imm (src=rb, dst=ra)
    {
        let e = gc(3, 3, EU_ALU, 2, 1, 0);
        t[136] = e;
        t[137] = e;
        t[142] = e;
        t[143] = e;
    }
    // Conditional moves 3-reg
    t[218] = gc(2, 2, EU_ALU, 4, 1, 0);
    t[219] = gc(2, 2, EU_ALU, 4, 1, 0);
    // Conditional moves imm
    t[147] = gc(2, 3, EU_ALU, 2, 1, 0);
    t[148] = gc(2, 3, EU_ALU, 2, 1, 0);
    // Min/Max (src=rb|rd, dst=ra, overlap adjust)
    {
        let e = gc_ov(3, 2, 3, EU_ALU, 4, 1, 0);
        t[227] = e;
        t[228] = e;
        t[229] = e;
        t[230] = e;
    }
    // and_inv, or_inv
    t[224] = gc(2, 3, EU_ALU, 4, 1, 0);
    t[225] = gc(2, 3, EU_ALU, 4, 1, 0);
    // xnor (overlap adjust)
    t[226] = gc_ov(2, 2, 3, EU_ALU, 4, 1, 0);
    // neg_add_imm
    t[154] = gc(2, 3, EU_ALU, 2, 1, 0);
    t[141] = gc(3, 4, EU_ALU, 2, 1, 0);
    // Multiply 64-bit 3-reg (overlap adjust)
    t[202] = gc_ov(3, 1, 2, EU_MUL, 4, 1, 0);
    // mul_imm_64
    t[150] = gc_ov(3, 1, 2, EU_MUL, 2, 1, 0);
    // Multiply 32-bit 3-reg
    t[192] = gc_ov(4, 2, 3, EU_MUL, 4, 1, 0);
    // mul_imm_32
    t[135] = gc_ov(4, 2, 3, EU_MUL, 2, 1, 0);
    // Multiply upper
    t[213] = gc(4, 4, EU_MUL, 4, 1, 0);
    t[214] = gc(4, 4, EU_MUL, 4, 1, 0);
    t[215] = gc(6, 4, EU_MUL, 4, 1, 0);
    // Divide (src=rb|rd, dst=ra)
    {
        let e = gc(60, 4, EU_DIV, 4, 1, 0);
        t[193] = e;
        t[194] = e;
        t[195] = e;
        t[196] = e;
        t[203] = e;
        t[204] = e;
        t[205] = e;
        t[206] = e;
    }
    t
};

/// Feed the gas simulator directly from raw register bytes, skipping FastCost
/// construction. Returns (is_terminator, is_branch_or_special) — the caller
/// uses is_branch_or_special to fall back to the full path for rare cases.
#[inline(always)]
pub fn feed_gas_direct(
    opcode_byte: u8,
    ra: u8,
    rb: u8,
    rd: u8,
    gas_sim: &mut crate::gas_sim::GasSimulator,
    mem_cycles: u8,
) -> (bool, bool) {
    let entry = &GAS_COST_LUT[opcode_byte as usize];
    let flags = entry.flags;

    // Fast path: non-branch, non-overlap, non-move (~90% of instructions).
    if flags & (F_BRANCH | F_BRANCH2 | F_OVERLAP | F_MOVE | F_SHIFT_OVERLAP) == 0 {
        // Map src_pat to register indices (0xFF = "no source")
        let (src1, src2) = match entry.src_pat {
            0 => (0xFF, 0xFF),
            1 => (ra.min(12), 0xFF),
            2 => (rb.min(12), 0xFF),
            3 => (ra.min(12), rb.min(12)),
            4 => (rb.min(12), rd.min(12)),
            _ => (0xFF, 0xFF),
        };
        let dst = if entry.dst_pat == 1 {
            ra.min(12)
        } else if entry.dst_pat == 2 {
            rd.min(12)
        } else {
            0xFF
        };
        // Override cycles for load/store with tier-dependent mem_cycles
        let cycles = if entry.exec_unit == EU_LOAD || entry.exec_unit == EU_STORE {
            mem_cycles
        } else {
            entry.cycles
        };
        gas_sim.feed_direct(cycles, entry.decode_slots, src1, src2, dst);
        return (flags & F_TERM != 0, false);
    }

    // Slow path needed — caller must use the full FastCost path
    (flags & F_TERM != 0, true)
}

/// Compute FastCost via lookup table — replaces the 256-arm match dispatch
/// with a single array access + lightweight mask computation.
#[inline(always)]
pub fn fast_cost_lut(
    opcode_byte: u8,
    args: &crate::args::Args,
    pc: u32,
    code: &[u8],
    bitmask: &[u8],
    mem_cycles: u8,
) -> FastCost {
    let pcu = pc as usize;
    let reg_byte1 = if pcu + 1 < code.len() {
        code[pcu + 1]
    } else {
        0xFF
    };
    let ra = reg_byte1 & 0x0F;
    let rb = (reg_byte1 >> 4) & 0x0F;
    let rd = if pcu + 2 < code.len() {
        code[pcu + 2] & 0x0F
    } else {
        0xFF
    };

    fast_cost_lut_inner(
        opcode_byte,
        args,
        pcu,
        code,
        bitmask,
        ra,
        rb,
        rd,
        mem_cycles,
    )
}

/// Like `fast_cost_lut` but takes pre-extracted register bytes to avoid
/// re-reading code[pc+1] and code[pc+2] (already decoded by the caller).
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub fn fast_cost_lut_regs(
    opcode_byte: u8,
    args: &crate::args::Args,
    pc: usize,
    code: &[u8],
    bitmask: &[u8],
    ra: u8,
    rb: u8,
    rd: u8,
    mem_cycles: u8,
) -> FastCost {
    fast_cost_lut_inner(opcode_byte, args, pc, code, bitmask, ra, rb, rd, mem_cycles)
}

/// Inner implementation — separated to allow the compiler to inline the
/// caller-side register extraction and keep the complex logic out-of-line.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn fast_cost_lut_inner(
    opcode_byte: u8,
    args: &crate::args::Args,
    pcu: usize,
    code: &[u8],
    bitmask: &[u8],
    ra: u8,
    rb: u8,
    rd: u8,
    mem_cycles: u8,
) -> FastCost {
    use crate::args::Args;

    let entry = &GAS_COST_LUT[opcode_byte as usize];
    let flags = entry.flags;

    // Fast path: most instructions are non-branch, non-overlap.
    // Skip the expensive branch cost and overlap calculations.
    if flags & (F_BRANCH | F_BRANCH2 | F_OVERLAP) == 0 {
        // Compute masks inline (branchless via LUT could be even faster,
        // but the match is well-predicted for the common patterns).
        let ra_bit = 1u16 << ra.min(12);
        let rb_bit = 1u16 << rb.min(12);
        let rd_bit = 1u16 << rd.min(12);
        let src_mask: u16 = match entry.src_pat {
            0 => 0,
            1 => ra_bit,
            2 => rb_bit,
            3 => ra_bit | rb_bit,
            4 => rb_bit | rd_bit,
            _ => 0,
        };
        let dst_mask: u16 = if entry.dst_pat == 1 { ra_bit } else { 0 };
        let cycles = if entry.exec_unit == EU_LOAD || entry.exec_unit == EU_STORE {
            mem_cycles
        } else {
            entry.cycles
        };
        return FastCost {
            cycles,
            decode_slots: entry.decode_slots,
            exec_unit: entry.exec_unit,
            src_mask,
            dst_mask,
            is_terminator: flags & F_TERM != 0,
            is_move_reg: flags & F_MOVE != 0,
        };
    }

    // Slow path: branch or overlap instructions
    let ra_bit = 1u16 << ra.min(12);
    let rb_bit = 1u16 << rb.min(12);
    let rd_bit = 1u16 << rd.min(12);

    let src_mask: u16 = match entry.src_pat {
        0 => 0,
        1 => ra_bit,
        2 => rb_bit,
        3 => ra_bit | rb_bit,
        4 => rb_bit | rd_bit,
        _ => 0,
    };
    let dst_mask: u16 = if entry.dst_pat == 1 { ra_bit } else { 0 };

    let cycles = if flags & (F_BRANCH | F_BRANCH2) != 0 {
        let branch_target = match args {
            Args::RegImmOffset { offset, .. } => *offset as usize,
            Args::TwoRegOffset { offset, .. } => *offset as usize,
            Args::Offset { offset } => *offset as usize,
            _ => pcu,
        };
        branch_cost(code, bitmask, branch_target) as u8
    } else if entry.exec_unit == EU_LOAD || entry.exec_unit == EU_STORE {
        mem_cycles
    } else {
        entry.cycles
    };

    let decode_slots = if flags & F_OVERLAP != 0 {
        let overlap = if flags & F_SHIFT_OVERLAP != 0 {
            rb == ra
        } else {
            (dst_mask & src_mask) != 0
        };
        if overlap {
            entry.overlap_slots & 0x0F
        } else {
            entry.overlap_slots >> 4
        }
    } else {
        entry.decode_slots
    };

    FastCost {
        cycles,
        decode_slots,
        exec_unit: entry.exec_unit,
        src_mask,
        dst_mask,
        is_terminator: flags & F_TERM != 0,
        is_move_reg: flags & F_MOVE != 0,
    }
}

/// Check if execution unit is available.
#[inline(always)]
fn eu_available(avail: &[u8; 5], eu: u8) -> bool {
    match eu {
        EU_NONE => true,
        EU_ALU => avail[0] >= 1,
        EU_LOAD => avail[0] >= 1 && avail[1] >= 1,
        EU_STORE => avail[0] >= 1 && avail[2] >= 1,
        EU_MUL => avail[0] >= 1 && avail[3] >= 1,
        EU_DIV => avail[0] >= 1 && avail[4] >= 1,
        _ => false,
    }
}

/// Consume execution unit.
#[inline(always)]
fn eu_consume(avail: &mut [u8; 5], eu: u8) {
    match eu {
        EU_ALU => {
            avail[0] -= 1;
        }
        EU_LOAD => {
            avail[0] -= 1;
            avail[1] -= 1;
        }
        EU_STORE => {
            avail[0] -= 1;
            avail[2] -= 1;
        }
        EU_MUL => {
            avail[0] -= 1;
            avail[3] -= 1;
        }
        EU_DIV => {
            avail[0] -= 1;
            avail[4] -= 1;
        }
        _ => {}
    }
}

// ---- Cycle advance ----

/// Advance all EXE entries by one cycle. Entries reaching 0 transition to FIN.
/// Uses bitmask iteration — only touches active entries (O(popcount) not O(32)).
#[inline(always)]
fn advance_cycle(cycles_left: &mut [u8; 32], exe_mask: &mut u32, fin_mask: &mut u32) {
    let mut exe = *exe_mask;
    while exe != 0 {
        let i = exe.trailing_zeros() as usize;
        exe &= exe - 1;
        if cycles_left[i] <= 1 {
            cycles_left[i] = 0;
            *exe_mask &= !(1u32 << i);
            *fin_mask |= 1u32 << i;
        } else {
            cycles_left[i] -= 1;
        }
    }
}

#[cfg(feature = "std")]
fn gas_sim_fast(
    instrs: &[crate::recompiler::predecode::PreDecodedInst],
    _code: &[u8],
    _bitmask: &[u8],
) -> u32 {
    // SoA ROB arrays (32 entries, stack-allocated)
    let mut state = [0u8; 32]; // 0=empty, 1=wait, 2=exe, 3=fin
    let mut cycles_left = [0u8; 32];
    let mut exec_unit = [0u8; 32];
    let mut deps = [0u32; 32];
    let mut reg_writer = [0xFFu8; 16]; // per-register: ROB slot that last wrote it

    // Bitmask tracking
    let mut fin_mask: u32 = 0;
    let mut wait_mask: u32 = 0;
    let mut exe_mask: u32 = 0;

    let mut next_slot: u8 = 0;
    let mut instr_idx: usize = 0;
    let mut cycles: u32 = 0;
    let mut decode_slots: u8 = 4;
    let mut dispatch_slots: u8 = 5;
    let mut eu_avail: [u8; 5] = [4, 4, 4, 1, 1]; // alu, load, store, mul, div

    let _done_decoding = |idx: usize| idx >= instrs.len();

    for _safety in 0..100_000u32 {
        // Phase 1: Decode as many instructions as possible this cycle
        while instr_idx < instrs.len() && decode_slots > 0 && (next_slot as usize) < 32 {
            let ii = &instrs[instr_idx];
            let cost = fast_cost_from_raw(
                ii.opcode as u8,
                ii.ra,
                ii.rb,
                ii.rd,
                ii.pc,
                _code,
                _bitmask,
                DEFAULT_MEM_CYCLES,
            );

            if cost.is_move_reg {
                decode_slots = decode_slots.saturating_sub(cost.decode_slots);
                instr_idx = if cost.is_terminator {
                    instrs.len()
                } else {
                    instr_idx + 1
                };
                continue;
            }

            // Build dependency mask from reg_writer lookups
            let mut dep_mask: u32 = 0;
            let mut src = cost.src_mask;
            while src != 0 {
                let reg = src.trailing_zeros() as usize;
                src &= src - 1;
                let writer = reg_writer[reg];
                if writer != 0xFF && (fin_mask & (1u32 << writer)) == 0 {
                    dep_mask |= 1u32 << writer;
                }
            }

            let slot = next_slot as usize;
            state[slot] = 1; // WAIT
            cycles_left[slot] = cost.cycles;
            exec_unit[slot] = cost.exec_unit;
            deps[slot] = dep_mask;
            wait_mask |= 1u32 << slot;

            let mut dst = cost.dst_mask;
            while dst != 0 {
                let reg = dst.trailing_zeros() as usize;
                dst &= dst - 1;
                reg_writer[reg] = next_slot;
            }

            next_slot += 1;
            decode_slots = decode_slots.saturating_sub(cost.decode_slots);
            instr_idx = if cost.is_terminator {
                instrs.len()
            } else {
                instr_idx + 1
            };
        }

        // Phase 2: Dispatch as many ready instructions as possible this cycle
        while dispatch_slots > 0 {
            let mut candidates = wait_mask;
            let mut found = false;
            while candidates != 0 {
                let i = candidates.trailing_zeros() as usize;
                candidates &= candidates - 1;
                if (deps[i] & !fin_mask) == 0 && eu_available(&eu_avail, exec_unit[i]) {
                    eu_consume(&mut eu_avail, exec_unit[i]);
                    state[i] = 2; // EXE
                    wait_mask &= !(1u32 << i);
                    exe_mask |= 1u32 << i;
                    dispatch_slots -= 1;
                    found = true;
                    break; // re-scan from start (priority order)
                }
            }
            if !found {
                break;
            }
        }

        // Phase 3: Done check
        if instr_idx >= instrs.len() && exe_mask == 0 && wait_mask == 0 {
            break;
        }

        // Phase 4: Advance cycle — decrement cycles_left for EXE entries, transition to FIN
        advance_cycle(&mut cycles_left, &mut exe_mask, &mut fin_mask);

        cycles += 1;
        decode_slots = 4;
        dispatch_slots = 5;
        eu_avail = [4, 4, 4, 1, 1];
    }

    cycles
}

#[cfg(feature = "std")]
/// Fast gas cost computation using bitmask-based pipeline simulator.
pub fn gas_cost_for_block_fast(
    instrs: &[crate::recompiler::predecode::PreDecodedInst],
    code: &[u8],
    bitmask: &[u8],
) -> u64 {
    let cycles = gas_sim_fast(instrs, code, bitmask);
    if cycles > 3 { (cycles - 3) as u64 } else { 1 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gas_sim::GasSimulator;

    /// Helper: compute gas cost for a single-block program using GasSimulator.
    fn block_cost(code: &[u8], bitmask: &[u8]) -> u32 {
        let mut sim = GasSimulator::new();
        let mut pc = 0;
        while pc < code.len() {
            if pc < bitmask.len() && bitmask[pc] != 1 {
                pc += 1;
                continue;
            }
            let opcode_byte = code[pc];
            let raw_ra = if pc + 1 < code.len() {
                code[pc + 1] & 0x0F
            } else {
                0xFF
            };
            let raw_rb = if pc + 1 < code.len() {
                (code[pc + 1] >> 4) & 0x0F
            } else {
                0xFF
            };
            let raw_rd = if pc + 2 < code.len() {
                code[pc + 2] & 0x0F
            } else {
                0xFF
            };
            let fc = fast_cost_from_raw(
                opcode_byte,
                raw_ra,
                raw_rb,
                raw_rd,
                pc as u32,
                code,
                bitmask,
                DEFAULT_MEM_CYCLES,
            );
            sim.feed(&fc);
            if fc.is_terminator {
                break;
            }
            let skip = skip_distance(bitmask, pc);
            pc += 1 + skip;
        }
        sim.flush_and_get_cost()
    }

    #[test]
    fn test_single_trap() {
        // trap = 2 cycles, max(2-3,1) = 1
        assert_eq!(block_cost(&[0u8], &[1u8]), 1);
    }

    #[test]
    fn test_single_ecalli() {
        // ecalli = 100 cycles, max(100-3,1) = 97
        assert_eq!(block_cost(&[10u8, 0], &[1, 0]), 97);
    }

    #[test]
    fn test_single_jump() {
        // jump = 15 cycles, max(15-3,1) = 12
        assert_eq!(block_cost(&[40u8, 0], &[1, 0]), 12);
    }

    #[test]
    fn test_single_fallthrough() {
        // fallthrough = 2 cycles, max(2-3,1) = 1
        assert_eq!(block_cost(&[1u8], &[1]), 1);
    }

    #[test]
    fn test_load_imm_then_trap() {
        let cost = block_cost(&[51, 0, 42, 0], &[1, 0, 0, 1]);
        assert!(cost >= 1, "cost should be >= 1, got {}", cost);
    }
}
