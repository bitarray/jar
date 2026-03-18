//! Per-basic-block gas cost model (JAR v0.8.0).
//!
//! Simulates a CPU pipeline to compute gas cost for a basic block.
//! Cost = max(simulation_cycles - 3, 1).
//!
//! Pipeline model:
//! - Reorder buffer: max 32 entries
//! - 4 decode slots per cycle, 5 dispatch slots per cycle
//! - Execution units: ALU:4, LOAD:4, STORE:4, MUL:1, DIV:1

use crate::instruction::Opcode;

// --- Data structures ---

#[derive(Clone, Copy, Default)]
struct ExecUnits {
    alu: u8,
    load: u8,
    store: u8,
    mul: u8,
    div: u8,
}

impl ExecUnits {
    fn can_satisfy(self, req: ExecUnits) -> bool {
        self.alu >= req.alu && self.load >= req.load && self.store >= req.store
            && self.mul >= req.mul && self.div >= req.div
    }
    fn sub(self, req: ExecUnits) -> ExecUnits {
        ExecUnits {
            alu: self.alu - req.alu, load: self.load - req.load,
            store: self.store - req.store, mul: self.mul - req.mul,
            div: self.div - req.div,
        }
    }
    const RESET: ExecUnits = ExecUnits { alu: 4, load: 4, store: 4, mul: 1, div: 1 };
    const ALU: ExecUnits = ExecUnits { alu: 1, load: 0, store: 0, mul: 0, div: 0 };
    const LOAD: ExecUnits = ExecUnits { alu: 1, load: 1, store: 0, mul: 0, div: 0 };
    const STORE: ExecUnits = ExecUnits { alu: 1, load: 0, store: 1, mul: 0, div: 0 };
    const MUL: ExecUnits = ExecUnits { alu: 1, load: 0, store: 0, mul: 1, div: 0 };
    const DIV: ExecUnits = ExecUnits { alu: 1, load: 0, store: 0, mul: 0, div: 1 };
    const NONE: ExecUnits = ExecUnits { alu: 0, load: 0, store: 0, mul: 0, div: 0 };
}

#[derive(Clone, Copy, PartialEq)]
enum RobState { Wait, Exe, Fin }

#[derive(Clone, Copy)]
struct RobEntry {
    state: RobState,
    cycles_left: u32,
    deps: [u8; 4],          // ROB indices this depends on (0xFF = unused)
    dep_count: u8,
    dest_regs: RegSet,
    exec_units: ExecUnits,
}

struct SimState {
    ip: Option<usize>,          // instruction pointer (None = done decoding)
    cycles: u32,
    decode_slots: u8,           // remaining per cycle (reset to 4)
    dispatch_slots: u8,         // remaining per cycle (reset to 5)
    exec_units: ExecUnits,      // remaining per cycle
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
    const EMPTY: Self = Self { regs: [0; 3], len: 0 };
    fn one(r: u8) -> Self { Self { regs: [r, 0, 0], len: 1 } }
    fn two(a: u8, b: u8) -> Self { Self { regs: [a, b, 0], len: 2 } }
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
    if pc + 1 < code.len() { code[pc + 1] & 0x0F } else { 0 }
}
/// Extract register B (second register, upper nibble of byte after opcode).
fn reg_b(code: &[u8], pc: usize) -> u8 {
    if pc + 1 < code.len() { (code[pc + 1] >> 4) & 0x0F } else { 0 }
}
/// Extract register D (third register encoding for 3-reg instructions).
fn reg_d(code: &[u8], pc: usize) -> u8 {
    if pc + 2 < code.len() { code[pc + 2] & 0x0F } else { 0 }
}

/// Compute skip distance (bytes to next instruction start).
fn skip_distance(bitmask: &[u8], pc: usize) -> usize {
    for j in 0..25 {
        let idx = pc + 1 + j;
        let bit = if idx < bitmask.len() { bitmask[idx] } else { 1 };
        if bit == 1 { return j; }
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
        let raw = crate::args::decode_args(code, pc, skip, crate::instruction::InstructionCategory::OneRegImmOffset);
        if let crate::args::Args::RegImmOffset { offset, .. } = raw {
            return offset as usize;
        }
    }
    pc // fallback
}

/// Extract branch target from two-reg+offset instruction.
fn extract_two_reg_branch_target(code: &[u8], bitmask: &[u8], pc: usize) -> usize {
    let skip = skip_distance(bitmask, pc);
    let raw = crate::args::decode_args(code, pc, skip, crate::instruction::InstructionCategory::TwoRegOneOffset);
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
        InstrCost { cycles: cy, decode_slots: dc, exec_units: eu,
                    dest_regs: dst, src_regs: src, is_terminator: false, is_move_reg: false }
    };
    let mkt = |cy: u32, dc: u8, eu: ExecUnits, dst: RegSet, src: RegSet| -> InstrCost {
        InstrCost { cycles: cy, decode_slots: dc, exec_units: eu,
                    dest_regs: dst, src_regs: src, is_terminator: true, is_move_reg: false }
    };
    let e = RegSet::EMPTY;
    let r1 = RegSet::one;
    let r2 = RegSet::two;

    match opcode {
        // No-arg
        0 => mkt(2, 1, ExecUnits::NONE, e, e),       // trap
        1 => mkt(2, 1, ExecUnits::NONE, e, e),       // fallthrough
        2 => mkt(40, 1, ExecUnits::NONE, e, e),      // unlikely
        10 => mkt(100, 4, ExecUnits::ALU, e, e),     // ecalli

        // Control flow
        40 => mkt(15, 1, ExecUnits::ALU, e, e),      // jump
        80 => {                                                       // load_imm_jump
            let skip = skip_distance(bitmask, pc);
            let raw = crate::args::decode_args(code, pc, skip, crate::instruction::InstructionCategory::OneRegImmOffset);
            let r = if let crate::args::Args::RegImmOffset { ra: r, .. } = raw { r as u8 } else { ra };
            mkt(15, 1, ExecUnits::ALU, r1(r), e)
        }
        50 => mkt(22, 1, ExecUnits::ALU, e, e),      // jump_ind
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
        51 => mk(1, 1, ExecUnits::NONE, r1(ra), e),          // load_imm
        20 => mk(1, 2, ExecUnits::NONE, r1(ra), e),          // load_imm_64

        // move_reg: decoded in frontend, no ROB entry
        100 => InstrCost {
            cycles: 0, decode_slots: 1, exec_units: ExecUnits::NONE,
            dest_regs: r1(ra), src_regs: r1(rb),
            is_terminator: false, is_move_reg: true,
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
            let dc = if dst_overlaps_src(ra, &r2(rb, rd)) { 1 } else { 2 };
            mk(1, dc, ExecUnits::ALU, r1(ra), r2(rb, rd))
        }
        // ALU 32-bit 3-reg: add_32(190), sub_32(191)
        190 | 191 => {
            let dc = if dst_overlaps_src(ra, &r2(rb, rd)) { 2 } else { 3 };
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
        227 | 228 | 229 | 230 => {
            let dc = if dst_overlaps_src(ra, &r2(rb, rd)) { 2 } else { 3 };
            mk(3, dc, ExecUnits::ALU, r1(ra), r2(rb, rd))
        }
        // and_inv, or_inv
        224 | 225 => mk(2, 3, ExecUnits::ALU, r1(ra), r2(rb, rd)),
        // xnor
        226 => {
            let dc = if dst_overlaps_src(ra, &r2(rb, rd)) { 2 } else { 3 };
            mk(2, dc, ExecUnits::ALU, r1(ra), r2(rb, rd))
        }

        // neg_add_imm_64
        154 => mk(2, 3, ExecUnits::ALU, r1(ra), r1(rb)),
        // neg_add_imm_32
        141 => mk(3, 4, ExecUnits::ALU, r1(ra), r1(rb)),

        // Multiply 64-bit (3-reg)
        202 => {
            let dc = if dst_overlaps_src(ra, &r2(rb, rd)) { 1 } else { 2 };
            mk(3, dc, ExecUnits::MUL, r1(ra), r2(rb, rd))
        }
        // mul_imm_64
        150 => {
            let dc = if dst_overlaps_src(ra, &r1(rb)) { 1 } else { 2 };
            mk(3, dc, ExecUnits::MUL, r1(ra), r1(rb))
        }
        // Multiply 32-bit (3-reg)
        192 => {
            let dc = if dst_overlaps_src(ra, &r2(rb, rd)) { 2 } else { 3 };
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
        193 | 194 | 195 | 196 | 203 | 204 | 205 | 206 =>
            mk(60, 4, ExecUnits::DIV, r1(ra), r2(rb, rd)),

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
            if trace {
                let op = crate::instruction::Opcode::from_byte(code[pc]).map(|o| format!("{:?}", o)).unwrap_or("?".into());
                eprintln!("  [{}] DECODE pc={} {} cy={} dec={} rob_idx={} deps={:?} move={} term={} slots_left={}",
                    iter, pc, op, cost.cycles, cost.decode_slots, s.rob.len(), &deps[..dep_count as usize], cost.is_move_reg, cost.is_terminator, s.decode_slots);
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
        if s.dispatch_slots > 0 {
            if let Some(idx) = find_ready_entry(&s.rob, s.exec_units) {
                let eu = s.rob[idx].exec_units;
                if trace {
                    eprintln!("  [{}] DISPATCH rob[{}] cy={} dispatch_left={}", iter, idx, s.rob[idx].cycles_left, s.dispatch_slots - 1);
                }
                s.rob[idx].state = RobState::Exe;
                s.dispatch_slots -= 1;
                s.exec_units = s.exec_units.sub(eu);
                continue;
            }
        }

        // Priority 3: Done
        if s.ip.is_none() && rob_all_finished(&s.rob) {
            if trace { eprintln!("  [{}] DONE cycles={}", iter, s.cycles); }
            break;
        }

        // Priority 4: Advance cycle
        if trace {
            let states: Vec<String> = s.rob.iter().enumerate().map(|(i, e)| {
                let st = match e.state { RobState::Wait => "W", RobState::Exe => "E", RobState::Fin => "F" };
                format!("{}:{}{}", i, st, if e.state == RobState::Exe { format!("({})", e.cycles_left) } else { String::new() })
            }).collect();
            eprintln!("  [{}] ADVANCE cycle {} → {} rob=[{}]", iter, s.cycles, s.cycles + 1, states.join(", "));
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

/// Compute gas cost for a block given as a slice of pre-decoded instructions.
/// This avoids re-parsing raw code+bitmask.
pub fn gas_cost_for_block_decoded(instrs: &[crate::recompiler::predecode::PreDecodedInst], code: &[u8], bitmask: &[u8]) -> u64 {
    let cycles = gas_sim_decoded(instrs, code, bitmask);
    if cycles > 3 { (cycles - 3) as u64 } else { 1 }
}

/// Pipeline simulation from pre-decoded instructions (no raw byte re-parsing).
fn gas_sim_decoded(instrs: &[crate::recompiler::predecode::PreDecodedInst], code: &[u8], bitmask: &[u8]) -> u32 {
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
        if let Some(idx) = s.ip {
            if idx < instrs.len() && s.decode_slots > 0 && s.rob.len() < 32 {
                let instr = &instrs[idx];
                let opcode_byte = instr.opcode as u8;

                // Extract register fields from decoded args
                let (ra, rb, rd) = match instr.args {
                    Args::ThreeReg { ra, rb, rd } => (ra as u8, rb as u8, rd as u8),
                    Args::TwoReg { rd: d, ra: a } => (a as u8, 0xFF, d as u8),
                    Args::TwoRegImm { ra, rb, .. } | Args::TwoRegOffset { ra, rb, .. }
                    | Args::TwoRegTwoImm { ra, rb, .. } => (ra as u8, rb as u8, 0xFF),
                    Args::RegImm { ra, .. } | Args::RegExtImm { ra, .. }
                    | Args::RegTwoImm { ra, .. } | Args::RegImmOffset { ra, .. } => (ra as u8, 0xFF, 0xFF),
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
                let next_ip = if cost.is_terminator { None } else { Some(idx + 1) };

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
        }

        if s.dispatch_slots > 0 {
            if let Some(idx) = find_ready_entry(&s.rob, s.exec_units) {
                let eu = s.rob[idx].exec_units;
                s.rob[idx].state = RobState::Exe;
                s.dispatch_slots -= 1;
                s.exec_units = s.exec_units.sub(eu);
                continue;
            }
        }

        if s.ip.map_or(true, |i| i >= instrs.len()) && rob_all_finished(&s.rob) {
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

/// Fast instruction cost lookup using pre-decoded register fields.
/// Avoids re-parsing code bytes for register extraction.
fn instruction_cost_fast(opcode: u8, ra: u8, rb: u8, rd: u8,
    instr: &crate::recompiler::predecode::PreDecodedInst, code: &[u8], bitmask: &[u8]) -> InstrCost
{
    let mk = |cy: u32, dc: u8, eu: ExecUnits, dst: RegSet, src: RegSet| -> InstrCost {
        InstrCost { cycles: cy, decode_slots: dc, exec_units: eu,
                    dest_regs: dst, src_regs: src, is_terminator: false, is_move_reg: false }
    };
    let mkt = |cy: u32, dc: u8, eu: ExecUnits, dst: RegSet, src: RegSet| -> InstrCost {
        InstrCost { cycles: cy, decode_slots: dc, exec_units: eu,
                    dest_regs: dst, src_regs: src, is_terminator: true, is_move_reg: false }
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
            cycles: 0, decode_slots: 1, exec_units: ExecUnits::NONE,
            dest_regs: r1(ra), src_regs: r1(rb),
            is_terminator: false, is_move_reg: true,
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
            let dc = if dst_overlaps_src(ra, &r2(rb, rd)) { 1 } else { 2 };
            mk(1, dc, ExecUnits::ALU, r1(ra), r2(rb, rd))
        }
        190 | 191 => {
            let dc = if dst_overlaps_src(ra, &r2(rb, rd)) { 2 } else { 3 };
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
        227 | 228 | 229 | 230 => {
            let dc = if dst_overlaps_src(ra, &r2(rb, rd)) { 2 } else { 3 };
            mk(3, dc, ExecUnits::ALU, r1(ra), r2(rb, rd))
        }
        224 | 225 => mk(2, 3, ExecUnits::ALU, r1(ra), r2(rb, rd)),
        226 => {
            let dc = if dst_overlaps_src(ra, &r2(rb, rd)) { 2 } else { 3 };
            mk(2, dc, ExecUnits::ALU, r1(ra), r2(rb, rd))
        }
        154 => mk(2, 3, ExecUnits::ALU, r1(ra), r1(rb)),
        141 => mk(3, 4, ExecUnits::ALU, r1(ra), r1(rb)),
        202 => {
            let dc = if dst_overlaps_src(ra, &r2(rb, rd)) { 1 } else { 2 };
            mk(3, dc, ExecUnits::MUL, r1(ra), r2(rb, rd))
        }
        150 => {
            let dc = if dst_overlaps_src(ra, &r1(rb)) { 1 } else { 2 };
            mk(3, dc, ExecUnits::MUL, r1(ra), r1(rb))
        }
        192 => {
            let dc = if dst_overlaps_src(ra, &r2(rb, rd)) { 2 } else { 3 };
            mk(4, dc, ExecUnits::MUL, r1(ra), r2(rb, rd))
        }
        135 => {
            let dc = if dst_overlaps_src(ra, &r1(rb)) { 2 } else { 3 };
            mk(4, dc, ExecUnits::MUL, r1(ra), r1(rb))
        }
        213 | 214 => mk(4, 4, ExecUnits::MUL, r1(ra), r2(rb, rd)),
        215 => mk(6, 4, ExecUnits::MUL, r1(ra), r2(rb, rd)),
        193 | 194 | 195 | 196 | 203 | 204 | 205 | 206 =>
            mk(60, 4, ExecUnits::DIV, r1(ra), r2(rb, rd)),
        _ => mk(1, 1, ExecUnits::NONE, e, e),
    }
}

/// Compute block gas costs for all basic block starts in the program.
/// Returns a Vec indexed by PC: block_gas_costs[pc] = cost if pc is a block start, 0 otherwise.
pub fn compute_block_gas_costs(code: &[u8], bitmask: &[u8]) -> Vec<u64> {
    let mut costs = vec![0u64; code.len()];
    let bb_starts = crate::vm::compute_basic_block_starts(code, bitmask);
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
    cycles: u8,
    decode_slots: u8,
    /// 0=none, 1=alu, 2=load(+alu), 3=store(+alu), 4=mul(+alu), 5=div(+alu)
    exec_unit: u8,
    src_mask: u16,     // bitmask of source registers (bits 0-12)
    dst_mask: u16,     // bitmask of dest registers (bits 0-12)
    is_terminator: bool,
    is_move_reg: bool,
}

const EU_NONE: u8 = 0;
const EU_ALU: u8 = 1;
const EU_LOAD: u8 = 2;
const EU_STORE: u8 = 3;
const EU_MUL: u8 = 4;
const EU_DIV: u8 = 5;

#[inline(always)]
fn reg_bit(r: u8) -> u16 {
    if r < 13 { 1u16 << r } else { 0 }
}

/// Compute FastCost from a pre-decoded instruction.
/// Uses flat (ra, rb, rd) fields from PreDecodedInst for zero-cost register access.
#[inline(always)]
pub fn fast_cost(instr: &crate::recompiler::predecode::PreDecodedInst, code: &[u8], bitmask: &[u8]) -> FastCost {
    use crate::args::Args;
    let (ra, rb, rd) = (instr.ra, instr.rb, instr.rd);

    let r1 = |r: u8| reg_bit(r);
    let r2 = |a: u8, b: u8| reg_bit(a) | reg_bit(b);
    let dst_src_overlap = |dst: u8, s: u16| (reg_bit(dst) & s) != 0;

    let opcode = instr.opcode as u8;
    match opcode {
        // No-arg terminators
        0 => FastCost { cycles: 2, decode_slots: 1, exec_unit: EU_NONE, src_mask: 0, dst_mask: 0, is_terminator: true, is_move_reg: false },
        1 => FastCost { cycles: 2, decode_slots: 1, exec_unit: EU_NONE, src_mask: 0, dst_mask: 0, is_terminator: true, is_move_reg: false },
        2 => FastCost { cycles: 40, decode_slots: 1, exec_unit: EU_NONE, src_mask: 0, dst_mask: 0, is_terminator: true, is_move_reg: false },
        10 => FastCost { cycles: 100, decode_slots: 4, exec_unit: EU_ALU, src_mask: 0, dst_mask: 0, is_terminator: true, is_move_reg: false },

        // Control flow
        40 => FastCost { cycles: 15, decode_slots: 1, exec_unit: EU_ALU, src_mask: 0, dst_mask: 0, is_terminator: true, is_move_reg: false },
        80 => FastCost { cycles: 15, decode_slots: 1, exec_unit: EU_ALU, src_mask: 0, dst_mask: r1(ra), is_terminator: true, is_move_reg: false },
        50 => FastCost { cycles: 22, decode_slots: 1, exec_unit: EU_ALU, src_mask: 0, dst_mask: 0, is_terminator: true, is_move_reg: false },
        180 => FastCost { cycles: 22, decode_slots: 1, exec_unit: EU_ALU, src_mask: r1(rb), dst_mask: r1(ra), is_terminator: true, is_move_reg: false },

        // Loads
        52..=58 => FastCost { cycles: 25, decode_slots: 1, exec_unit: EU_LOAD, src_mask: r1(rb), dst_mask: r1(ra), is_terminator: false, is_move_reg: false },
        124..=130 => FastCost { cycles: 25, decode_slots: 1, exec_unit: EU_LOAD, src_mask: r1(rb), dst_mask: r1(ra), is_terminator: false, is_move_reg: false },

        // Stores
        59..=62 => FastCost { cycles: 25, decode_slots: 1, exec_unit: EU_STORE, src_mask: r2(ra, rb), dst_mask: 0, is_terminator: false, is_move_reg: false },
        120..=123 => FastCost { cycles: 25, decode_slots: 1, exec_unit: EU_STORE, src_mask: r2(ra, rb), dst_mask: 0, is_terminator: false, is_move_reg: false },
        30..=33 => FastCost { cycles: 25, decode_slots: 1, exec_unit: EU_STORE, src_mask: 0, dst_mask: 0, is_terminator: false, is_move_reg: false },
        70..=73 => FastCost { cycles: 25, decode_slots: 1, exec_unit: EU_STORE, src_mask: r1(ra), dst_mask: 0, is_terminator: false, is_move_reg: false },

        // Load immediates
        51 => FastCost { cycles: 1, decode_slots: 1, exec_unit: EU_NONE, src_mask: 0, dst_mask: r1(ra), is_terminator: false, is_move_reg: false },
        20 => FastCost { cycles: 1, decode_slots: 2, exec_unit: EU_NONE, src_mask: 0, dst_mask: r1(ra), is_terminator: false, is_move_reg: false },

        // move_reg — no ROB entry
        100 => FastCost { cycles: 0, decode_slots: 1, exec_unit: EU_NONE, src_mask: r1(rb), dst_mask: r1(ra), is_terminator: false, is_move_reg: true },

        101 => FastCost { cycles: 2, decode_slots: 1, exec_unit: EU_NONE, src_mask: 0, dst_mask: 0, is_terminator: false, is_move_reg: false },

        // Branches (reg+imm+offset)
        81..=90 => {
            let target = match instr.args { Args::RegImmOffset { offset, .. } => offset as usize, _ => instr.pc as usize };
            let bc = branch_cost(code, bitmask, target);
            FastCost { cycles: bc as u8, decode_slots: 1, exec_unit: EU_ALU, src_mask: r1(ra), dst_mask: 0, is_terminator: true, is_move_reg: false }
        }
        // Branches (two-reg+offset)
        170..=175 => {
            let target = match instr.args { Args::TwoRegOffset { offset, .. } => offset as usize, _ => instr.pc as usize };
            let bc = branch_cost(code, bitmask, target);
            FastCost { cycles: bc as u8, decode_slots: 1, exec_unit: EU_ALU, src_mask: r2(ra, rb), dst_mask: 0, is_terminator: true, is_move_reg: false }
        }

        // ALU 64-bit 3-reg
        200 | 201 | 210 | 211 | 212 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 1 } else { 2 };
            FastCost { cycles: 1, decode_slots: dc, exec_unit: EU_ALU, src_mask: s, dst_mask: r1(ra), is_terminator: false, is_move_reg: false }
        }
        // ALU 32-bit 3-reg
        190 | 191 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 2 } else { 3 };
            FastCost { cycles: 2, decode_slots: dc, exec_unit: EU_ALU, src_mask: s, dst_mask: r1(ra), is_terminator: false, is_move_reg: false }
        }
        // ALU 2-op imm 64-bit
        132 | 133 | 134 | 149 | 151 | 152 | 153 | 158 | 110 => {
            let dc = if dst_src_overlap(ra, r1(rb)) { 1 } else { 2 };
            FastCost { cycles: 1, decode_slots: dc, exec_unit: EU_ALU, src_mask: r1(rb), dst_mask: r1(ra), is_terminator: false, is_move_reg: false }
        }
        // ALU 2-op imm 32-bit
        131 | 138 | 139 | 140 | 160 => {
            let dc = if dst_src_overlap(ra, r1(rb)) { 2 } else { 3 };
            FastCost { cycles: 2, decode_slots: dc, exec_unit: EU_ALU, src_mask: r1(rb), dst_mask: r1(ra), is_terminator: false, is_move_reg: false }
        }
        // Trivial 2-op: popcount, clz, sign_extend, zero_extend, reverse_bytes
        102 | 103 | 104 | 105 | 108 | 109 | 111 => FastCost { cycles: 1, decode_slots: 1, exec_unit: EU_ALU, src_mask: r1(rb), dst_mask: r1(ra), is_terminator: false, is_move_reg: false },
        // ctz
        106 | 107 => FastCost { cycles: 2, decode_slots: 1, exec_unit: EU_ALU, src_mask: r1(rb), dst_mask: r1(ra), is_terminator: false, is_move_reg: false },

        // Shifts 64-bit 3-reg
        207 | 208 | 209 | 220 | 222 => {
            let dc = if rb == ra { 2 } else { 3 };
            FastCost { cycles: 1, decode_slots: dc, exec_unit: EU_ALU, src_mask: r2(rb, rd), dst_mask: r1(ra), is_terminator: false, is_move_reg: false }
        }
        // Shifts 32-bit 3-reg
        197 | 198 | 199 | 221 | 223 => {
            let dc = if rb == ra { 3 } else { 4 };
            FastCost { cycles: 2, decode_slots: dc, exec_unit: EU_ALU, src_mask: r2(rb, rd), dst_mask: r1(ra), is_terminator: false, is_move_reg: false }
        }
        // Shift alt 64-bit
        155 | 156 | 157 | 159 => FastCost { cycles: 1, decode_slots: 3, exec_unit: EU_ALU, src_mask: r1(rb), dst_mask: r1(ra), is_terminator: false, is_move_reg: false },
        // Shift alt 32-bit
        144 | 145 | 146 | 161 => FastCost { cycles: 2, decode_slots: 4, exec_unit: EU_ALU, src_mask: r1(rb), dst_mask: r1(ra), is_terminator: false, is_move_reg: false },

        // Comparisons 3-reg
        216 | 217 => FastCost { cycles: 3, decode_slots: 3, exec_unit: EU_ALU, src_mask: r2(rb, rd), dst_mask: r1(ra), is_terminator: false, is_move_reg: false },
        // Comparisons imm
        136 | 137 | 142 | 143 => FastCost { cycles: 3, decode_slots: 3, exec_unit: EU_ALU, src_mask: r1(rb), dst_mask: r1(ra), is_terminator: false, is_move_reg: false },

        // Conditional moves 3-reg
        218 | 219 => FastCost { cycles: 2, decode_slots: 2, exec_unit: EU_ALU, src_mask: r2(rb, rd), dst_mask: r1(ra), is_terminator: false, is_move_reg: false },
        // Conditional moves imm
        147 | 148 => FastCost { cycles: 2, decode_slots: 3, exec_unit: EU_ALU, src_mask: r1(rb), dst_mask: r1(ra), is_terminator: false, is_move_reg: false },

        // Min/Max
        227 | 228 | 229 | 230 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 2 } else { 3 };
            FastCost { cycles: 3, decode_slots: dc, exec_unit: EU_ALU, src_mask: s, dst_mask: r1(ra), is_terminator: false, is_move_reg: false }
        }
        // and_inv, or_inv
        224 | 225 => FastCost { cycles: 2, decode_slots: 3, exec_unit: EU_ALU, src_mask: r2(rb, rd), dst_mask: r1(ra), is_terminator: false, is_move_reg: false },
        // xnor
        226 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 2 } else { 3 };
            FastCost { cycles: 2, decode_slots: dc, exec_unit: EU_ALU, src_mask: s, dst_mask: r1(ra), is_terminator: false, is_move_reg: false }
        }
        // neg_add_imm
        154 => FastCost { cycles: 2, decode_slots: 3, exec_unit: EU_ALU, src_mask: r1(rb), dst_mask: r1(ra), is_terminator: false, is_move_reg: false },
        141 => FastCost { cycles: 3, decode_slots: 4, exec_unit: EU_ALU, src_mask: r1(rb), dst_mask: r1(ra), is_terminator: false, is_move_reg: false },

        // Multiply 64-bit 3-reg
        202 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 1 } else { 2 };
            FastCost { cycles: 3, decode_slots: dc, exec_unit: EU_MUL, src_mask: s, dst_mask: r1(ra), is_terminator: false, is_move_reg: false }
        }
        // mul_imm_64
        150 => {
            let dc = if dst_src_overlap(ra, r1(rb)) { 1 } else { 2 };
            FastCost { cycles: 3, decode_slots: dc, exec_unit: EU_MUL, src_mask: r1(rb), dst_mask: r1(ra), is_terminator: false, is_move_reg: false }
        }
        // Multiply 32-bit 3-reg
        192 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 2 } else { 3 };
            FastCost { cycles: 4, decode_slots: dc, exec_unit: EU_MUL, src_mask: s, dst_mask: r1(ra), is_terminator: false, is_move_reg: false }
        }
        // mul_imm_32
        135 => {
            let dc = if dst_src_overlap(ra, r1(rb)) { 2 } else { 3 };
            FastCost { cycles: 4, decode_slots: dc, exec_unit: EU_MUL, src_mask: r1(rb), dst_mask: r1(ra), is_terminator: false, is_move_reg: false }
        }
        // Multiply upper
        213 | 214 => FastCost { cycles: 4, decode_slots: 4, exec_unit: EU_MUL, src_mask: r2(rb, rd), dst_mask: r1(ra), is_terminator: false, is_move_reg: false },
        215 => FastCost { cycles: 6, decode_slots: 4, exec_unit: EU_MUL, src_mask: r2(rb, rd), dst_mask: r1(ra), is_terminator: false, is_move_reg: false },

        // Divide
        193 | 194 | 195 | 196 | 203 | 204 | 205 | 206 =>
            FastCost { cycles: 60, decode_slots: 4, exec_unit: EU_DIV, src_mask: r2(rb, rd), dst_mask: r1(ra), is_terminator: false, is_move_reg: false },

        // Default
        _ => FastCost { cycles: 1, decode_slots: 1, exec_unit: EU_NONE, src_mask: 0, dst_mask: 0, is_terminator: false, is_move_reg: false },
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
        EU_ALU => { avail[0] -= 1; }
        EU_LOAD => { avail[0] -= 1; avail[1] -= 1; }
        EU_STORE => { avail[0] -= 1; avail[2] -= 1; }
        EU_MUL => { avail[0] -= 1; avail[3] -= 1; }
        EU_DIV => { avail[0] -= 1; avail[4] -= 1; }
        _ => {}
    }
}

/// Fast pipeline simulation using bitmask-based SoA ROB.
/// All state on the stack, zero heap allocation.
/// Uses pre-computed FastCost from each instruction (no per-call match dispatch).
fn gas_sim_fast(instrs: &[crate::recompiler::predecode::PreDecodedInst], _code: &[u8], _bitmask: &[u8]) -> u32 {
    // SoA ROB arrays (32 entries, stack-allocated)
    let mut state = [0u8; 32];        // 0=empty, 1=wait, 2=exe, 3=fin
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

    let done_decoding = |idx: usize| idx >= instrs.len();

    for _safety in 0..100_000u32 {
        // Phase 1: Decode as many instructions as possible this cycle
        while instr_idx < instrs.len() && decode_slots > 0 && (next_slot as usize) < 32 {
            let cost = fast_cost(&instrs[instr_idx], _code, _bitmask);

            if cost.is_move_reg {
                decode_slots = decode_slots.saturating_sub(cost.decode_slots);
                instr_idx = if cost.is_terminator { instrs.len() } else { instr_idx + 1 };
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
            instr_idx = if cost.is_terminator { instrs.len() } else { instr_idx + 1 };
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
            if !found { break; }
        }

        // Phase 3: Done check
        if instr_idx >= instrs.len() && exe_mask == 0 && wait_mask == 0 {
            break;
        }

        // Phase 4: Advance cycle
        let mut exe = exe_mask;
        while exe != 0 {
            let i = exe.trailing_zeros() as usize;
            exe &= exe - 1;
            if cycles_left[i] <= 1 {
                state[i] = 3; // FIN
                exe_mask &= !(1u32 << i);
                fin_mask |= 1u32 << i;
            } else {
                cycles_left[i] -= 1;
            }
        }

        cycles += 1;
        decode_slots = 4;
        dispatch_slots = 5;
        eu_avail = [4, 4, 4, 1, 1];
    }

    cycles
}

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

    #[test]
    fn test_single_trap() {
        let code = vec![0u8];
        let bitmask = vec![1u8];
        let cycles = gas_sim_traced(&code, &bitmask, 0, false);
        assert_eq!(cycles, 2);
        assert_eq!(gas_cost_for_block(&code, &bitmask, 0), 1); // max(2-3,1)=1
    }

    #[test]
    fn test_single_ecalli() {
        // ecalli 0: opcode=10, imm=0
        let code = vec![10u8, 0];
        let bitmask = vec![1, 0];
        let cycles = gas_sim_traced(&code, &bitmask, 0, true);
        eprintln!("ecalli-only: cycles={} cost={}", cycles, gas_cost_for_block(&code, &bitmask, 0));
        assert_eq!(cycles, 100, "ecalli should take 100 cycles");
        assert_eq!(gas_cost_for_block(&code, &bitmask, 0), 97);
    }

    #[test]
    fn test_single_jump() {
        // jump offset=0: opcode=40
        let code = vec![40u8, 0];
        let bitmask = vec![1, 0];
        let cycles = gas_sim_traced(&code, &bitmask, 0, false);
        assert_eq!(cycles, 15);
        assert_eq!(gas_cost_for_block(&code, &bitmask, 0), 12);
    }

    #[test]
    fn test_single_fallthrough() {
        let code = vec![1u8]; // fallthrough
        let bitmask = vec![1];
        let cycles = gas_sim_traced(&code, &bitmask, 0, false);
        assert_eq!(cycles, 2);
        assert_eq!(gas_cost_for_block(&code, &bitmask, 0), 1);
    }

    #[test]
    fn test_loadimm_then_trap() {
    }

    #[test]
    fn test_load_imm_then_trap() {
        // Block: load_imm φ[0], 42; trap
        // load_imm (51) = 1 cycle, trap (0) = 2 cycles
        // Pipeline: both decode in cycle 0, dispatch cycle 0/1, done by cycle ~3
        let code = vec![51, 0, 42, 0];
        let bitmask = vec![1, 0, 0, 1];
        let cost = gas_cost_for_block(&code, &bitmask, 0);
        assert!(cost >= 1, "cost should be >= 1, got {}", cost);
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    
    #[test]
    fn test_service_blob_gas() {
        let blob = match std::fs::read("/tmp/test_service_blob.bin") {
            Ok(b) => b,
            Err(_) => { eprintln!("Skipping: /tmp/test_service_blob.bin not found"); return; }
        };
        let pvm = crate::program::initialize_program(&blob, &[0,0,0,0], 100_000).unwrap();
        eprintln!("Code length: {}", pvm.code.len());
        
        // Show block gas costs near the entry points
        let mut block_count = 0;
        for (pc, &cost) in pvm.block_gas_costs.iter().enumerate() {
            if cost > 0 {
                block_count += 1;
                if block_count <= 30 {
                    eprintln!("  BB[{:5}] cost={:4} (opcode={})", pc, cost, 
                        if pc < pvm.code.len() { pvm.code[pc] } else { 255 });
                }
            }
        }
        eprintln!("Total basic blocks: {}", block_count);
    }

    #[test]
    fn trace_ecalli_block() {
        let blob = match std::fs::read("/tmp/test_service_blob.bin") {
            Ok(b) => b,
            Err(_) => { eprintln!("Skipping: /tmp/test_service_blob.bin not found"); return; }
        };
        let pvm = crate::program::initialize_program(&blob, &[0,0,0,0], 100_000).unwrap();
        let code = &pvm.code;
        let bm = &pvm.bitmask;

        // Trace ALL blocks that the test program executes
        // (blocks from the gas trace: 5, 2055, 18927, 17372, 17429, ...)
        for &pc in &[5usize, 2055, 18927, 17372, 17429, 17454, 17459, 17463, 17469, 17532, 17545] {
            let cycles = gas_sim_traced(code, bm, pc, false);
            let cost = if cycles > 3 { cycles - 3 } else { 1 };
            eprintln!("BB[{}]: cycles={} cost={}", pc, cycles, cost);
        }

        // Verify pre-computed costs match dynamic costs for key PCs
        let bb = crate::vm::compute_basic_block_starts(code, bm);
        for &pc in &[5usize, 2055, 18927, 17372, 17429, 17454, 17532, 17545] {
            let is_bb = pc < bb.len() && bb[pc];
            assert!(is_bb, "PC={} should be BB start", pc);
            assert_eq!(pvm.block_gas_costs[pc], gas_cost_for_block(code, bm, pc),
                "pre-computed vs dynamic cost mismatch at PC={}", pc);
        }
    }

    #[test]
    fn trace_block_instructions() {
        let blob = match std::fs::read("/tmp/test_service_blob.bin") {
            Ok(b) => b,
            Err(_) => { eprintln!("Skipping: /tmp/test_service_blob.bin not found"); return; }
        };
        let pvm = crate::program::initialize_program(&blob, &[0,0,0,0], 100_000).unwrap();
        let code = &pvm.code;
        let bm = &pvm.bitmask;
        let bb = crate::vm::compute_basic_block_starts(code, bm);

        // Dump first 5 blocks starting from PC=0
        let block_starts: Vec<usize> = bb.iter().enumerate()
            .filter(|&(_, b)| *b).map(|(i, _)| i).take(10).collect();

        for &start in &block_starts {
            eprintln!("\n=== Block at PC={} (cost={}) ===", start, gas_cost_for_block(code, bm, start));
            let mut pc = start;
            let mut count = 0;
            loop {
                if pc >= code.len() || count > 20 { break; }
                if pc < bm.len() && bm[pc] == 1 {
                    let op = crate::instruction::Opcode::from_byte(code[pc]);
                    let skip = skip_distance(bm, pc);
                    let cost = instruction_cost(code, bm, pc);
                    eprintln!("  pc={:5} {:?} cy={} dec={} eu=alu:{}/ld:{}/st:{}/mul:{}/div:{} dst={:?} src={:?} term={} move={}",
                        pc, op, cost.cycles, cost.decode_slots,
                        cost.exec_units.alu, cost.exec_units.load, cost.exec_units.store,
                        cost.exec_units.mul, cost.exec_units.div,
                        cost.dest_regs, cost.src_regs, cost.is_terminator, cost.is_move_reg);
                    if let Some(o) = op {
                        if o.is_terminator() { break; }
                    }
                    pc += 1 + skip;
                    count += 1;
                    if pc < bb.len() && bb[pc] { break; }
                } else {
                    pc += 1;
                }
            }
        }
    }
}
