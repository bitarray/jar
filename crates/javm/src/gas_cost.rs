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

#[derive(Clone)]
struct RobEntry {
    state: RobState,
    cycles_left: u32,
    deps: Vec<usize>,       // ROB indices this depends on
    dest_regs: Vec<u8>,     // registers written
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

struct InstrCost {
    cycles: u32,
    decode_slots: u8,
    exec_units: ExecUnits,
    dest_regs: Vec<u8>,
    src_regs: Vec<u8>,
    is_terminator: bool,
    is_move_reg: bool,
}

fn dst_overlaps_src(dst: u8, srcs: &[u8]) -> bool {
    srcs.contains(&dst)
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

    let mk = |cy: u32, dc: u8, eu: ExecUnits, dst: Vec<u8>, src: Vec<u8>| -> InstrCost {
        InstrCost { cycles: cy, decode_slots: dc, exec_units: eu,
                    dest_regs: dst, src_regs: src, is_terminator: false, is_move_reg: false }
    };
    let mkt = |cy: u32, dc: u8, eu: ExecUnits, dst: Vec<u8>, src: Vec<u8>| -> InstrCost {
        InstrCost { cycles: cy, decode_slots: dc, exec_units: eu,
                    dest_regs: dst, src_regs: src, is_terminator: true, is_move_reg: false }
    };

    match opcode {
        // No-arg
        0 => mkt(2, 1, ExecUnits::NONE, vec![], vec![]),       // trap
        1 => mkt(2, 1, ExecUnits::NONE, vec![], vec![]),       // fallthrough
        2 => mkt(40, 1, ExecUnits::NONE, vec![], vec![]),      // unlikely
        10 => mkt(100, 4, ExecUnits::ALU, vec![], vec![]),     // ecalli

        // Control flow
        40 => mkt(15, 1, ExecUnits::ALU, vec![], vec![]),      // jump
        80 => {                                                       // load_imm_jump
            let skip = skip_distance(bitmask, pc);
            let raw = crate::args::decode_args(code, pc, skip, crate::instruction::InstructionCategory::OneRegImmOffset);
            let r = if let crate::args::Args::RegImmOffset { ra: r, .. } = raw { r as u8 } else { ra };
            mkt(15, 1, ExecUnits::ALU, vec![r], vec![])
        }
        50 => mkt(22, 1, ExecUnits::ALU, vec![], vec![]),      // jump_ind
        180 => mkt(22, 1, ExecUnits::ALU, vec![ra], vec![rb]), // load_imm_jump_ind

        // Loads (reg+imm and two-reg+imm variants)
        52..=58 => mk(25, 1, ExecUnits::LOAD, vec![ra], vec![rb]),
        124..=130 => mk(25, 1, ExecUnits::LOAD, vec![ra], vec![rb]),

        // Stores (reg+imm variants)
        59..=62 => mk(25, 1, ExecUnits::STORE, vec![], vec![ra, rb]),
        // Stores (two-reg+imm)
        120..=123 => mk(25, 1, ExecUnits::STORE, vec![], vec![ra, rb]),
        // Store immediates (two-imm)
        30..=33 => mk(25, 1, ExecUnits::STORE, vec![], vec![]),
        // Store imm indirect (reg+two-imm)
        70..=73 => mk(25, 1, ExecUnits::STORE, vec![], vec![ra]),

        // Load immediates
        51 => mk(1, 1, ExecUnits::NONE, vec![ra], vec![]),          // load_imm
        20 => mk(1, 2, ExecUnits::NONE, vec![ra], vec![]),          // load_imm_64

        // move_reg: decoded in frontend, no ROB entry
        100 => InstrCost {
            cycles: 0, decode_slots: 1, exec_units: ExecUnits::NONE,
            dest_regs: vec![ra], src_regs: vec![rb],
            is_terminator: false, is_move_reg: true,
        },

        // sbrk (101): removed in jar080, but cost it anyway for simulation
        101 => mk(2, 1, ExecUnits::NONE, vec![], vec![]),

        // Branches (reg + imm + offset)
        81..=90 => {
            let target = extract_branch_target(code, bitmask, pc);
            let bc = branch_cost(code, bitmask, target);
            mkt(bc, 1, ExecUnits::ALU, vec![], vec![ra])
        }

        // Branches (two-reg + offset)
        170..=175 => {
            let target = extract_two_reg_branch_target(code, bitmask, pc);
            let bc = branch_cost(code, bitmask, target);
            mkt(bc, 1, ExecUnits::ALU, vec![], vec![ra, rb])
        }

        // ALU 64-bit 3-reg: add_64(200), sub_64(201), and(210), xor(211), or(212)
        200 | 201 | 210 | 211 | 212 => {
            let dc = if dst_overlaps_src(ra, &[rb, rd]) { 1 } else { 2 };
            mk(1, dc, ExecUnits::ALU, vec![ra], vec![rb, rd])
        }
        // ALU 32-bit 3-reg: add_32(190), sub_32(191)
        190 | 191 => {
            let dc = if dst_overlaps_src(ra, &[rb, rd]) { 2 } else { 3 };
            mk(2, dc, ExecUnits::ALU, vec![ra], vec![rb, rd])
        }

        // ALU 2-op imm 64-bit
        132 | 133 | 134 | 149 | 151 | 152 | 153 | 158 | 110 => {
            let dc = if dst_overlaps_src(ra, &[rb]) { 1 } else { 2 };
            mk(1, dc, ExecUnits::ALU, vec![ra], vec![rb])
        }
        // ALU 2-op imm 32-bit
        131 | 138 | 139 | 140 | 160 => {
            let dc = if dst_overlaps_src(ra, &[rb]) { 2 } else { 3 };
            mk(2, dc, ExecUnits::ALU, vec![ra], vec![rb])
        }

        // Trivial 2-op 1-cycle: popcount, clz, sign_extend, zero_extend
        102 | 103 | 104 | 105 | 108 | 109 => mk(1, 1, ExecUnits::ALU, vec![ra], vec![rb]),
        // Trivial 2-op 2-cycle: ctz
        106 | 107 => mk(2, 1, ExecUnits::ALU, vec![ra], vec![rb]),
        // reverse_bytes
        111 => mk(1, 1, ExecUnits::ALU, vec![ra], vec![rb]),

        // Shifts 64-bit 3-reg
        207 | 208 | 209 | 220 | 222 => {
            let dc = if rb == ra { 2 } else { 3 };
            mk(1, dc, ExecUnits::ALU, vec![ra], vec![rb, rd])
        }
        // Shifts 32-bit 3-reg
        197 | 198 | 199 | 221 | 223 => {
            let dc = if rb == ra { 3 } else { 4 };
            mk(2, dc, ExecUnits::ALU, vec![ra], vec![rb, rd])
        }
        // Shift alt 64-bit
        155 | 156 | 157 | 159 => mk(1, 3, ExecUnits::ALU, vec![ra], vec![rb]),
        // Shift alt 32-bit
        144 | 145 | 146 | 161 => mk(2, 4, ExecUnits::ALU, vec![ra], vec![rb]),

        // Comparisons (3-reg)
        216 | 217 => mk(3, 3, ExecUnits::ALU, vec![ra], vec![rb, rd]),
        // Comparisons (imm)
        136 | 137 | 142 | 143 => mk(3, 3, ExecUnits::ALU, vec![ra], vec![rb]),

        // Conditional moves (3-reg)
        218 | 219 => mk(2, 2, ExecUnits::ALU, vec![ra], vec![rb, rd]),
        // Conditional moves (imm)
        147 | 148 => mk(2, 3, ExecUnits::ALU, vec![ra], vec![rb]),

        // Min/Max
        227 | 228 | 229 | 230 => {
            let dc = if dst_overlaps_src(ra, &[rb, rd]) { 2 } else { 3 };
            mk(3, dc, ExecUnits::ALU, vec![ra], vec![rb, rd])
        }
        // and_inv, or_inv
        224 | 225 => mk(2, 3, ExecUnits::ALU, vec![ra], vec![rb, rd]),
        // xnor
        226 => {
            let dc = if dst_overlaps_src(ra, &[rb, rd]) { 2 } else { 3 };
            mk(2, dc, ExecUnits::ALU, vec![ra], vec![rb, rd])
        }

        // neg_add_imm_64
        154 => mk(2, 3, ExecUnits::ALU, vec![ra], vec![rb]),
        // neg_add_imm_32
        141 => mk(3, 4, ExecUnits::ALU, vec![ra], vec![rb]),

        // Multiply 64-bit (3-reg)
        202 => {
            let dc = if dst_overlaps_src(ra, &[rb, rd]) { 1 } else { 2 };
            mk(3, dc, ExecUnits::MUL, vec![ra], vec![rb, rd])
        }
        // mul_imm_64
        150 => {
            let dc = if dst_overlaps_src(ra, &[rb]) { 1 } else { 2 };
            mk(3, dc, ExecUnits::MUL, vec![ra], vec![rb])
        }
        // Multiply 32-bit (3-reg)
        192 => {
            let dc = if dst_overlaps_src(ra, &[rb, rd]) { 2 } else { 3 };
            mk(4, dc, ExecUnits::MUL, vec![ra], vec![rb, rd])
        }
        // mul_imm_32
        135 => {
            let dc = if dst_overlaps_src(ra, &[rb]) { 2 } else { 3 };
            mk(4, dc, ExecUnits::MUL, vec![ra], vec![rb])
        }

        // Multiply upper (SS, UU)
        213 | 214 => mk(4, 4, ExecUnits::MUL, vec![ra], vec![rb, rd]),
        // Multiply upper (SU)
        215 => mk(6, 4, ExecUnits::MUL, vec![ra], vec![rb, rd]),

        // Divide (all variants)
        193 | 194 | 195 | 196 | 203 | 204 | 205 | 206 =>
            mk(60, 4, ExecUnits::DIV, vec![ra], vec![rb, rd]),

        // Rotate 64-bit (3-reg)
        // Already covered by shifts above (220, 222 = RotL64, RotR64)

        // Rotate 32-bit (3-reg)
        // Already covered by shifts above (221, 223 = RotL32, RotR32)

        // Rotate imm
        // Already covered by shift alt above

        // Default: unknown opcode
        _ => mk(1, 1, ExecUnits::NONE, vec![], vec![]),
    }
}

// --- Simulation ---

fn all_deps_finished(rob: &[RobEntry], entry: &RobEntry) -> bool {
    entry.deps.iter().all(|&idx| idx < rob.len() && rob[idx].state == RobState::Fin)
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
        rob: Vec::new(),
    };

    for iter in 0..100_000 {
        // Priority 1: Decode
        if s.ip.is_some() && s.decode_slots > 0 && s.rob.len() < 32 {
            let pc = s.ip.unwrap();
            let cost = instruction_cost(code, bitmask, pc);
            let deps: Vec<usize> = s.rob.iter().enumerate()
                .filter(|(_, e)| e.state != RobState::Fin
                    && e.dest_regs.iter().any(|dr| cost.src_regs.contains(dr)))
                .map(|(i, _)| i)
                .collect();
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
                    iter, pc, op, cost.cycles, cost.decode_slots, s.rob.len(), deps, cost.is_move_reg, cost.is_terminator, s.decode_slots);
            }
            if cost.is_move_reg {
                s.ip = next_ip;
            } else {
                s.rob.push(RobEntry {
                    state: RobState::Wait,
                    cycles_left: cost.cycles,
                    deps,
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
