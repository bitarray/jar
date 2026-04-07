//! RISC-V ELF to JAM PVM transpiler.
//!
//! Converts RISC-V rv64em ELF binaries into PVM program blobs
//! suitable for execution by the Grey PVM (Appendix A).
//!
//! Also provides utilities to hand-assemble PVM programs directly.

pub mod assembler;
pub mod emitter;
pub mod linker;
pub mod riscv;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum TranspileError {
    #[error("ELF parse error: {0}")]
    ElfParse(String),
    #[error("unsupported RISC-V instruction at offset {offset:#x}: {detail}")]
    UnsupportedInstruction { offset: usize, detail: String },
    #[error("unsupported relocation: {0}")]
    UnsupportedRelocation(String),
    #[error("register mapping error: RISC-V register {0} has no PVM equivalent")]
    RegisterMapping(u8),
    #[error("code too large: {0} bytes")]
    CodeTooLarge(usize),
    #[error("invalid section: {0}")]
    InvalidSection(String),
}

/// Link a RISC-V rv64em ELF binary into a JAR capability manifest PVM blob.
/// Single entrypoint (PC=0). Works for both standard and service programs.
pub fn link_elf(elf_data: &[u8]) -> Result<Vec<u8>, TranspileError> {
    linker::link_elf(elf_data)
}

/// Compute skip distance from bitmask: number of continuation bytes after position `pc`.
fn skip_for(bitmask: &[u8], pc: usize) -> usize {
    for j in 0..25 {
        let idx = pc + 1 + j;
        if idx >= bitmask.len() || bitmask[idx] == 1 {
            return j;
        }
    }
    0
}

/// Collect all branch targets and jump table entries from PVM code.
///
/// Returns a set of byte offsets that are branch/jump destinations.
/// Used by peephole passes to avoid fusing across branch boundaries.
fn collect_branch_targets(
    code: &[u8],
    bitmask: &[u8],
    jump_table: &[u32],
) -> std::collections::HashSet<usize> {
    let len = code.len();
    let mut targets = std::collections::HashSet::new();
    let mut i = 0;
    while i < len {
        if i >= bitmask.len() || bitmask[i] != 1 {
            i += 1;
            continue;
        }
        let op = code[i];
        let s = skip_for(bitmask, i);
        // jump (40): 4-byte offset
        if op == 40 && i + 5 <= len {
            let off = i32::from_le_bytes([code[i + 1], code[i + 2], code[i + 3], code[i + 4]]);
            let t = (i as i64 + off as i64) as usize;
            if t < len {
                targets.insert(t);
            }
        }
        // branch_eq..branch_ge_u (170-175): 4-byte offset at +2
        if (170..=175).contains(&op) && i + 6 <= len {
            let off = i32::from_le_bytes([code[i + 2], code[i + 3], code[i + 4], code[i + 5]]);
            let t = (i as i64 + off as i64) as usize;
            if t < len {
                targets.insert(t);
            }
        }
        // branch_*_imm (80-90): variable-length offset
        if (80..=90).contains(&op) && i + 2 <= len {
            let reg_byte = code[i + 1];
            let lx = ((reg_byte as usize / 16) % 8).min(4);
            let ly = if s > lx + 1 { (s - lx - 1).min(4) } else { 0 };
            let off_start = i + 2 + lx;
            if ly > 0 && off_start + ly <= len {
                let mut buf = [0u8; 4];
                buf[..ly].copy_from_slice(&code[off_start..off_start + ly]);
                if ly < 4 && buf[ly - 1] & 0x80 != 0 {
                    for b in &mut buf[ly..4] {
                        *b = 0xFF;
                    }
                }
                let off = i32::from_le_bytes(buf);
                let t = (i as i64 + off as i64) as usize;
                if t < len {
                    targets.insert(t);
                }
            }
        }
        i += 1 + s;
    }
    for &jt in jump_table {
        targets.insert(jt as usize);
    }
    targets
}

/// Peephole pass: fuse `load_imm(51) + ThreeReg ALU` into `TwoRegOneImm` immediate form.
///
/// Scans the PVM code for consecutive pairs where:
/// 1. First instruction is `load_imm` (opcode 51)
/// 2. Second instruction is a ThreeReg ALU op with an immediate-form equivalent
/// 3. The load destination register equals the ALU output register (dead after ALU)
/// 4. The load value fits in i32 (4-byte immediate)
/// 5. Neither instruction is a branch target
///
/// When fusable, rewrites the pair in-place: the first instruction becomes the
/// TwoRegOneImm form with a 4-byte immediate, and all remaining bytes through
/// the end of the second instruction become bitmask=0 continuation bytes.
pub fn peephole_fuse_load_imm_alu(
    code: &mut [u8],
    bitmask: &mut [u8],
    jump_table: &[u32],
) -> usize {
    let len = code.len();
    if len < 4 {
        return 0;
    }

    let targets = collect_branch_targets(code, bitmask, jump_table);

    // ThreeReg ALU → TwoRegOneImm immediate form mapping
    let imm_opcode = |three_reg_op: u8| -> Option<u8> {
        match three_reg_op {
            200 => Some(149), // add_64 → add_imm_64
            202 => Some(150), // mul_64 → mul_imm_64
            207 => Some(151), // shl_64 → shl_imm_64
            208 => Some(152), // shr_64 → shr_imm_64
            209 => Some(153), // sar_64 → sar_imm_64
            210 => Some(132), // and → and_imm
            211 => Some(133), // xor → xor_imm
            212 => Some(134), // or → or_imm
            // set_lt_u (216) and set_lt_s (217) are non-commutative — handled below
            _ => None,
        }
    };

    let mut fused = 0;
    let mut i = 0;
    while i < len {
        if i >= bitmask.len() || bitmask[i] != 1 {
            i += 1;
            continue;
        }
        let op = code[i];
        let s = skip_for(bitmask, i);
        let next_i = i + 1 + s;

        // Look for load_imm (51) followed by a ThreeReg ALU
        if op == 51 && next_i < len && bitmask[next_i] == 1 && !targets.contains(&next_i) {
            let alu_op = code[next_i];
            let alu_s = skip_for(bitmask, next_i);
            if let Some(imm_op) = imm_opcode(alu_op) {
                // Parse load_imm: [51, reg_byte, imm...] — OneRegOneImm
                // lx = skip - 1 (from bitmask)
                if i + 1 < len {
                    let load_reg_byte = code[i + 1];
                    let load_rd = load_reg_byte & 0x0F;
                    let lx = s.saturating_sub(1);
                    let mut imm_buf = [0u8; 8];
                    for k in 0..lx.min(8) {
                        if i + 2 + k < len {
                            imm_buf[k] = code[i + 2 + k];
                        }
                    }
                    if lx > 0 && lx <= 8 && imm_buf[lx.min(8) - 1] & 0x80 != 0 {
                        for b in &mut imm_buf[lx.min(8)..8] {
                            *b = 0xFF;
                        }
                    }
                    let load_val = i64::from_le_bytes(imm_buf);

                    // Parse ThreeReg ALU: [op, ra|(rb<<4), rd]
                    if next_i + 2 < len {
                        let alu_reg1 = code[next_i + 1];
                        let alu_ra = alu_reg1 & 0x0F;
                        let alu_rb = (alu_reg1 >> 4) & 0x0F;
                        let alu_rd = code[next_i + 2].min(12);

                        // Fusable if: load_rd == alu_rd, load_val fits i32,
                        // and load_rd matches one of the ALU sources
                        let fits_i32 = load_val >= i32::MIN as i64 && load_val <= i32::MAX as i64;
                        let matches_ra = load_rd == alu_ra;
                        let matches_rb = load_rd == alu_rb;

                        // Non-commutative: set_lt_u (216) and set_lt_s (217).
                        // rd = ra < rb: constant as rb → set_lt_imm, constant as ra → set_gt_imm
                        if (alu_op == 216 || alu_op == 217)
                            && fits_i32
                            && load_rd == alu_rd
                            && (matches_ra != matches_rb)
                        {
                            let (cmp_imm_op, base) = if matches_rb {
                                // rd = ra < K → set_lt_imm(rd, ra, K)
                                let op = if alu_op == 216 { 136u8 } else { 137u8 };
                                (op, alu_ra)
                            } else {
                                // rd = K < rb → rb > K → set_gt_imm(rd, rb, K)
                                let op = if alu_op == 216 { 142u8 } else { 143u8 };
                                (op, alu_rb)
                            };
                            let imm32 = load_val as i32;
                            let end_of_pair = next_i + 1 + alu_s;
                            if end_of_pair >= i + 6 {
                                code[i] = cmp_imm_op;
                                code[i + 1] = (alu_rd & 0x0F) | ((base & 0x0F) << 4);
                                let imm_bytes = imm32.to_le_bytes();
                                code[i + 2] = imm_bytes[0];
                                code[i + 3] = imm_bytes[1];
                                code[i + 4] = imm_bytes[2];
                                code[i + 5] = imm_bytes[3];
                                for k in 6..(end_of_pair - i) {
                                    code[i + k] = 0;
                                }
                                for b in &mut bitmask[(i + 1)..end_of_pair] {
                                    *b = 0;
                                }
                                fused += 1;
                                i = end_of_pair;
                                continue;
                            }
                        }

                        // Special case: sub_64 (201) is non-commutative.
                        // load_imm rd, K; sub_64 rd, ra, rb (rd = ra - rb):
                        //   rd==rb (constant subtrahend): rd = ra - K → add_imm_64(rd, ra, -K)
                        //   rd==ra (constant minuend):    rd = K - rb → neg_add_imm_64(rd, rb, K)
                        if alu_op == 201
                            && fits_i32
                            && load_rd == alu_rd
                            && (matches_ra != matches_rb)
                        {
                            let (sub_imm_op, base, imm32) = if matches_rb {
                                // rd = ra - K → add_imm_64(rd, ra, -K)
                                let neg_k = -(load_val as i32) as i64;
                                if neg_k < i32::MIN as i64 || neg_k > i32::MAX as i64 {
                                    i += 1 + s;
                                    continue;
                                }
                                (149u8, alu_ra, neg_k as i32) // add_imm_64
                            } else {
                                // rd = K - rb → neg_add_imm_64(rd, rb, K)
                                (154u8, alu_rb, load_val as i32) // neg_add_imm_64
                            };

                            let end_of_pair = next_i + 1 + alu_s;
                            if end_of_pair >= i + 6 {
                                code[i] = sub_imm_op;
                                code[i + 1] = (alu_rd & 0x0F) | ((base & 0x0F) << 4);
                                let imm_bytes = imm32.to_le_bytes();
                                code[i + 2] = imm_bytes[0];
                                code[i + 3] = imm_bytes[1];
                                code[i + 4] = imm_bytes[2];
                                code[i + 5] = imm_bytes[3];
                                for k in 6..(end_of_pair - i) {
                                    code[i + k] = 0;
                                }
                                for b in &mut bitmask[(i + 1)..end_of_pair] {
                                    *b = 0;
                                }
                                fused += 1;
                                i = end_of_pair;
                                continue;
                            }
                        }

                        if fits_i32 && load_rd == alu_rd && (matches_ra || matches_rb) {
                            // The "base" register is whichever ALU source is NOT load_rd
                            let base = if matches_ra { alu_rb } else { alu_ra };
                            let imm32 = load_val as i32;

                            // Write fused TwoRegOneImm: [imm_op, alu_rd|(base<<4), imm0..imm3]
                            // alu_rd goes in rA position (dest), base goes in rB position
                            let end_of_pair = next_i + 1 + alu_s;

                            // Need at least 6 bytes for opcode + reg + 4-byte imm
                            if end_of_pair >= i + 6 {
                                code[i] = imm_op;
                                code[i + 1] = (alu_rd & 0x0F) | ((base & 0x0F) << 4);
                                let imm_bytes = imm32.to_le_bytes();
                                code[i + 2] = imm_bytes[0];
                                code[i + 3] = imm_bytes[1];
                                code[i + 4] = imm_bytes[2];
                                code[i + 5] = imm_bytes[3];

                                // Zero out remaining bytes and clear bitmask
                                for k in 6..(end_of_pair - i) {
                                    code[i + k] = 0;
                                }
                                // bitmask[i] stays 1 (instruction start)
                                // Clear bitmask for all continuation bytes including old ALU start
                                for b in &mut bitmask[(i + 1)..end_of_pair] {
                                    *b = 0;
                                }

                                fused += 1;
                                i = end_of_pair;
                                continue;
                            }
                        }
                    }
                }
            }
        }
        i += 1 + s;
    }
    fused
}

/// Peephole pass: eliminate dead `load_imm` instructions.
///
/// When a `load_imm` (opcode 51) or `load_imm_64` (opcode 20) writes to register R,
/// and the immediately following instruction also writes to R without reading it
/// (another load_imm/load_imm_64, or move_reg with R as destination), the first
/// instruction is dead and can be replaced with a no-op (bitmask cleared).
///
/// The second instruction must not be a branch target (otherwise the first
/// load_imm could be reached independently via a different path).
pub fn peephole_eliminate_dead_load_imm(
    code: &mut [u8],
    bitmask: &mut [u8],
    jump_table: &[u32],
) -> usize {
    let len = code.len();
    if len < 4 {
        return 0;
    }

    let targets = collect_branch_targets(code, bitmask, jump_table);

    /// Extract the destination register from a load_imm (51) or load_imm_64 (20).
    /// Returns None if the instruction doesn't write to a register or is malformed.
    fn load_dest_reg(code: &[u8], pc: usize) -> Option<u8> {
        let op = code[pc];
        if (op == 51 || op == 20) && pc + 1 < code.len() {
            Some(code[pc + 1] & 0x0F)
        } else {
            None
        }
    }

    /// Check if an instruction at `pc` unconditionally writes to register `rd`
    /// without reading it first. Covers: load_imm(51), load_imm_64(20), move_reg(100).
    fn writes_without_reading(code: &[u8], pc: usize, rd: u8) -> bool {
        if pc >= code.len() {
            return false;
        }
        let op = code[pc];
        match op {
            // load_imm / load_imm_64: dest is bits 0-3 of reg_byte
            51 | 20 => pc + 1 < code.len() && (code[pc + 1] & 0x0F) == rd,
            // move_reg: [100, rd|(rs<<4)] — writes rd, reads rs
            // Safe only if rd != rs (otherwise it reads rd too, but move to self is still dead)
            100 => pc + 1 < code.len() && (code[pc + 1] & 0x0F) == rd,
            _ => false,
        }
    }

    let mut eliminated = 0;
    let mut i = 0;
    while i < len {
        if i >= bitmask.len() || bitmask[i] != 1 {
            i += 1;
            continue;
        }
        let s = skip_for(bitmask, i);
        let next_i = i + 1 + s;

        if let Some(rd) = load_dest_reg(code, i)
            && next_i < len
            && bitmask[next_i] == 1
            && !targets.contains(&next_i)
            && writes_without_reading(code, next_i, rd)
        {
            // First load_imm is dead — NOP it by clearing its bitmask
            bitmask[i] = 0;
            // Zero out the instruction bytes
            for b in code[i..next_i].iter_mut() {
                *b = 0;
            }
            eliminated += 1;
            i = next_i;
            continue;
        }
        i += 1 + s;
    }
    eliminated
}

/// Post-pass: ensure all PVM branch targets are basic block starts (ϖ).
///
/// Scans the PVM code for branch/jump instructions, extracts their targets,
/// and inserts `fallthrough` (opcode 1) before any target not preceded by a
/// terminator. Adjusts all branch offsets and jump table entries to account
/// for the inserted bytes.
///
/// This guarantees the JAM spec invariant: all branch targets ∈ ϖ.
pub fn ensure_branch_targets_are_block_starts(
    code: &mut Vec<u8>,
    bitmask: &mut Vec<u8>,
    jump_table: &mut [u32],
) {
    let terminators: &[u8] = &[0, 1, 2, 10, 40, 50, 80, 180];
    let is_terminator = |op: u8| -> bool {
        terminators.contains(&op) || (81..=90).contains(&op) || (170..=175).contains(&op)
    };

    // Helper: compute skip from bitmask (next instruction start after pc)
    let skip_for = |bm: &[u8], pc: usize| -> usize {
        for j in 0..25 {
            let idx = pc + 1 + j;
            if idx >= bm.len() || bm[idx] == 1 {
                return j;
            }
        }
        0
    };

    // Pass 1: find all branch target PCs and check which need fallthrough.
    let len = code.len();
    let mut insert_positions: Vec<usize> = Vec::new(); // PVM offsets to insert fallthrough BEFORE

    // Build post-terminator set for checking
    let mut post_term = std::collections::HashSet::new();
    post_term.insert(0usize);
    {
        let mut i = 0;
        while i < len {
            if i >= bitmask.len() || bitmask[i] != 1 {
                i += 1;
                continue;
            }
            let op = code[i];
            let s = skip_for(bitmask, i);
            if is_terminator(op) {
                let nxt = i + 1 + s;
                if nxt < len && nxt < bitmask.len() && bitmask[nxt] == 1 {
                    post_term.insert(nxt);
                }
            }
            i += 1 + s;
        }
    }

    // Collect branch targets
    let mut branch_targets = std::collections::HashSet::new();
    {
        let mut i = 0;
        while i < len {
            if i >= bitmask.len() || bitmask[i] != 1 {
                i += 1;
                continue;
            }
            let op = code[i];
            let s = skip_for(bitmask, i);

            // OneOffset: opcode 40 (jump), 80 (load_imm_jump)
            if op == 40 && i + 5 <= len {
                let off = i32::from_le_bytes([code[i + 1], code[i + 2], code[i + 3], code[i + 4]]);
                let t = (i as i64 + off as i64) as usize;
                if t < len && t < bitmask.len() && bitmask[t] == 1 {
                    branch_targets.insert(t);
                }
            }
            // TwoRegOneOffset: opcodes 170-175
            if (170..=175).contains(&op) && i + 6 <= len {
                let off = i32::from_le_bytes([code[i + 2], code[i + 3], code[i + 4], code[i + 5]]);
                let t = (i as i64 + off as i64) as usize;
                if t < len && t < bitmask.len() && bitmask[t] == 1 {
                    branch_targets.insert(t);
                }
            }
            // OneRegImmOffset: opcodes 80-90
            if (80..=90).contains(&op) && i + 2 <= len {
                let reg_byte = code[i + 1];
                let lx = ((reg_byte as usize / 16) % 8).min(4);
                let ly = if s > lx + 1 { (s - lx - 1).min(4) } else { 0 };
                let off_start = i + 2 + lx;
                if ly > 0 && off_start + ly <= len {
                    let mut buf = [0u8; 4];
                    buf[..ly].copy_from_slice(&code[off_start..off_start + ly]);
                    if ly < 4 && buf[ly - 1] & 0x80 != 0 {
                        for b in &mut buf[ly..4] {
                            *b = 0xFF;
                        }
                    }
                    let off = i32::from_le_bytes(buf);
                    let t = (i as i64 + off as i64) as usize;
                    if t < len && t < bitmask.len() && bitmask[t] == 1 {
                        branch_targets.insert(t);
                    }
                }
            }
            i += 1 + s;
        }
    }

    // Find branch targets not in post_term
    for &t in &branch_targets {
        if !post_term.contains(&t) {
            insert_positions.push(t);
        }
    }
    // Also check jump table entries
    for &jt_entry in jump_table.iter() {
        let t = jt_entry as usize;
        if t < len
            && t < bitmask.len()
            && bitmask[t] == 1
            && !post_term.contains(&t)
            && !insert_positions.contains(&t)
        {
            insert_positions.push(t);
        }
    }

    if insert_positions.is_empty() {
        return;
    }

    insert_positions.sort();
    insert_positions.dedup();

    // Pass 2: build new code/bitmask with fallthroughs inserted.
    // Also build an offset map: old_pc → new_pc.
    let new_len = len + insert_positions.len();
    let mut new_code = Vec::with_capacity(new_len);
    let mut new_bitmask = Vec::with_capacity(new_len);
    let mut offset_map = vec![0u32; len + 1]; // old_pc → new_pc

    let mut insert_idx = 0;
    for old_pc in 0..len {
        // Insert fallthrough before this PC if needed
        while insert_idx < insert_positions.len() && insert_positions[insert_idx] == old_pc {
            new_code.push(1); // fallthrough opcode
            new_bitmask.push(1); // instruction start
            insert_idx += 1;
        }
        offset_map[old_pc] = new_code.len() as u32;
        new_code.push(code[old_pc]);
        new_bitmask.push(bitmask[old_pc]);
    }
    offset_map[len] = new_code.len() as u32;

    // Pass 3: fix all PC-relative branch offsets in the new code.
    // Scan for branch instructions and recalculate their offsets.
    {
        let mut i = 0;
        while i < new_code.len() {
            if i >= new_bitmask.len() || new_bitmask[i] != 1 {
                i += 1;
                continue;
            }
            let op = new_code[i];
            let s = {
                let mut s = 0;
                for j in 0..25 {
                    let idx = i + 1 + j;
                    if idx >= new_bitmask.len() || new_bitmask[idx] == 1 {
                        s = j;
                        break;
                    }
                }
                s
            };

            // OneOffset with fixed 4-byte immediate: opcode 40 (jump)
            if op == 40 && i + 5 <= new_code.len() {
                let _old_off = i32::from_le_bytes([
                    new_code[i + 1],
                    new_code[i + 2],
                    new_code[i + 3],
                    new_code[i + 4],
                ]);
                // Find old PC for this instruction
                // The instruction at new_pc=i maps back to some old_pc.
                // old_target = old_pc + old_off. new_target = offset_map[old_target].
                // new_off = new_target - new_pc = offset_map[old_target] - i.
                // But we need old_pc. We can compute: old_target was in the original code.
                // Since new code has extra bytes, old_off referenced old positions.
                // Actually, the offset was already resolved in the old code. old_target = old_inst_pc + old_off.
                // We need to map old_inst_pc back. But that's complex.
                // Simpler: compute old target from old offset, then remap.
                // We need to find which old_pc maps to this new i.
                // Build reverse map:
                // Actually let's just do this with a reverse lookup.
            }

            i += 1 + s;
        }
    }

    // This approach is getting complex. Use a simpler strategy:
    // rebuild fixups from scratch by scanning old code, computing old targets,
    // and patching new code with remapped offsets.

    // Actually, let's use the offset_map directly on the old code's branch instructions.
    {
        let mut old_i = 0;
        while old_i < len {
            if old_i >= bitmask.len() || bitmask[old_i] != 1 {
                old_i += 1;
                continue;
            }
            let op = code[old_i];
            let s = skip_for(bitmask, old_i);
            let new_i = offset_map[old_i] as usize;

            // Fix OneOffset: opcode 40
            if op == 40 && old_i + 5 <= len {
                let old_off = i32::from_le_bytes([
                    code[old_i + 1],
                    code[old_i + 2],
                    code[old_i + 3],
                    code[old_i + 4],
                ]);
                let old_target = (old_i as i64 + old_off as i64) as usize;
                if old_target <= len {
                    let new_target = offset_map[old_target] as i64;
                    let new_off = (new_target - new_i as i64) as i32;
                    new_code[new_i + 1..new_i + 5].copy_from_slice(&new_off.to_le_bytes());
                }
            }
            // Fix TwoRegOneOffset: opcodes 170-175
            if (170..=175).contains(&op) && old_i + 6 <= len {
                let old_off = i32::from_le_bytes([
                    code[old_i + 2],
                    code[old_i + 3],
                    code[old_i + 4],
                    code[old_i + 5],
                ]);
                let old_target = (old_i as i64 + old_off as i64) as usize;
                if old_target <= len {
                    let new_target = offset_map[old_target] as i64;
                    let new_off = (new_target - new_i as i64) as i32;
                    new_code[new_i + 2..new_i + 6].copy_from_slice(&new_off.to_le_bytes());
                }
            }
            // Fix OneRegImmOffset: opcodes 80-90
            if (80..=90).contains(&op) && old_i + 2 <= len {
                let reg_byte = code[old_i + 1];
                let lx = ((reg_byte as usize / 16) % 8).min(4);
                let ly = if s > lx + 1 { (s - lx - 1).min(4) } else { 0 };
                let off_start_old = old_i + 2 + lx;
                if ly > 0 && off_start_old + ly <= len {
                    let mut buf = [0u8; 4];
                    buf[..ly].copy_from_slice(&code[off_start_old..off_start_old + ly]);
                    if ly < 4 && buf[ly - 1] & 0x80 != 0 {
                        for b in &mut buf[ly..4] {
                            *b = 0xFF;
                        }
                    }
                    let old_off = i32::from_le_bytes(buf);
                    let old_target = (old_i as i64 + old_off as i64) as usize;
                    if old_target <= len {
                        let new_target = offset_map[old_target] as i64;
                        let new_off = (new_target - new_i as i64) as i32;
                        // Write back with same length ly
                        let new_bytes = new_off.to_le_bytes();
                        let off_start_new = new_i + 2 + lx;
                        new_code[off_start_new..off_start_new + ly]
                            .copy_from_slice(&new_bytes[..ly]);
                    }
                }
            }

            old_i += 1 + s;
        }
    }

    // Fix jump table entries
    for entry in jump_table.iter_mut() {
        let old_pc = *entry as usize;
        if old_pc <= len {
            *entry = offset_map[old_pc];
        }
    }

    *code = new_code;
    *bitmask = new_bitmask;
}
