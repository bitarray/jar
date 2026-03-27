//! RISC-V ELF to JAM PVM transpiler.
//!
//! Converts RISC-V rv64em ELF binaries into PVM program blobs
//! suitable for execution by the Grey PVM (Appendix A).
//!
//! Also provides utilities to hand-assemble PVM programs directly.

pub mod riscv;
pub mod emitter;
pub mod assembler;
pub mod linker;

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

/// Link a RISC-V rv64em ELF binary into a PVM standard program blob.
pub fn link_elf(elf_data: &[u8]) -> Result<Vec<u8>, TranspileError> {
    linker::link_elf(elf_data)
}

/// Link a RISC-V rv64em ELF binary into a JAM service PVM blob.
pub fn link_elf_service(elf_data: &[u8]) -> Result<Vec<u8>, TranspileError> {
    linker::link_elf_service(elf_data)
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
    jump_table: &mut Vec<u32>,
) {
    let terminators: &[u8] = &[0, 1, 2, 10, 40, 50, 80, 180];
    let is_terminator = |op: u8| -> bool {
        terminators.contains(&op) || (81..=90).contains(&op) || (170..=175).contains(&op)
    };

    // Helper: compute skip from bitmask (next instruction start after pc)
    let skip_for = |bm: &[u8], pc: usize| -> usize {
        for j in 0..25 {
            let idx = pc + 1 + j;
            if idx >= bm.len() || bm[idx] == 1 { return j; }
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
            if i >= bitmask.len() || bitmask[i] != 1 { i += 1; continue; }
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
            if i >= bitmask.len() || bitmask[i] != 1 { i += 1; continue; }
            let op = code[i];
            let s = skip_for(bitmask, i);

            // OneOffset: opcode 40 (jump), 80 (load_imm_jump)
            if op == 40 && i + 5 <= len {
                let off = i32::from_le_bytes([code[i+1], code[i+2], code[i+3], code[i+4]]);
                let t = (i as i64 + off as i64) as usize;
                if t < len && t < bitmask.len() && bitmask[t] == 1 {
                    branch_targets.insert(t);
                }
            }
            // TwoRegOneOffset: opcodes 170-175
            if (170..=175).contains(&op) && i + 6 <= len {
                let off = i32::from_le_bytes([code[i+2], code[i+3], code[i+4], code[i+5]]);
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
                        for b in &mut buf[ly..4] { *b = 0xFF; }
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
        if t < len && t < bitmask.len() && bitmask[t] == 1 && !post_term.contains(&t) {
            if !insert_positions.contains(&t) {
                insert_positions.push(t);
            }
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
            if i >= new_bitmask.len() || new_bitmask[i] != 1 { i += 1; continue; }
            let op = new_code[i];
            let s = {
                let mut s = 0;
                for j in 0..25 {
                    let idx = i + 1 + j;
                    if idx >= new_bitmask.len() || new_bitmask[idx] == 1 { s = j; break; }
                }
                s
            };

            // OneOffset with fixed 4-byte immediate: opcode 40 (jump)
            if op == 40 && i + 5 <= new_code.len() {
                let old_off = i32::from_le_bytes([new_code[i+1], new_code[i+2], new_code[i+3], new_code[i+4]]);
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
            if old_i >= bitmask.len() || bitmask[old_i] != 1 { old_i += 1; continue; }
            let op = code[old_i];
            let s = skip_for(bitmask, old_i);
            let new_i = offset_map[old_i] as usize;

            // Fix OneOffset: opcode 40
            if op == 40 && old_i + 5 <= len {
                let old_off = i32::from_le_bytes([code[old_i+1], code[old_i+2], code[old_i+3], code[old_i+4]]);
                let old_target = (old_i as i64 + old_off as i64) as usize;
                if old_target <= len {
                    let new_target = offset_map[old_target] as i64;
                    let new_off = (new_target - new_i as i64) as i32;
                    new_code[new_i+1..new_i+5].copy_from_slice(&new_off.to_le_bytes());
                }
            }
            // Fix TwoRegOneOffset: opcodes 170-175
            if (170..=175).contains(&op) && old_i + 6 <= len {
                let old_off = i32::from_le_bytes([code[old_i+2], code[old_i+3], code[old_i+4], code[old_i+5]]);
                let old_target = (old_i as i64 + old_off as i64) as usize;
                if old_target <= len {
                    let new_target = offset_map[old_target] as i64;
                    let new_off = (new_target - new_i as i64) as i32;
                    new_code[new_i+2..new_i+6].copy_from_slice(&new_off.to_le_bytes());
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
                        for b in &mut buf[ly..4] { *b = 0xFF; }
                    }
                    let old_off = i32::from_le_bytes(buf);
                    let old_target = (old_i as i64 + old_off as i64) as usize;
                    if old_target <= len {
                        let new_target = offset_map[old_target] as i64;
                        let new_off = (new_target - new_i as i64) as i32;
                        // Write back with same length ly
                        let new_bytes = new_off.to_le_bytes();
                        let off_start_new = new_i + 2 + lx;
                        for k in 0..ly {
                            new_code[off_start_new + k] = new_bytes[k];
                        }
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
