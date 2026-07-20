//! Offline RISC-V oracle: run a [`Program`] on the golden model (Spike) and
//! read back its final register file as the [`crate::SIG_BYTES`]-byte signature.
//! Used by the `mint` binary to produce committed golden vectors — **never** a
//! build/CI dependency (CI replays the committed vectors, it does not run Spike).
//!
//! We drive `spike -d` with a command file (no ELF symbols, no HTIF): materialize
//! the initial registers, run to the end of the **body** (the signature epilogue
//! is excluded — it stores to `SIG_BASE`, which is below Spike's DRAM; Spike
//! reads the registers directly instead), then print each captured register. The
//! materialization + body is loaded as the single segment of a hand-emitted ELF
//! (no external assembler/linker needed — we already have the instruction
//! words). The model runs as the RV64I superset; the generator never names
//! x16–x31, so the extra registers are irrelevant.

use crate::Program;
use crate::encode::{SIG_BYTES, SIG_REGS, SIG_XREGS};
use std::io::Write;
use std::process::Command;

/// Spike's default DRAM base — the program loads here.
const LOAD: u64 = 0x8000_0000;
/// ISA string (RV64I superset of PVM2's compute core).
pub const SPIKE_ISA: &str = "rv64imc_zba_zbb_zbs_zicond";

/// Slot index (0..=12) → RV x-register number (inverse of `reg_slot_or_ff`).
pub fn slot_to_xreg(slot: u8) -> u8 {
    const X: [u8; 13] = [1, 2, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    X[slot as usize]
}

/// Append one `Elf64_Shdr` (64 bytes).
#[allow(clippy::too_many_arguments)]
fn shdr(
    v: &mut Vec<u8>,
    name: u32,
    typ: u32,
    flags: u64,
    addr: u64,
    off: u64,
    size: u64,
    align: u64,
) {
    v.extend_from_slice(&name.to_le_bytes());
    v.extend_from_slice(&typ.to_le_bytes());
    v.extend_from_slice(&flags.to_le_bytes());
    v.extend_from_slice(&addr.to_le_bytes());
    v.extend_from_slice(&off.to_le_bytes());
    v.extend_from_slice(&size.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes()); // sh_link
    v.extend_from_slice(&0u32.to_le_bytes()); // sh_info
    v.extend_from_slice(&align.to_le_bytes());
    v.extend_from_slice(&0u64.to_le_bytes()); // sh_entsize
}

/// Build a static RV64 ELF: one `PT_LOAD` (R+X) segment holding `code` at
/// [`LOAD`] (entry = [`LOAD`]), plus the minimal section headers Spike's
/// elfloader requires (NULL, `.text`, `.shstrtab` — it asserts
/// `e_shstrndx < e_shnum`).
fn build_elf(code: &[u8]) -> Vec<u8> {
    const EH: u64 = 64; // ELF header
    const PH: u64 = 56; // program header
    let code_off = EH + PH; // 120
    let strtab: &[u8] = b"\0.text\0.shstrtab\0"; // names: .text@1, .shstrtab@7
    let strtab_off = code_off + code.len() as u64;
    let shoff = strtab_off + strtab.len() as u64;

    let mut v = Vec::new();
    // -- Elf64_Ehdr --
    v.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]); // magic, 64-bit, LE, v1, SysV
    v.extend_from_slice(&[0u8; 8]); // e_ident padding
    v.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
    v.extend_from_slice(&243u16.to_le_bytes()); // e_machine = EM_RISCV
    v.extend_from_slice(&1u32.to_le_bytes()); // e_version
    v.extend_from_slice(&LOAD.to_le_bytes()); // e_entry
    v.extend_from_slice(&EH.to_le_bytes()); // e_phoff
    v.extend_from_slice(&shoff.to_le_bytes()); // e_shoff
    v.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    v.extend_from_slice(&(EH as u16).to_le_bytes()); // e_ehsize
    v.extend_from_slice(&(PH as u16).to_le_bytes()); // e_phentsize
    v.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    v.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
    v.extend_from_slice(&3u16.to_le_bytes()); // e_shnum
    v.extend_from_slice(&2u16.to_le_bytes()); // e_shstrndx → .shstrtab

    // -- Elf64_Phdr --
    v.extend_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
    v.extend_from_slice(&5u32.to_le_bytes()); // p_flags = R | X
    v.extend_from_slice(&code_off.to_le_bytes()); // p_offset
    v.extend_from_slice(&LOAD.to_le_bytes()); // p_vaddr
    v.extend_from_slice(&LOAD.to_le_bytes()); // p_paddr
    v.extend_from_slice(&(code.len() as u64).to_le_bytes()); // p_filesz
    v.extend_from_slice(&(code.len() as u64).to_le_bytes()); // p_memsz
    v.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
    debug_assert_eq!(v.len() as u64, code_off);

    v.extend_from_slice(code);
    v.extend_from_slice(strtab);
    debug_assert_eq!(v.len() as u64, shoff);

    // -- Section headers --
    shdr(&mut v, 0, 0, 0, 0, 0, 0, 0); // [0] NULL
    shdr(&mut v, 1, 1, 6, LOAD, code_off, code.len() as u64, 4); // [1] .text PROGBITS, ALLOC|EXEC
    shdr(&mut v, 7, 3, 0, 0, strtab_off, strtab.len() as u64, 1); // [2] .shstrtab STRTAB
    v
}

/// A unique temp path under the system temp dir (no `rand`/time deps — uses the
/// pid and a per-call counter).
fn temp_path(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("javm-fuzz-{}-{}-{tag}", std::process::id(), n))
}

/// Spike ABI register name for x-register `xreg` (the debugger's `reg` command
/// takes ABI names). Only the captured set [`SIG_XREGS`] is needed.
fn abi_name(xreg: u8) -> &'static str {
    match xreg {
        1 => "ra",
        2 => "sp",
        5 => "t0",
        6 => "t1",
        7 => "t2",
        8 => "s0",
        9 => "s1",
        10 => "a0",
        11 => "a1",
        12 => "a2",
        13 => "a3",
        14 => "a4",
        15 => "a5",
        _ => panic!("abi_name: x{xreg} is not in the captured signature set"),
    }
}

/// Run `prog`'s **body** (body + signature epilogue, **no terminator** — the
/// epilogue is stripped: it stores to `SIG_BASE`, below Spike's DRAM) on Spike
/// and return its final register file as the [`SIG_BYTES`]-byte signature (one
/// LE `u64` per captured slot, in [`SIG_XREGS`] order). Errors if Spike is
/// missing or its output can't be parsed.
///
/// We don't ask Spike's debugger to set registers (it can't reliably, and the
/// RISC-V boot convention clobbers a0/a1 = hartid/dtb anyway). Instead we
/// **prepend register materialization** (`li64` per captured register, to its
/// seed or 0) so the oracle starts from the same state as our engines, then read
/// each register back — exactly the values the engines' signature epilogue
/// stores into the scratchpad region.
pub fn spike_signature(prog: &Program) -> std::io::Result<[u8; SIG_BYTES]> {
    // Strip the signature epilogue: the oracle reads registers directly, so it
    // runs only the body (the epilogue's stores to SIG_BASE would fault Spike).
    let epilogue_len = crate::encode::signature_epilogue(crate::SIG_BASE).len();
    let body_end = prog.code.len().saturating_sub(epilogue_len);
    let body = &prog.code[..body_end];

    let mut words: Vec<u32> = Vec::new();
    for &xreg in &SIG_XREGS {
        // x10–x13 (a0–a3) are the invocation argument registers: the engines
        // load the call args ([0;4]) over any cap seed (nub-arch-local:131),
        // so they always start at 0. Match that here — otherwise the oracle's
        // initial state diverges from both engines for any seed in x10–x13.
        let val = if (10..=13).contains(&xreg) {
            0
        } else {
            let slot = nub_exec::regs::reg_slot_or_ff(xreg);
            prog.init_regs.get(&slot).copied().unwrap_or(0)
        };
        words.extend(crate::encode::li64(xreg, val));
    }
    words.extend_from_slice(body);
    let code = crate::encode::enc(&words);
    let end = LOAD + code.len() as u64; // PC at the end of the body

    let elf_path = temp_path("elf");
    let cmd_path = temp_path("cmd");
    std::fs::write(&elf_path, build_elf(&code))?;

    // Debug command script: run to `end`, print each captured register in
    // SIG_XREGS order, quit. (Initial registers are materialized in the code
    // above, not set here.)
    let mut cmd = String::new();
    cmd.push_str(&format!("until pc 0 0x{end:016x}\n"));
    for &xreg in &SIG_XREGS {
        cmd.push_str(&format!("reg 0 {}\n", abi_name(xreg)));
    }
    cmd.push_str("quit\n");
    std::fs::File::create(&cmd_path)?.write_all(cmd.as_bytes())?;

    let out = Command::new("spike")
        .arg("-d")
        .arg(format!("--debug-cmd={}", cmd_path.display()))
        .arg(format!("--isa={SPIKE_ISA}"))
        .arg(&elf_path)
        .output()?;

    let _ = std::fs::remove_file(&elf_path);
    let _ = std::fs::remove_file(&cmd_path);

    // Spike prints debugger output (incl. each `reg` value) to stderr. The
    // SIG_REGS register prints are the last hex tokens before `quit`, in
    // command (SIG_XREGS) order.
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let vals = parse_last_n_hex(&text, SIG_REGS).ok_or_else(|| {
        std::io::Error::other(format!(
            "could not parse {SIG_REGS} registers from spike output:\n{text}"
        ))
    })?;
    let mut sig = [0u8; SIG_BYTES];
    for (i, v) in vals.iter().enumerate() {
        sig[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    Ok(sig)
}

/// The last `n` `0x…`-prefixed hex values in `text`, in order (the captured
/// `reg` prints are the last things emitted before `quit`). `None` if fewer than
/// `n` hex tokens are present.
fn parse_last_n_hex(text: &str, n: usize) -> Option<Vec<u64>> {
    let all: Vec<u64> = text
        .split(|c: char| !c.is_ascii_hexdigit() && c != 'x' && c != 'X')
        .filter_map(|tok| tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X")))
        .filter_map(|h| u64::from_str_radix(h, 16).ok())
        .collect();
    if all.len() < n {
        return None;
    }
    Some(all[all.len() - n..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode;
    use std::collections::BTreeMap;

    /// Spike computes `s0 = seed(s0) + 5` for `addi s0, s0, 5` (just the body —
    /// no epilogue). Seeds a non-arg register (x10–x13 are forced to 0), so the
    /// signature slot for x8 reads 15. Validates the ELF + command driving and
    /// the register read-back. `#[ignore]` — needs the `spike` binary on PATH.
    #[test]
    #[ignore = "needs spike on PATH"]
    fn spike_computes_addi() {
        let mut init = BTreeMap::new();
        init.insert(nub_exec::regs::reg_slot_or_ff(8), 10u64); // x8 = s0
        let prog = Program {
            code: vec![encode::addi(8, 8, 5)],
            init_regs: init,
            init_mem: None,
        };
        let sig = spike_signature(&prog).unwrap();
        // Signature slot for x8 (s0) holds the LE u64 result 15.
        let s = nub_exec::regs::reg_slot_or_ff(8) as usize;
        let val = u64::from_le_bytes(sig[s * 8..s * 8 + 8].try_into().unwrap());
        assert_eq!(val, 15);
    }
}
