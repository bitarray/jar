//! `sbpf-link` — turn the relocatable BPF object that `bpf-linker`
//! emits into an SBPFv3 ELF that `solana-sbpf` will load.
//!
//! This is not a general linker. `bpf-linker` has already done fat LTO
//! and handed us a single `ET_REL` object, so all that remains is to
//! apply the relocations it left behind and wrap the result in the
//! container the strict v3 parser demands:
//!
//! ```text
//!   e_type    = ET_DYN            e_machine = EM_BPF (247)
//!   e_flags   = 3                 (selects SBPFVersion::V3)
//!   e_phoff   = 64                e_phnum   = 1 or 2
//!   phdr[0]   = PT_LOAD PF_R  vaddr 0            (read-only data)
//!   phdr[1]   = PT_LOAD PF_X  vaddr 0x1_0000_0000 (bytecode)
//! ```
//!
//! Every `p_offset` and `p_filesz` must be a multiple of 8, each
//! segment must sit immediately after the previous one, and
//! `p_filesz == p_memsz` — which is the container's way of saying it
//! cannot express writable or zero-initialized memory at all. That is
//! why a non-empty `SHF_WRITE|SHF_ALLOC` section is a hard error here
//! rather than something to paper over: it would fail at load time with
//! a far less obvious message.

use std::collections::HashMap;

const EHDR_LEN: usize = 64;
const PHDR_LEN: usize = 56;
const SHDR_LEN: usize = 64;
const SYM_LEN: usize = 24;
const INSN: u64 = 8;

const EM_BPF: u16 = 247;
const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_R: u32 = 4;

const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_REL: u32 = 9;
const SHT_NOBITS: u32 = 8;

const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;

/// `solana_sbpf::ebpf::MM_BYTECODE_START`.
const TEXT_VADDR: u64 = 1 << 32;

fn u16a(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn u32a(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64a(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

struct Section {
    name: String,
    sh_type: u32,
    flags: u64,
    offset: usize,
    size: usize,
    link: u32,
    info: u32,
}

struct Sym {
    name: String,
    shndx: u16,
    value: u64,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut input = None;
    let mut output = None;
    let mut entry_sym = "run".to_string();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-o" => {
                output = Some(args[i + 1].clone());
                i += 2;
            }
            "--entry" => {
                entry_sym = args[i + 1].clone();
                i += 2;
            }
            a => {
                input = Some(a.to_string());
                i += 1;
            }
        }
    }
    let (input, output) = match (input, output) {
        (Some(i), Some(o)) => (i, o),
        _ => {
            eprintln!("usage: sbpf-link <input.o> -o <out.sbpf> [--entry <sym>]");
            std::process::exit(2);
        }
    };

    let obj = std::fs::read(&input).unwrap_or_else(|e| fail(&format!("read {input}: {e}")));
    let out = link(&obj, &entry_sym);
    std::fs::write(&output, &out).unwrap_or_else(|e| fail(&format!("write {output}: {e}")));
    eprintln!("sbpf-link: wrote {} ({} bytes)", output, out.len());
}

fn fail(msg: &str) -> ! {
    eprintln!("sbpf-link: {msg}");
    std::process::exit(1);
}

fn link(obj: &[u8], entry_sym: &str) -> Vec<u8> {
    if obj.get(..4) != Some(&[0x7f, b'E', b'L', b'F']) {
        fail("input is not an ELF");
    }
    if u16a(obj, 18) != EM_BPF {
        fail(&format!(
            "input e_machine is {}, expected 247",
            u16a(obj, 18)
        ));
    }

    let shoff = u64a(obj, 40) as usize;
    let shnum = u16a(obj, 60) as usize;
    let shstrndx = u16a(obj, 62) as usize;

    let raw = |i: usize| -> (u32, u32, u64, usize, usize, u32, u32) {
        let o = shoff + i * SHDR_LEN;
        (
            u32a(obj, o),               // sh_name
            u32a(obj, o + 4),           // sh_type
            u64a(obj, o + 8),           // sh_flags
            u64a(obj, o + 24) as usize, // sh_offset
            u64a(obj, o + 32) as usize, // sh_size
            u32a(obj, o + 40),          // sh_link
            u32a(obj, o + 44),          // sh_info
        )
    };

    let shstr_off = raw(shstrndx).3;
    let cstr = |base: usize, off: usize| -> String {
        let s = base + off;
        let end = obj[s..].iter().position(|&c| c == 0).unwrap_or(0) + s;
        String::from_utf8_lossy(&obj[s..end]).into_owned()
    };

    let sections: Vec<Section> = (0..shnum)
        .map(|i| {
            let (n, t, f, o, sz, link, info) = raw(i);
            Section {
                name: cstr(shstr_off, n as usize),
                sh_type: t,
                flags: f,
                offset: o,
                size: sz,
                link,
                info,
            }
        })
        .collect();

    // The container has no writable segment. Catch it here, loudly,
    // rather than at load time.
    for s in &sections {
        let writable = s.flags & SHF_WRITE != 0 && s.flags & SHF_ALLOC != 0;
        if writable && s.size > 0 {
            fail(&format!(
                "section `{}` is writable and {} bytes; sBPF has no writable segment. \
                 Move the data to the heap or make it immutable.",
                s.name, s.size
            ));
        }
        if s.sh_type == SHT_NOBITS && s.size > 0 && s.flags & SHF_ALLOC != 0 {
            fail(&format!(
                "section `{}` is {} bytes of .bss; sBPF cannot express zero-initialized memory.",
                s.name, s.size
            ));
        }
    }

    // Gather code and read-only data. bpf-linker emits a single `.text`
    // after LTO, but tolerate the general case.
    let mut text = Vec::new();
    let mut text_base: HashMap<usize, u64> = HashMap::new();
    let mut rodata = Vec::new();
    let mut rodata_base: HashMap<usize, u64> = HashMap::new();
    for (i, s) in sections.iter().enumerate() {
        if s.sh_type != SHT_PROGBITS || s.flags & SHF_ALLOC == 0 {
            continue;
        }
        if s.flags & SHF_EXECINSTR != 0 {
            text_base.insert(i, text.len() as u64);
            text.extend_from_slice(&obj[s.offset..s.offset + s.size]);
        } else {
            while rodata.len() % 8 != 0 {
                rodata.push(0);
            }
            rodata_base.insert(i, rodata.len() as u64);
            rodata.extend_from_slice(&obj[s.offset..s.offset + s.size]);
        }
    }
    if text.is_empty() {
        fail("no executable section found");
    }
    while text.len() % INSN as usize != 0 {
        text.push(0);
    }
    while rodata.len() % INSN as usize != 0 {
        rodata.push(0);
    }

    // Symbols, with their final virtual addresses.
    let symtab = sections
        .iter()
        .position(|s| s.sh_type == SHT_SYMTAB)
        .unwrap_or_else(|| fail("no .symtab"));
    let strtab_off = sections[sections[symtab].link as usize].offset;
    let nsyms = sections[symtab].size / SYM_LEN;
    let syms: Vec<Sym> = (0..nsyms)
        .map(|i| {
            let o = sections[symtab].offset + i * SYM_LEN;
            Sym {
                name: cstr(strtab_off, u32a(obj, o) as usize),
                shndx: u16a(obj, o + 6),
                value: u64a(obj, o + 8),
            }
        })
        .collect();

    let sym_vaddr = |s: &Sym| -> Option<u64> {
        let idx = s.shndx as usize;
        if let Some(b) = text_base.get(&idx) {
            Some(TEXT_VADDR + b + s.value)
        } else {
            rodata_base.get(&idx).map(|b| b + s.value)
        }
    };

    // Apply relocations into the text image.
    for s in &sections {
        if s.sh_type != SHT_REL || !s.name.starts_with(".rel") {
            continue;
        }
        let target = s.info as usize;
        let Some(&tbase) = text_base.get(&target) else {
            continue; // relocations against a non-code section
        };
        let n = s.size / 16;
        for i in 0..n {
            let o = s.offset + i * 16;
            let r_offset = u64a(obj, o);
            let r_info = u64a(obj, o + 8);
            let r_type = (r_info & 0xffff_ffff) as u32;
            let r_sym = (r_info >> 32) as usize;
            let sym = &syms[r_sym];
            let at = (tbase + r_offset) as usize;

            let Some(target_va) = sym_vaddr(sym) else {
                fail(&format!(
                    "unresolved symbol `{}` — nothing defines it in this object",
                    sym.name
                ));
            };

            match r_type {
                // call: imm32 is the pc-relative target, in instructions.
                10 => {
                    let this_insn = (at as u64) / INSN;
                    let target_insn = (target_va - TEXT_VADDR) / INSN;
                    let rel = target_insn as i64 - this_insn as i64 - 1;
                    let imm = i32::try_from(rel)
                        .unwrap_or_else(|_| fail("call target out of range for imm32"));
                    text[at + 4..at + 8].copy_from_slice(&imm.to_le_bytes());
                }
                // lddw: a 64-bit address split across two instruction slots.
                1 => {
                    let addend = u32a(&text, at + 4) as u64;
                    let va = target_va + addend;
                    text[at + 4..at + 8]
                        .copy_from_slice(&((va & 0xffff_ffff) as u32).to_le_bytes());
                    text[at + 12..at + 16].copy_from_slice(&((va >> 32) as u32).to_le_bytes());
                }
                0 => {}
                t => fail(&format!(
                    "unsupported relocation type {t} against `{}`",
                    sym.name
                )),
            }
        }
    }

    let entry = syms
        .iter()
        .find(|s| s.name == entry_sym)
        .and_then(sym_vaddr)
        .unwrap_or_else(|| fail(&format!("entry symbol `{entry_sym}` not found")));

    emit(&rodata, &text, entry)
}

fn emit(rodata: &[u8], text: &[u8], entry: u64) -> Vec<u8> {
    // One program header when there is no read-only data: the parser
    // explicitly allows starting at the bytecode header if the first
    // one is not PF_R.
    let phnum: u16 = if rodata.is_empty() { 1 } else { 2 };
    let phoff = EHDR_LEN;
    let first = phoff + PHDR_LEN * phnum as usize;
    assert_eq!(first % 8, 0, "segment offset must be 8-aligned");

    let mut out = Vec::new();
    out.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]); // ident: ELF64, LSB, current, SYSV
    out.extend_from_slice(&[0u8; 8]); // abiversion + pad
    out.extend_from_slice(&ET_DYN.to_le_bytes());
    out.extend_from_slice(&EM_BPF.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes()); // e_version
    out.extend_from_slice(&entry.to_le_bytes());
    out.extend_from_slice(&(phoff as u64).to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // e_shoff — no section headers
    out.extend_from_slice(&3u32.to_le_bytes()); // e_flags = 3 -> SBPFVersion::V3
    out.extend_from_slice(&(EHDR_LEN as u16).to_le_bytes());
    out.extend_from_slice(&(PHDR_LEN as u16).to_le_bytes());
    out.extend_from_slice(&phnum.to_le_bytes());
    out.extend_from_slice(&(SHDR_LEN as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    out.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
    assert_eq!(out.len(), EHDR_LEN);

    let push_ph = |out: &mut Vec<u8>, flags: u32, off: usize, vaddr: u64, len: usize| {
        out.extend_from_slice(&PT_LOAD.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&(off as u64).to_le_bytes());
        out.extend_from_slice(&vaddr.to_le_bytes());
        out.extend_from_slice(&vaddr.to_le_bytes()); // p_paddr == p_vaddr
        out.extend_from_slice(&(len as u64).to_le_bytes()); // p_filesz
        out.extend_from_slice(&(len as u64).to_le_bytes()); // p_memsz == p_filesz
        out.extend_from_slice(&8u64.to_le_bytes()); // p_align
    };

    let text_off = if rodata.is_empty() {
        first
    } else {
        push_ph(&mut out, PF_R, first, 0, rodata.len());
        first + rodata.len()
    };
    push_ph(&mut out, PF_X, text_off, TEXT_VADDR, text.len());
    assert_eq!(out.len(), first);

    out.extend_from_slice(rodata);
    out.extend_from_slice(text);
    out
}
