//! Quick dump of PVM2 Image.code for debugging.

#![cfg_attr(not(all(target_os = "linux", target_arch = "x86_64")), allow(unused))]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_cap::image::Image;
use ssz::Decode;

fn main() {
    let blob = std::fs::read(env!("GOLDILOCKS_MUL_PVM2_BLOB")).unwrap();
    let img = Image::from_ssz_bytes(&blob).unwrap();
    println!("code = {} bytes", img.code.len());
    for (idx, ep) in &img.endpoints {
        println!("endpoint {idx}: entry_pc={:#x}", ep.entry_pc);
    }
    for m in &img.memory_mappings {
        println!(
            "mapping: start={:#x} size={:#x} target={:?}",
            m.start, m.size, m.source.target()
        );
    }
    println!("\nFirst 128 bytes of code (PC // byte hex // disasm-hint):");
    let mut i = 0;
    while i < img.code.len().min(128) {
        if i + 2 > img.code.len() {
            break;
        }
        let lo = u16::from_le_bytes([img.code[i], img.code[i + 1]]);
        if lo & 0b11 != 0b11 {
            println!("  {:04x}: {:04x}        (RVC)", i, lo);
            i += 2;
        } else {
            if i + 4 > img.code.len() {
                break;
            }
            let w = u32::from_le_bytes([
                img.code[i], img.code[i + 1], img.code[i + 2], img.code[i + 3],
            ]);
            let op = w & 0x7F;
            let mnem = match op {
                0x37 => "LUI",
                0x17 => "AUIPC",
                0x6F => "JAL",
                0x67 => "JALR",
                0x63 => "B*",
                0x03 => "L*",
                0x23 => "S*",
                0x13 => "ALU-imm",
                0x33 => "ALU-rr",
                0x73 => "SYSTEM",
                0x0B => "custom-0",
                _ => "?",
            };
            println!("  {:04x}: {:08x}  {}", i, w, mnem);
            i += 4;
        }
    }
}
