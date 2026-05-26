//! Dump the rewritten PVM2 code as a raw .bin so it can be disassembled
//! with llvm-objdump --disassemble-symbols.

#![cfg_attr(not(all(target_os = "linux", target_arch = "x86_64")), allow(unused))]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_cap::image::Image;
use ssz::Decode;

fn main() {
    let blob = std::fs::read(env!("GOLDILOCKS_MUL_PVM2_BLOB")).unwrap();
    let img = Image::from_ssz_bytes(&blob).unwrap();
    let out = std::env::args().nth(1).unwrap_or_else(|| "/tmp/pvm2_code.bin".into());
    std::fs::write(&out, &img.code).unwrap();
    println!("wrote {} bytes to {}", img.code.len(), out);
}
