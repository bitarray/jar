//! Quick dump of PVM2 Image.code + predecode for debugging.

#![cfg_attr(not(all(target_os = "linux", target_arch = "x86_64")), allow(unused))]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use javm_cap::image::Image;
use javm_exec::rv_instruction::RvInst;
use javm_exec::rv_predecode::predecode_rv;
use ssz::Decode;

fn dump(name: &str, blob: &[u8]) {
    let img = Image::from_ssz_bytes(blob).expect("decode");
    println!("=== {} ===", name);
    println!("code = {} bytes", img.code.len());
    let pd = predecode_rv(&img.code);
    println!(
        "predecode: {} insts, decode_error_at = {:?}",
        pd.insts.len(),
        pd.decode_error_at
    );
    let n_reserved = pd
        .insts
        .iter()
        .filter(|i| matches!(i.inst, RvInst::Reserved { .. }))
        .count();
    println!("reserved: {}", n_reserved);
    if n_reserved > 0 && n_reserved < 40 {
        for i in &pd.insts {
            if let RvInst::Reserved { raw } = i.inst {
                println!("  PC {:#x}: Reserved raw={:#x}", i.pc, raw);
            }
        }
    }
}

fn main() {
    dump(
        "goldilocks_mul (passes)",
        include_bytes!(env!("GOLDILOCKS_MUL_PVM2_BLOB")),
    );
    dump(
        "poly_eval (fails)",
        include_bytes!(env!("POLY_EVAL_PVM2_BLOB")),
    );
    dump(
        "ed25519 (fails)",
        include_bytes!(env!("ED25519_PVM2_BLOB")),
    );
}
