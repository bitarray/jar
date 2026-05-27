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
    if let Ok(want) = std::env::var("DUMP_DISASM")
        && want == name
    {
        for i in &pd.insts {
            println!("  {:#06x}: {:?}", i.pc, i.inst);
        }
    }
    let mut hist: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    for i in &pd.insts {
        let n = match &i.inst {
            RvInst::Add { .. } => "Add",
            RvInst::Sub { .. } => "Sub",
            RvInst::Sltu { .. } => "Sltu",
            RvInst::Slt { .. } => "Slt",
            RvInst::Sltiu { .. } => "Sltiu",
            RvInst::Slti { .. } => "Slti",
            RvInst::Mul { .. } => "Mul",
            RvInst::Mulh { .. } => "Mulh",
            RvInst::Mulhsu { .. } => "Mulhsu",
            RvInst::Mulhu { .. } => "Mulhu",
            RvInst::Div { .. } => "Div",
            RvInst::Divu { .. } => "Divu",
            RvInst::Rem { .. } => "Rem",
            RvInst::Remu { .. } => "Remu",
            RvInst::Divw { .. } => "Divw",
            RvInst::Divuw { .. } => "Divuw",
            RvInst::Remw { .. } => "Remw",
            RvInst::Remuw { .. } => "Remuw",
            RvInst::Slli { .. } => "Slli",
            RvInst::Srli { .. } => "Srli",
            RvInst::Srai { .. } => "Srai",
            RvInst::Sll { .. } => "Sll",
            RvInst::Srl { .. } => "Srl",
            RvInst::Sra { .. } => "Sra",
            RvInst::Sllw { .. } => "Sllw",
            RvInst::Srlw { .. } => "Srlw",
            RvInst::Sraw { .. } => "Sraw",
            RvInst::Rori { .. } => "Rori",
            RvInst::Maxu { .. } => "Maxu",
            RvInst::Minu { .. } => "Minu",
            RvInst::Max { .. } => "Max",
            RvInst::Min { .. } => "Min",
            RvInst::Mulw { .. } => "Mulw",
            RvInst::Addw { .. } => "Addw",
            RvInst::Subw { .. } => "Subw",
            RvInst::Adduw { .. } => "Adduw",
            RvInst::Sh1adduw { .. } => "Sh1adduw",
            RvInst::Sh2adduw { .. } => "Sh2adduw",
            RvInst::Sh3adduw { .. } => "Sh3adduw",
            RvInst::Slliuw { .. } => "Slliuw",
            RvInst::Clz { .. } => "Clz",
            RvInst::Ctz { .. } => "Ctz",
            RvInst::Cpop { .. } => "Cpop",
            RvInst::Clzw { .. } => "Clzw",
            RvInst::Ctzw { .. } => "Ctzw",
            RvInst::Cpopw { .. } => "Cpopw",
            RvInst::SextB { .. } => "SextB",
            RvInst::SextH { .. } => "SextH",
            RvInst::ZextH { .. } => "ZextH",
            RvInst::OrcB { .. } => "OrcB",
            RvInst::Rev8 { .. } => "Rev8",
            RvInst::Bclri { .. } => "Bclri",
            RvInst::Bseti { .. } => "Bseti",
            RvInst::Binvi { .. } => "Binvi",
            RvInst::Bexti { .. } => "Bexti",
            RvInst::Trap => "Trap",
            RvInst::EcallJar => "EcallJar",
            RvInst::Ecalli { .. } => "Ecalli",
            RvInst::Retf => "Retf",
            RvInst::Fallthrough => "Fallthrough",
            RvInst::Callf { .. } => "Callf",
            RvInst::CzeroEqz { .. } => "CzeroEqz",
            RvInst::CzeroNez { .. } => "CzeroNez",
            RvInst::Xor { .. } => "Xor",
            RvInst::Or { .. } => "Or",
            RvInst::And { .. } => "And",
            RvInst::Bclr { .. } => "Bclr",
            RvInst::Bset { .. } => "Bset",
            RvInst::Bext { .. } => "Bext",
            RvInst::Binv { .. } => "Binv",
            RvInst::Sh1add { .. } => "Sh1add",
            RvInst::Sh2add { .. } => "Sh2add",
            RvInst::Sh3add { .. } => "Sh3add",
            RvInst::Rol { .. } => "Rol",
            RvInst::Ror { .. } => "Ror",
            RvInst::Andn { .. } => "Andn",
            RvInst::Orn { .. } => "Orn",
            RvInst::Xnor { .. } => "Xnor",
            RvInst::Reserved { .. } => "Reserved",
            _ => continue,
        };
        *hist.entry(n).or_insert(0) += 1;
    }
    println!("opcode histogram (interesting):");
    for (k, v) in &hist {
        println!("  {k}: {v}");
    }
}

fn main() {
    dump("prime_sieve", include_bytes!(env!("PRIME_SIEVE_PVM2_BLOB")));
    dump("keccak", include_bytes!(env!("KECCAK_PVM2_BLOB")));
    dump("blake2b", include_bytes!(env!("BLAKE2B_PVM2_BLOB")));
    dump(
        "goldilocks_mul",
        include_bytes!(env!("GOLDILOCKS_MUL_PVM2_BLOB")),
    );
    dump(
        "poseidon2_perm",
        include_bytes!(env!("POSEIDON2_PERM_PVM2_BLOB")),
    );
    dump(
        "mini_verifier",
        include_bytes!(env!("MINI_VERIFIER_PVM2_BLOB")),
    );
    dump("poly_eval", include_bytes!(env!("POLY_EVAL_PVM2_BLOB")));
    dump(
        "fri_fold_tree",
        include_bytes!(env!("FRI_FOLD_TREE_PVM2_BLOB")),
    );
    dump("ed25519", include_bytes!(env!("ED25519_PVM2_BLOB")));
    dump("ecrecover", include_bytes!(env!("ECRECOVER_PVM2_BLOB")));
}
