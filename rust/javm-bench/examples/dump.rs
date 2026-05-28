//! Quick dump of PVM2 Image.code + predecode for debugging.

use javm_cap::image::Image;
use javm_exec::instruction::Inst;
use javm_exec::predecode::predecode;
use ssz::Decode;

fn dump(name: &str, blob: &[u8]) {
    let img = Image::from_ssz_bytes(blob).expect("decode");
    println!("=== {} ===", name);
    println!("code = {} bytes", img.code.len());
    let pd = predecode(&img.code);
    println!(
        "predecode: {} insts, decode_error_at = {:?}",
        pd.insts.len(),
        pd.decode_error_at
    );
    let n_reserved = pd
        .insts
        .iter()
        .filter(|i| matches!(i.inst, Inst::Reserved { .. }))
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
            Inst::Add { .. } => "Add",
            Inst::Sub { .. } => "Sub",
            Inst::Sltu { .. } => "Sltu",
            Inst::Slt { .. } => "Slt",
            Inst::Sltiu { .. } => "Sltiu",
            Inst::Slti { .. } => "Slti",
            Inst::Mul { .. } => "Mul",
            Inst::Mulh { .. } => "Mulh",
            Inst::Mulhsu { .. } => "Mulhsu",
            Inst::Mulhu { .. } => "Mulhu",
            Inst::Div { .. } => "Div",
            Inst::Divu { .. } => "Divu",
            Inst::Rem { .. } => "Rem",
            Inst::Remu { .. } => "Remu",
            Inst::Divw { .. } => "Divw",
            Inst::Divuw { .. } => "Divuw",
            Inst::Remw { .. } => "Remw",
            Inst::Remuw { .. } => "Remuw",
            Inst::Slli { .. } => "Slli",
            Inst::Srli { .. } => "Srli",
            Inst::Srai { .. } => "Srai",
            Inst::Sll { .. } => "Sll",
            Inst::Srl { .. } => "Srl",
            Inst::Sra { .. } => "Sra",
            Inst::Sllw { .. } => "Sllw",
            Inst::Srlw { .. } => "Srlw",
            Inst::Sraw { .. } => "Sraw",
            Inst::Rori { .. } => "Rori",
            Inst::Maxu { .. } => "Maxu",
            Inst::Minu { .. } => "Minu",
            Inst::Max { .. } => "Max",
            Inst::Min { .. } => "Min",
            Inst::Mulw { .. } => "Mulw",
            Inst::Addw { .. } => "Addw",
            Inst::Subw { .. } => "Subw",
            Inst::Adduw { .. } => "Adduw",
            Inst::Sh1adduw { .. } => "Sh1adduw",
            Inst::Sh2adduw { .. } => "Sh2adduw",
            Inst::Sh3adduw { .. } => "Sh3adduw",
            Inst::Slliuw { .. } => "Slliuw",
            Inst::Clz { .. } => "Clz",
            Inst::Ctz { .. } => "Ctz",
            Inst::Cpop { .. } => "Cpop",
            Inst::Clzw { .. } => "Clzw",
            Inst::Ctzw { .. } => "Ctzw",
            Inst::Cpopw { .. } => "Cpopw",
            Inst::SextB { .. } => "SextB",
            Inst::SextH { .. } => "SextH",
            Inst::ZextH { .. } => "ZextH",
            Inst::OrcB { .. } => "OrcB",
            Inst::Rev8 { .. } => "Rev8",
            Inst::Bclri { .. } => "Bclri",
            Inst::Bseti { .. } => "Bseti",
            Inst::Binvi { .. } => "Binvi",
            Inst::Bexti { .. } => "Bexti",
            Inst::Trap => "Trap",
            Inst::EcallJar => "EcallJar",
            Inst::Ecalli { .. } => "Ecalli",
            Inst::BrTable { .. } => "BrTable",
            Inst::Fallthrough => "Fallthrough",
            Inst::CzeroEqz { .. } => "CzeroEqz",
            Inst::CzeroNez { .. } => "CzeroNez",
            Inst::Xor { .. } => "Xor",
            Inst::Or { .. } => "Or",
            Inst::And { .. } => "And",
            Inst::Bclr { .. } => "Bclr",
            Inst::Bset { .. } => "Bset",
            Inst::Bext { .. } => "Bext",
            Inst::Binv { .. } => "Binv",
            Inst::Sh1add { .. } => "Sh1add",
            Inst::Sh2add { .. } => "Sh2add",
            Inst::Sh3add { .. } => "Sh3add",
            Inst::Rol { .. } => "Rol",
            Inst::Ror { .. } => "Ror",
            Inst::Andn { .. } => "Andn",
            Inst::Orn { .. } => "Orn",
            Inst::Xnor { .. } => "Xnor",
            Inst::Reserved { .. } => "Reserved",
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
    dump("prime_sieve", include_bytes!(env!("PRIME_SIEVE_BLOB")));
    dump("keccak", include_bytes!(env!("KECCAK_BLOB")));
    dump("blake2b", include_bytes!(env!("BLAKE2B_BLOB")));
    dump(
        "goldilocks_mul",
        include_bytes!(env!("GOLDILOCKS_MUL_BLOB")),
    );
    dump(
        "poseidon2_perm",
        include_bytes!(env!("POSEIDON2_PERM_BLOB")),
    );
    dump("mini_verifier", include_bytes!(env!("MINI_VERIFIER_BLOB")));
    dump("poly_eval", include_bytes!(env!("POLY_EVAL_BLOB")));
    dump("fri_fold_tree", include_bytes!(env!("FRI_FOLD_TREE_BLOB")));
    dump("ed25519", include_bytes!(env!("ED25519_BLOB")));
    dump("ecrecover", include_bytes!(env!("ECRECOVER_BLOB")));
}
