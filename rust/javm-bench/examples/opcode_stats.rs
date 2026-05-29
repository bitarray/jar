//! Frequency profile of RV opcodes (and adjacency-pair patterns) in
//! PVM2 guest images. Run to identify which RV variants/pairs are
//! worth fusion peepholes in the recompiler hot loop.

use javm_cap::image::Image;
use javm_exec::instruction::{Inst, decode};
use ssz::Decode;
use std::collections::BTreeMap;

fn variant_name(inst: &Inst) -> &'static str {
    use Inst::*;
    match inst {
        Lb { .. } => "Lb",
        Lh { .. } => "Lh",
        Lw { .. } => "Lw",
        Ld { .. } => "Ld",
        Lbu { .. } => "Lbu",
        Lhu { .. } => "Lhu",
        Lwu { .. } => "Lwu",
        Sb { .. } => "Sb",
        Sh { .. } => "Sh",
        Sw { .. } => "Sw",
        Sd { .. } => "Sd",
        Addi { .. } => "Addi",
        Slti { .. } => "Slti",
        Sltiu { .. } => "Sltiu",
        Andi { .. } => "Andi",
        Ori { .. } => "Ori",
        Xori { .. } => "Xori",
        Slli { .. } => "Slli",
        Srli { .. } => "Srli",
        Srai { .. } => "Srai",
        Addiw { .. } => "Addiw",
        Slliw { .. } => "Slliw",
        Srliw { .. } => "Srliw",
        Sraiw { .. } => "Sraiw",
        Add { .. } => "Add",
        Sub { .. } => "Sub",
        Sll { .. } => "Sll",
        Srl { .. } => "Srl",
        Sra { .. } => "Sra",
        Slt { .. } => "Slt",
        Sltu { .. } => "Sltu",
        Xor { .. } => "Xor",
        Or { .. } => "Or",
        And { .. } => "And",
        Addw { .. } => "Addw",
        Subw { .. } => "Subw",
        Sllw { .. } => "Sllw",
        Srlw { .. } => "Srlw",
        Sraw { .. } => "Sraw",
        Mul { .. } => "Mul",
        Mulh { .. } => "Mulh",
        Mulhsu { .. } => "Mulhsu",
        Mulhu { .. } => "Mulhu",
        Div { .. } => "Div",
        Divu { .. } => "Divu",
        Rem { .. } => "Rem",
        Remu { .. } => "Remu",
        Mulw { .. } => "Mulw",
        Divw { .. } => "Divw",
        Divuw { .. } => "Divuw",
        Remw { .. } => "Remw",
        Remuw { .. } => "Remuw",
        Clz { .. } => "Clz",
        Clzw { .. } => "Clzw",
        Ctz { .. } => "Ctz",
        Ctzw { .. } => "Ctzw",
        Cpop { .. } => "Cpop",
        Cpopw { .. } => "Cpopw",
        SextB { .. } => "SextB",
        SextH { .. } => "SextH",
        ZextH { .. } => "ZextH",
        Rev8 { .. } => "Rev8",
        OrcB { .. } => "OrcB",
        Min { .. } => "Min",
        Minu { .. } => "Minu",
        Max { .. } => "Max",
        Maxu { .. } => "Maxu",
        Andn { .. } => "Andn",
        Orn { .. } => "Orn",
        Xnor { .. } => "Xnor",
        Rol { .. } => "Rol",
        Ror { .. } => "Ror",
        Rolw { .. } => "Rolw",
        Rorw { .. } => "Rorw",
        Rori { .. } => "Rori",
        Roriw { .. } => "Roriw",
        Sh1add { .. } => "Sh1add",
        Sh2add { .. } => "Sh2add",
        Sh3add { .. } => "Sh3add",
        Sh1adduw { .. } => "Sh1adduw",
        Sh2adduw { .. } => "Sh2adduw",
        Sh3adduw { .. } => "Sh3adduw",
        Adduw { .. } => "Adduw",
        Slliuw { .. } => "Slliuw",
        Bclr { .. } => "Bclr",
        Bclri { .. } => "Bclri",
        Bext { .. } => "Bext",
        Bexti { .. } => "Bexti",
        Binv { .. } => "Binv",
        Binvi { .. } => "Binvi",
        Bset { .. } => "Bset",
        Bseti { .. } => "Bseti",
        Lui { .. } => "Lui",
        Jal { .. } => "Jal",
        Beq { .. } => "Beq",
        Bne { .. } => "Bne",
        Blt { .. } => "Blt",
        Bge { .. } => "Bge",
        Bltu { .. } => "Bltu",
        Bgeu { .. } => "Bgeu",
        EcallJar => "EcallJar",
        Ecalli { .. } => "Ecalli",
        Auipc { .. } => "Auipc",
        Jalr { .. } => "Jalr",
        Fallthrough => "Fallthrough",
        Trap => "Trap",
        Reserved { .. } => "Reserved",
        CzeroEqz { .. } => "CzeroEqz",
        CzeroNez { .. } => "CzeroNez",
        Fence => "Fence",
        FenceI => "FenceI",
    }
}

fn dst_of(inst: &Inst) -> Option<u8> {
    use Inst::*;
    match *inst {
        Lb { rd, .. }
        | Lh { rd, .. }
        | Lw { rd, .. }
        | Ld { rd, .. }
        | Lbu { rd, .. }
        | Lhu { rd, .. }
        | Lwu { rd, .. }
        | Addi { rd, .. }
        | Slti { rd, .. }
        | Sltiu { rd, .. }
        | Andi { rd, .. }
        | Ori { rd, .. }
        | Xori { rd, .. }
        | Slli { rd, .. }
        | Srli { rd, .. }
        | Srai { rd, .. }
        | Addiw { rd, .. }
        | Slliw { rd, .. }
        | Srliw { rd, .. }
        | Sraiw { rd, .. }
        | Add { rd, .. }
        | Sub { rd, .. }
        | Sll { rd, .. }
        | Srl { rd, .. }
        | Sra { rd, .. }
        | Slt { rd, .. }
        | Sltu { rd, .. }
        | Xor { rd, .. }
        | Or { rd, .. }
        | And { rd, .. }
        | Addw { rd, .. }
        | Subw { rd, .. }
        | Sllw { rd, .. }
        | Srlw { rd, .. }
        | Sraw { rd, .. }
        | Mul { rd, .. }
        | Mulh { rd, .. }
        | Mulhsu { rd, .. }
        | Mulhu { rd, .. }
        | Div { rd, .. }
        | Divu { rd, .. }
        | Rem { rd, .. }
        | Remu { rd, .. }
        | Mulw { rd, .. }
        | Divw { rd, .. }
        | Divuw { rd, .. }
        | Remw { rd, .. }
        | Remuw { rd, .. }
        | Lui { rd, .. }
        | Sh1add { rd, .. }
        | Sh2add { rd, .. }
        | Sh3add { rd, .. }
        | Sh1adduw { rd, .. }
        | Sh2adduw { rd, .. }
        | Sh3adduw { rd, .. }
        | Adduw { rd, .. }
        | Slliuw { rd, .. } => Some(rd),
        _ => None,
    }
}

fn rs1_of(inst: &Inst) -> Option<u8> {
    use Inst::*;
    match *inst {
        Lb { rs1, .. }
        | Lh { rs1, .. }
        | Lw { rs1, .. }
        | Ld { rs1, .. }
        | Lbu { rs1, .. }
        | Lhu { rs1, .. }
        | Lwu { rs1, .. }
        | Addi { rs1, .. }
        | Slti { rs1, .. }
        | Sltiu { rs1, .. }
        | Andi { rs1, .. }
        | Ori { rs1, .. }
        | Xori { rs1, .. }
        | Slli { rs1, .. }
        | Srli { rs1, .. }
        | Srai { rs1, .. }
        | Addiw { rs1, .. }
        | Slliw { rs1, .. }
        | Srliw { rs1, .. }
        | Sraiw { rs1, .. }
        | Add { rs1, .. }
        | Sub { rs1, .. }
        | Sll { rs1, .. }
        | Srl { rs1, .. }
        | Sra { rs1, .. }
        | Slt { rs1, .. }
        | Sltu { rs1, .. }
        | Xor { rs1, .. }
        | Or { rs1, .. }
        | And { rs1, .. }
        | Addw { rs1, .. }
        | Subw { rs1, .. }
        | Sllw { rs1, .. }
        | Srlw { rs1, .. }
        | Sraw { rs1, .. }
        | Mul { rs1, .. }
        | Mulh { rs1, .. }
        | Mulhsu { rs1, .. }
        | Mulhu { rs1, .. }
        | Div { rs1, .. }
        | Divu { rs1, .. }
        | Rem { rs1, .. }
        | Remu { rs1, .. } => Some(rs1),
        _ => None,
    }
}

fn profile_one(name: &str, blob: &[u8]) {
    let image = Image::from_ssz_bytes(blob).expect("decode Image");
    let code = &image.code[..];

    let mut single: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut total = 0usize;

    // (prev_variant, this_variant) for variants where prev's dst == this's rs1.
    let mut chained_pairs: BTreeMap<(&'static str, &'static str), usize> = BTreeMap::new();
    // LUI+ADDI pairs where the addi consumes the LUI's dst.
    let mut lui_addi = 0usize;

    // Precise fusion-candidate counters (exact patterns the recompiler fuses).
    let mut lui_add_same_rd = 0usize; // lui rd, _; add rd, {rd,x|x,rd} (a_rd == rd)
    let mut ld_add_any = 0usize; // ld rd, _(rs1); add a, rs, rd / a, rd, rs
    let mut ld_xor_any = 0usize;
    let mut ld_or_any = 0usize;
    let mut ld_and_any = 0usize;

    let mut prev: Option<Inst> = None;
    let mut pc = 0;
    while pc < code.len() {
        let Some((inst, len)) = decode(&code[pc..]) else {
            break;
        };
        total += 1;
        *single.entry(variant_name(&inst)).or_default() += 1;

        if let Some(p) = prev {
            let p_dst = dst_of(&p);
            let i_rs1 = rs1_of(&inst);
            if let (Some(d), Some(s)) = (p_dst, i_rs1)
                && d != 0
                && d == s
            {
                *chained_pairs
                    .entry((variant_name(&p), variant_name(&inst)))
                    .or_default() += 1;
                if matches!(p, Inst::Lui { .. }) && matches!(inst, Inst::Addi { .. }) {
                    lui_addi += 1;
                }
            }
            // Precise Lui→Add same-rd pattern (this is what compile_lui actually fuses).
            if let (Inst::Lui { rd: l_rd, .. }, Inst::Add { rd: a_rd, rs1, rs2 }) = (p, inst)
                && a_rd != 0
                && a_rd == l_rd
                && (rs1 == l_rd || rs2 == l_rd)
            {
                lui_add_same_rd += 1;
            }
            // Precise Ld→ALU patterns the recompiler fuses (rd != 0; ALU reads ld's rd).
            if let Inst::Ld { rd: l_rd, .. } = p
                && l_rd != 0
            {
                let alu_uses_ld = |a_rs1: u8, a_rs2: u8| a_rs1 == l_rd || a_rs2 == l_rd;
                match inst {
                    Inst::Add { rd: a_rd, rs1, rs2 } if a_rd != 0 && alu_uses_ld(rs1, rs2) => {
                        ld_add_any += 1
                    }
                    Inst::Xor { rd: a_rd, rs1, rs2 } if a_rd != 0 && alu_uses_ld(rs1, rs2) => {
                        ld_xor_any += 1
                    }
                    Inst::Or { rd: a_rd, rs1, rs2 } if a_rd != 0 && alu_uses_ld(rs1, rs2) => {
                        ld_or_any += 1
                    }
                    Inst::And { rd: a_rd, rs1, rs2 } if a_rd != 0 && alu_uses_ld(rs1, rs2) => {
                        ld_and_any += 1
                    }
                    _ => {}
                }
            }
        }
        prev = Some(inst);
        pc += len as usize;
    }

    let mut singles: Vec<(&&'static str, &usize)> = single.iter().collect();
    singles.sort_by(|a, b| b.1.cmp(a.1));
    let mut pairs: Vec<(&(&'static str, &'static str), &usize)> = chained_pairs.iter().collect();
    pairs.sort_by(|a, b| b.1.cmp(a.1));

    println!(
        "=== {} (total={}, lui+addi chained={}, {:.2}%) ===",
        name,
        total,
        lui_addi,
        100.0 * lui_addi as f64 / total as f64
    );
    let pct = |c: usize| 100.0 * c as f64 / total as f64;
    println!(
        "  fusion-precise: lui+add(same-rd)={:>4} ({:.2}%); ld+add={:>4} ({:.2}%); ld+xor={:>3} ({:.2}%); ld+or={:>3} ({:.2}%); ld+and={:>3} ({:.2}%)",
        lui_add_same_rd,
        pct(lui_add_same_rd),
        ld_add_any,
        pct(ld_add_any),
        ld_xor_any,
        pct(ld_xor_any),
        ld_or_any,
        pct(ld_or_any),
        ld_and_any,
        pct(ld_and_any),
    );
    println!("  top single variants:");
    for (n, c) in singles.iter().take(10) {
        println!(
            "    {:<12} {:>6}  {:>5.2}%",
            n,
            c,
            100.0 * **c as f64 / total as f64
        );
    }
    println!("  top chained pairs (prev.dst == this.rs1):");
    for ((p, q), c) in pairs.iter().take(10) {
        println!(
            "    {:<12} -> {:<12} {:>5}  {:>5.2}%",
            p,
            q,
            c,
            100.0 * **c as f64 / total as f64
        );
    }
    println!();
}

macro_rules! workload {
    ($name:literal, $env:literal) => {
        profile_one($name, include_bytes!(env!($env)));
    };
}

fn main() {
    println!("PVM2 RV opcode + chained-pair frequency profile");
    println!();
    workload!("ed25519", "ED25519_BLOB");
    workload!("ecrecover", "ECRECOVER_BLOB");
    workload!("blake2b", "BLAKE2B_BLOB");
    workload!("keccak", "KECCAK_BLOB");
    workload!("poseidon2_perm", "POSEIDON2_PERM_BLOB");
    workload!("mini_verifier", "MINI_VERIFIER_BLOB");
    workload!("fri_fold_tree", "FRI_FOLD_TREE_BLOB");
}
