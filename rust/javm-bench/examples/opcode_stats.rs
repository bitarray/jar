//! Image-size and opcode-frequency statistics for every bench guest.
//!
//! For each of the 12 bench workloads (pvm_bench + stark_bench + sub_vm),
//! report:
//!
//!   - Total wire-format Image size (SSZ-encoded blob length).
//!   - Code / packed-bitmask / jump-table byte breakdown.
//!   - Static instruction count (number of opcodes in the code stream).
//!   - Average bytes per static instruction.
//!   - Per-opcode static frequency (count + % of static insns).
//!
//! Both per-workload and aggregated-across-all-workloads outputs are
//! printed. Used to inform the PVM2 encoding design — confirms which
//! opcodes earn their slot and which are rarely used.
//!
//! Linux x86-64 only (matches the bench harness).
//!
//! Run with:
//! ```
//! cargo run --release -p javm-bench --example opcode_stats
//! ```

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    eprintln!("opcode_stats is Linux x86-64 only");
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() {
    linux_x86_64::main();
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_x86_64 {
    use javm_cap::image::Image;
    use javm_exec::instruction::Opcode;
    use javm_exec::unpack_bitmask;
    use ssz::Decode;
    use std::collections::BTreeMap;

    struct WorkloadStats {
        name: &'static str,
        image_bytes: usize,
        code_bytes: usize,
        bitmask_bytes_packed: usize,
        jump_table_bytes: usize,
        insn_count: usize,
        insn_bytes_total: usize,
        /// opcode byte → count
        opcode_hist: BTreeMap<u8, usize>,
        /// invalid-opcode byte → count (should be 0 for valid programs)
        unknown_hist: BTreeMap<u8, usize>,
        /// category (Debug string) → count
        category_hist: BTreeMap<String, usize>,
    }

    fn opcode_name(op: u8) -> String {
        match Opcode::from_byte(op) {
            Some(o) => format!("{o:?}"),
            None => format!("UNKNOWN({op})"),
        }
    }

    fn compute_skip(pc: usize, bitmask: &[u8]) -> usize {
        for j in 0..25 {
            let idx = pc + 1 + j;
            let bit = if idx < bitmask.len() { bitmask[idx] } else { 1 };
            if bit == 1 {
                return j;
            }
        }
        24
    }

    fn analyze(name: &'static str, blob: &[u8]) -> WorkloadStats {
        let image = Image::from_ssz_bytes(blob).unwrap_or_else(|e| {
            panic!("[{name}] decode Image: {e:?}");
        });
        let code = image.code.as_slice();
        let bitmask = unpack_bitmask(&image.packed_bitmask, code.len());

        let mut opcode_hist: BTreeMap<u8, usize> = BTreeMap::new();
        let mut unknown_hist: BTreeMap<u8, usize> = BTreeMap::new();
        let mut category_hist: BTreeMap<String, usize> = BTreeMap::new();
        let mut insn_count = 0usize;
        let mut insn_bytes_total = 0usize;

        let mut pc = 0usize;
        while pc < code.len() {
            // Skip non-opcode bytes (continuation bytes within an instruction).
            if pc < bitmask.len() && bitmask[pc] != 1 {
                pc += 1;
                continue;
            }
            let byte = code[pc];
            match Opcode::from_byte(byte) {
                Some(op) => {
                    *opcode_hist.entry(byte).or_default() += 1;
                    *category_hist
                        .entry(format!("{:?}", op.category()))
                        .or_default() += 1;
                }
                None => {
                    *unknown_hist.entry(byte).or_default() += 1;
                }
            }
            insn_count += 1;

            let skip = compute_skip(pc, &bitmask);
            let insn_len = 1 + skip;
            insn_bytes_total += insn_len;
            pc += insn_len;
        }

        WorkloadStats {
            name,
            image_bytes: blob.len(),
            code_bytes: code.len(),
            bitmask_bytes_packed: image.packed_bitmask.len(),
            jump_table_bytes: image.jump_table.len() * core::mem::size_of::<u32>(),
            insn_count,
            insn_bytes_total,
            opcode_hist,
            unknown_hist,
            category_hist,
        }
    }

    fn print_workload_summary(s: &WorkloadStats) {
        let bytes_per_insn = if s.insn_count > 0 {
            s.insn_bytes_total as f64 / s.insn_count as f64
        } else {
            0.0
        };
        println!(
            "{:<22} | image={:>7} code={:>7} bitmask={:>6} jt={:>6} | insns={:>6} bytes/insn={:.2}",
            s.name,
            s.image_bytes,
            s.code_bytes,
            s.bitmask_bytes_packed,
            s.jump_table_bytes,
            s.insn_count,
            bytes_per_insn,
        );
    }

    fn print_opcode_hist(label: &str, hist: &BTreeMap<u8, usize>, total: usize, top_n: usize) {
        let mut entries: Vec<(u8, usize)> = hist.iter().map(|(&k, &v)| (k, v)).collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        println!("\n{label} — top {top_n} opcodes (total static insns = {total}):");
        println!("  {:<5} {:<22} {:>10} {:>8}", "byte", "name", "count", "%");
        for (op, count) in entries.iter().take(top_n) {
            let pct = if total > 0 {
                100.0 * (*count as f64) / (total as f64)
            } else {
                0.0
            };
            println!(
                "  {:>5} {:<22} {:>10} {:>7.2}%",
                op,
                opcode_name(*op),
                count,
                pct,
            );
        }
        if entries.len() > top_n {
            let tail_count: usize = entries.iter().skip(top_n).map(|(_, c)| c).sum();
            let pct = if total > 0 {
                100.0 * (tail_count as f64) / (total as f64)
            } else {
                0.0
            };
            println!(
                "  ... {} more opcodes accounting for {} ({:.2}%)",
                entries.len() - top_n,
                tail_count,
                pct,
            );
        }
    }

    fn print_category_hist(hist: &BTreeMap<String, usize>, total: usize) {
        let mut entries: Vec<(String, usize)> = hist.iter().map(|(k, &v)| (k.clone(), v)).collect();
        entries.sort_by_key(|e| core::cmp::Reverse(e.1));
        println!("\nBy instruction category:");
        for (cat, count) in &entries {
            let pct = if total > 0 {
                100.0 * (*count as f64) / (total as f64)
            } else {
                0.0
            };
            println!("  {:<22} {:>10} {:>7.2}%", cat, count, pct);
        }
    }

    fn aggregate(per_wl: &[WorkloadStats]) -> WorkloadStats {
        let mut agg = WorkloadStats {
            name: "AGGREGATE",
            image_bytes: 0,
            code_bytes: 0,
            bitmask_bytes_packed: 0,
            jump_table_bytes: 0,
            insn_count: 0,
            insn_bytes_total: 0,
            opcode_hist: BTreeMap::new(),
            unknown_hist: BTreeMap::new(),
            category_hist: BTreeMap::new(),
        };
        for s in per_wl {
            agg.image_bytes += s.image_bytes;
            agg.code_bytes += s.code_bytes;
            agg.bitmask_bytes_packed += s.bitmask_bytes_packed;
            agg.jump_table_bytes += s.jump_table_bytes;
            agg.insn_count += s.insn_count;
            agg.insn_bytes_total += s.insn_bytes_total;
            for (k, v) in &s.opcode_hist {
                *agg.opcode_hist.entry(*k).or_default() += v;
            }
            for (k, v) in &s.unknown_hist {
                *agg.unknown_hist.entry(*k).or_default() += v;
            }
            for (k, v) in &s.category_hist {
                *agg.category_hist.entry(k.clone()).or_default() += v;
            }
        }
        agg
    }

    /// Print which valid opcodes have ZERO uses across all measured workloads.
    /// These are candidates for removal in a PVM2 encoding redesign.
    fn print_unused_opcodes(agg_hist: &BTreeMap<u8, usize>) {
        let all_valid_opcodes: &[u8] = &[
            0, 1, 2, 3, 10, 20, 30, 31, 32, 33, 40, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
            62, 70, 71, 72, 73, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 100, 101, 102, 103,
            104, 105, 106, 107, 108, 109, 110, 111, 120, 121, 122, 123, 124, 125, 126, 127, 128,
            129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145,
            146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 170,
            171, 172, 173, 174, 175, 180, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200,
            201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217,
            218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230,
        ];
        let unused: Vec<u8> = all_valid_opcodes
            .iter()
            .copied()
            .filter(|op| !agg_hist.contains_key(op))
            .collect();
        println!(
            "\nUnused opcodes ({} of {} valid PVM opcodes have zero static uses across all benches):",
            unused.len(),
            all_valid_opcodes.len(),
        );
        for op in &unused {
            println!("  {:>5}  {}", op, opcode_name(*op));
        }
    }

    pub fn main() {
        let workloads: &[(&'static str, &[u8])] = &[
            ("prime_sieve", include_bytes!(env!("PRIME_SIEVE_BLOB"))),
            ("ed25519", include_bytes!(env!("ED25519_BLOB"))),
            ("keccak", include_bytes!(env!("KECCAK_BLOB"))),
            ("blake2b", include_bytes!(env!("BLAKE2B_BLOB"))),
            ("ecrecover", include_bytes!(env!("ECRECOVER_BLOB"))),
            (
                "goldilocks_mul",
                include_bytes!(env!("GOLDILOCKS_MUL_BLOB")),
            ),
            (
                "poseidon2_perm",
                include_bytes!(env!("POSEIDON2_PERM_BLOB")),
            ),
            ("mini_verifier", include_bytes!(env!("MINI_VERIFIER_BLOB"))),
            ("poly_eval", include_bytes!(env!("POLY_EVAL_BLOB"))),
            ("fri_fold_tree", include_bytes!(env!("FRI_FOLD_TREE_BLOB"))),
            (
                "sub_vm_recurse",
                include_bytes!(env!("SUB_VM_RECURSE_BLOB")),
            ),
            (
                "sub_vm_data_recurse",
                include_bytes!(env!("SUB_VM_DATA_RECURSE_BLOB")),
            ),
        ];

        let stats: Vec<WorkloadStats> = workloads.iter().map(|(n, b)| analyze(n, b)).collect();

        println!("=== Per-workload size + instruction count ===\n");
        println!(
            "{:<22} | {:>7} {:>7} {:>6} {:>6} | {:>6} {:>9}",
            "workload", "image", "code", "bitmsk", "jt", "insns", "B/insn"
        );
        println!("{}", "-".repeat(96));
        for s in &stats {
            print_workload_summary(s);
        }

        let agg = aggregate(&stats);
        println!("{}", "-".repeat(96));
        print_workload_summary(&agg);

        // Aggregate-level histograms (most informative for design decisions).
        print_category_hist(&agg.category_hist, agg.insn_count);
        print_opcode_hist("AGGREGATE", &agg.opcode_hist, agg.insn_count, 30);
        print_unused_opcodes(&agg.opcode_hist);

        if !agg.unknown_hist.is_empty() {
            println!("\nWARNING: invalid opcode bytes found in code stream:");
            for (op, count) in &agg.unknown_hist {
                println!("  byte {op} → {count} occurrences");
            }
        }
    }
}
