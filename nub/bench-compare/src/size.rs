//! Artifact size: how big the program is, as opposed to how fast it runs.
//!
//! Two figures per artifact, because one would hide things.
//!
//! **Whole blob** is the file on disk — what actually gets gossiped,
//! stored and paid for.
//!
//! **Raw code** excludes the data regions. It exists because several
//! kernels carry large initialized data that swamps the signal
//! completely: `prime-sieve` is 178 bytes of nub code inside a
//! 158,182-byte blob — 0.1%. A whole-blob comparison of that row
//! compares static lookup tables, not code generators.
//!
//! # What counts as code, per format
//!
//! | format | code figure |
//! |---|---|
//! | pvm2 | `code` |
//! | polkavm64 | `code` + jump table + bitmask |
//! | wasm32 | `Code`(10) + `Type`(1) + `Function`(3) + `Table`(4) + `Element`(9) + `Global`(6) |
//!
//! nub's is the whole story on its side: PVM2 is standard RV64EMC, and
//! a fixed-width self-delimiting encoding needs no side tables.
//!
//! PolkaVM's two extras are code information relocated *out* of the
//! instruction stream, so leaving them out would not be measuring the
//! same thing. Its instructions are variable-length, so the bitmask —
//! one bit per code byte, marking instruction starts — is what makes
//! the stream decodable at all; RISC-V encodes that inline in the low
//! two bits of each word. The jump table lists legal indirect-branch
//! targets, which `jalr rd, rs1, imm` simply takes from a register.
//! Note this is *broader* than upstream's own disassembler, which
//! labels only `code` as "code size" — hence the breakdown table, so
//! the definition is checkable rather than asserted.
//!
//! wasm's aux sections are the same argument: `Type`/`Function` hold
//! per-function signatures that the register machines encode implicitly
//! in their calling convention, and `Table`/`Element` are the direct
//! analogue of PolkaVM's jump table.
//!
//! All three figures are **payload bytes, excluding container framing**.
//! The breakdown tables' framing columns absorb the difference, and
//! every breakdown row sums to the file size.
//!
//! # No compression is involved, in any of the three
//!
//! There is nothing to disable. nub trims trailing zeros off `ro`/`rw`
//! (`nub_program::codec`) and PolkaVM stores only the initial non-zero
//! prefix of its data sections; both are BSS elision — exactly what ELF
//! does with `p_filesz < p_memsz` — and wasm data segments are
//! explicitly offset so they carry no trailing zeros either. No entropy
//! coder, dictionary or transform exists in any of these containers,
//! and `polkavm_linker::Config` has no compression knob at all.
//!
//! The varint/LEB128 encoding in PolkaVM and wasm is **instruction
//! encoding, not container compression**. It cannot be turned off —
//! there is no alternative encoding — and turning it off is not what
//! anyone would want anyway: it is precisely the axis these formats
//! trade on. PolkaVM buys small immediates with variable-length
//! instructions and pays a 12.5% bitmask; RISC-V pays fixed width and
//! needs no side table. Both are raw code.
//!
//! # Golden values
//!
//! Recorded rather than asserted: `artifacts/` is gitignored, so a
//! golden test could never run in CI, and these legitimately move with
//! the kernel sources, the inline threshold and the linkers. They are
//! here so a surprising diff is recognizable as one. Regenerate with
//! `cargo run --release -- size`.
//!
//! As of 2026-07-28, rustc 1.95.0:
//!
//! | program | pvm2 | polkavm64 | wasm32 |
//! |---|--:|--:|--:|
//! | goldilocks-mul | 126 | 138 | 346 |
//! | keccak | 1848 | 4551 | 2760 |
//! | blake2b | 6944 | 12453 | 6552 |
//! | ed25519 | 41406 | 53632 | 60116 |
//! | ecrecover | 96112 | 130599 | 82977 |
//! | prime-sieve | 178 | 168 | 318 |
//! | poly-eval | 766 | 1000 | 10885 |
//! | poseidon2-perm | 3368 | 4625 | 5183 |
//! | fri-fold-tree | 4134 | 6256 | 17178 |
//! | mini-verifier | 4246 | 6276 | 6659 |

use std::path::Path;

use anyhow::{bail, Result};

use crate::backend::{Family, SIZE_FAMILIES};

/// Byte counts for one artifact.
pub struct Sizes {
    /// The file on disk.
    pub file: u64,
    /// The raw-code figure for this family — see the module docs.
    pub code: u64,
    /// Every component, in table order. Sums to `file`.
    pub parts: Vec<(&'static str, u64)>,
}

impl Sizes {
    fn part(&self, name: &str) -> u64 {
        self.parts
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    }

    /// Every container must account for every byte. A walk that ends
    /// anywhere but the end of the file means the parser is wrong, and
    /// a wrong parser that still prints a plausible number is the
    /// failure mode worth engineering against.
    fn check(self, what: &str) -> Result<Self> {
        let sum: u64 = self.parts.iter().map(|(_, v)| *v).sum();
        if sum != self.file {
            bail!(
                "{what}: components sum to {sum} but the file is {} bytes",
                self.file
            );
        }
        Ok(self)
    }
}

/// Parse one artifact's container. Never decodes instructions.
pub fn measure(bytes: &[u8], family: Family) -> Result<Sizes> {
    match family {
        Family::Pvm2 => nub(bytes),
        Family::Polkavm64 => polkavm(bytes),
        Family::Wasm32 => wasm(bytes),
        Family::Native => bail!("native artifacts have no comparable size figure"),
    }
}

// ---- pvm2 -------------------------------------------------------------

/// `magic|version|flags|stack|ro|rw|heap|code_len|ro_len|rw_len|n_endpoints`
const NUB_HEADER: usize = 40;

fn u32_at(bytes: &[u8], off: usize) -> Result<u64> {
    let raw = bytes
        .get(off..off + 4)
        .ok_or_else(|| anyhow::anyhow!("truncated at offset {off}"))?;
    Ok(u32::from_le_bytes(raw.try_into().unwrap()) as u64)
}

fn nub(bytes: &[u8]) -> Result<Sizes> {
    if bytes.get(..4) != Some(b"NUBP") {
        bail!("not a nub program blob (bad magic)");
    }
    // The on-disk lengths come from the header, NOT from the decoded
    // blob. `from_bytes` zero-extends `ro`/`rw` back to
    // `pages * PAGE_SIZE`, so `blob.ro_data.len()` is the in-memory
    // size and will not reconcile against the file.
    let code_len = u32_at(bytes, 24)?;
    let ro_len = u32_at(bytes, 28)?;
    let rw_len = u32_at(bytes, 32)?;
    let endpoint_count = u32_at(bytes, 36)?;

    // Endpoint records are variable-length: 12 bytes plus 16 per
    // seeded register.
    let mut off = NUB_HEADER;
    for _ in 0..endpoint_count {
        let reg_count = *bytes
            .get(off + 3)
            .ok_or_else(|| anyhow::anyhow!("truncated endpoint record"))?
            as usize;
        off += 12 + reg_count * 16;
    }
    let endpoints = (off - NUB_HEADER) as u64;

    Sizes {
        file: bytes.len() as u64,
        code: code_len,
        parts: vec![
            ("header", NUB_HEADER as u64),
            ("endpoints", endpoints),
            ("code", code_len),
            ("ro", ro_len),
            ("rw", rw_len),
        ],
    }
    .check("pvm2")
}

// ---- polkavm64 --------------------------------------------------------

const PVM_HEADER: usize = 13;
const SECTION_MEMORY_CONFIG: u8 = 1;
const SECTION_RO_DATA: u8 = 2;
const SECTION_RW_DATA: u8 = 3;
const SECTION_EXPORTS: u8 = 5;
const SECTION_CODE_AND_JUMP_TABLE: u8 = 6;
const SECTION_END: u8 = 0;

/// PolkaVM's varint — **not LEB128**.
///
/// The count of leading one-bits in the first byte gives how many extra
/// little-endian bytes follow; the first byte's remaining low bits are
/// the value's *high* bits. Decoding it as LEB128 silently yields wrong
/// answers for every value >= 128, i.e. for every real artifact, while
/// still producing plausible-looking numbers — so this has its own
/// test.
fn pvm_varint(bytes: &[u8], i: usize) -> Result<(u64, usize)> {
    let first = *bytes
        .get(i)
        .ok_or_else(|| anyhow::anyhow!("truncated varint"))?;
    let extra = first.leading_ones().min(4) as usize;
    let upper = if extra >= 4 {
        0
    } else {
        u64::from(first) & ((1u64 << (8 - extra - 1)) - 1)
    };
    let mut value = 0u64;
    for k in 0..extra {
        let b = *bytes
            .get(i + 1 + k)
            .ok_or_else(|| anyhow::anyhow!("truncated varint"))?;
        value |= u64::from(b) << (8 * k);
    }
    value |= upper << (8 * extra);
    Ok((value, i + 1 + extra))
}

fn polkavm(bytes: &[u8]) -> Result<Sizes> {
    if bytes.get(..4) != Some(b"PVM\0") {
        bail!("not a polkavm blob (bad magic)");
    }
    let declared = u64::from_le_bytes(
        bytes
            .get(5..13)
            .ok_or_else(|| anyhow::anyhow!("truncated header"))?
            .try_into()
            .unwrap(),
    );
    if declared != bytes.len() as u64 {
        bail!("header says {declared} bytes, file is {}", bytes.len());
    }

    let (mut code, mut jump_table, mut bitmask, mut framing) = (0u64, 0u64, 0u64, 0u64);
    let (mut ro, mut rw, mut exports, mut memcfg, mut other) = (0u64, 0u64, 0u64, 0u64, 0u64);

    let mut i = PVM_HEADER;
    loop {
        let id = *bytes
            .get(i)
            .ok_or_else(|| anyhow::anyhow!("truncated section id"))?;
        i += 1;
        if id == SECTION_END {
            break;
        }
        let (len, next) = pvm_varint(bytes, i)?;
        i = next;
        let payload = bytes
            .get(i..i + len as usize)
            .ok_or_else(|| anyhow::anyhow!("truncated section {id}"))?;

        match id {
            SECTION_CODE_AND_JUMP_TABLE => {
                // varint entry_count | u8 entry_size | varint code_len
                let (entry_count, j) = pvm_varint(payload, 0)?;
                let entry_size = *payload
                    .get(j)
                    .ok_or_else(|| anyhow::anyhow!("truncated jump-table header"))?
                    as u64;
                let (code_len, j) = pvm_varint(payload, j + 1)?;
                framing = j as u64;
                jump_table = entry_count
                    .checked_mul(entry_size)
                    .ok_or_else(|| anyhow::anyhow!("jump table size overflow"))?;
                code = code_len;
                bitmask = len
                    .checked_sub(framing + jump_table + code)
                    .ok_or_else(|| anyhow::anyhow!("section 6 shorter than its parts"))?;
                // Independent cross-check: the bitmask is exactly one
                // bit per code byte. Misread `entry_size` and this
                // fires immediately, which is the whole point of
                // checking it rather than trusting the subtraction.
                let expect = code.div_ceil(8);
                if bitmask != expect {
                    bail!("bitmask is {bitmask} bytes, expected {expect} for {code} bytes of code");
                }
            }
            SECTION_RO_DATA => ro += len,
            SECTION_RW_DATA => rw += len,
            SECTION_EXPORTS => exports += len,
            SECTION_MEMORY_CONFIG => memcfg += len,
            // `SECTION_IMPORTS`, the optional debug/metadata sections
            // (ids >= 128, absent because the linker strips), and
            // anything a future version adds. Never an error:
            // surfacing an unexpected section as a number is more
            // useful than refusing to measure.
            _ => other += len,
        }
        i += len as usize;
    }
    if i != bytes.len() {
        bail!("walk ended at {i}, file is {} bytes", bytes.len());
    }

    // Framing: the fixed header, each section's (id, varint len), and
    // the one-byte terminator. Whatever the components do not account
    // for is exactly that.
    let accounted = code + jump_table + bitmask + framing + ro + rw + exports + memcfg + other;
    let container = bytes.len() as u64 - accounted;

    Sizes {
        file: bytes.len() as u64,
        code: code + jump_table + bitmask,
        parts: vec![
            ("code", code),
            ("jump table", jump_table),
            ("bitmask", bitmask),
            ("§6 framing", framing),
            ("ro", ro),
            ("rw", rw),
            ("exports", exports),
            ("memory cfg", memcfg),
            ("other", other),
            ("container", container),
        ],
    }
    .check("polkavm64")
}

// ---- wasm32 -----------------------------------------------------------

const WASM_HEADER: usize = 8;
const WASM_CUSTOM: u8 = 0;
const WASM_DATA: u8 = 11;

/// Sections counted as code, each with its breakdown-column label.
///
/// Listed individually rather than summed into one bucket so the
/// breakdown table shows every contributor — the code figure here is a
/// sum of six sections, and a reader should be able to check it rather
/// than take it on trust.
const WASM_CODE_SECTIONS: [(u8, &str); 6] = [
    (10, "code(10)"),
    (1, "type(1)"),
    (3, "function(3)"),
    (4, "table(4)"),
    (9, "element(9)"),
    (6, "global(6)"),
];

fn leb128(bytes: &[u8], mut i: usize) -> Result<(u64, usize)> {
    let (mut value, mut shift) = (0u64, 0u32);
    loop {
        let b = *bytes
            .get(i)
            .ok_or_else(|| anyhow::anyhow!("truncated LEB128"))?;
        i += 1;
        value |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok((value, i));
        }
        shift += 7;
        if shift > 63 {
            bail!("LEB128 too long");
        }
    }
}

fn wasm(bytes: &[u8]) -> Result<Sizes> {
    if bytes.get(..4) != Some(b"\0asm") {
        bail!("not a wasm module (bad magic)");
    }
    let mut per_code = [0u64; WASM_CODE_SECTIONS.len()];
    let (mut data, mut custom, mut other) = (0u64, 0u64, 0u64);
    let mut framing = 0u64;

    let mut i = WASM_HEADER;
    while i < bytes.len() {
        let start = i;
        let id = bytes[i];
        i += 1;
        let (len, next) = leb128(bytes, i)?;
        i = next;
        framing += (i - start) as u64;
        if bytes.len() < i + len as usize {
            bail!("truncated section {id}");
        }
        match WASM_CODE_SECTIONS.iter().position(|(s, _)| *s == id) {
            Some(k) => per_code[k] += len,
            None if id == WASM_DATA => data += len,
            None if id == WASM_CUSTOM => custom += len,
            // Memory, Export, Import, Start, DataCount, Tag, and
            // whatever a future proposal adds.
            None => other += len,
        }
        i += len as usize;
    }
    if i != bytes.len() {
        bail!("walk ended at {i}, file is {} bytes", bytes.len());
    }

    let mut parts: Vec<(&'static str, u64)> = WASM_CODE_SECTIONS
        .iter()
        .zip(per_code)
        .map(|((_, label), n)| (*label, n))
        .collect();
    parts.push(("data(11)", data));
    parts.push(("custom(0)", custom));
    parts.push(("other", other));
    parts.push(("container", WASM_HEADER as u64 + framing));

    Sizes {
        file: bytes.len() as u64,
        code: per_code.iter().sum(),
        parts,
    }
    .check("wasm32")
}

// ---- rendering --------------------------------------------------------

/// Thousands separators. Exact bytes throughout, never KiB: the
/// breakdown tables exist so a reader can check that a row sums, and
/// rounded units would break that.
fn commas(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// One row of the size section: the three families' figures for one
/// program, or the reason a family is missing.
struct Row {
    program: String,
    sizes: Vec<(Family, Result<Sizes>)>,
}

/// The whole `## Artifact size` section.
///
/// Infallible by construction: a missing or unparseable artifact
/// becomes a `-` cell, never an error, so adding this to `report`
/// cannot make `report` fail. Returns `""` when no artifact exists at
/// all.
pub fn render(root: &Path, programs: &[&str]) -> String {
    let mut rows: Vec<Row> = Vec::new();
    for program in programs {
        let mut sizes = Vec::new();
        for family in SIZE_FAMILIES {
            let path = family.artifact_path(root, program);
            if !path.exists() {
                continue;
            }
            let measured = std::fs::read(&path)
                .map_err(Into::into)
                .and_then(|bytes| measure(&bytes, family));
            sizes.push((family, measured));
        }
        if !sizes.is_empty() {
            rows.push(Row {
                program: (*program).to_string(),
                sizes,
            });
        }
    }
    if rows.is_empty() {
        return String::new();
    }

    let mut out = String::from("\n## Artifact size\n\n");
    out.push_str(
        "How big the program is, which for a chain VM is the other half of the \
         story — it is what gets gossiped, stored and paid for.\n\n\
         **Raw code excludes the data regions**, and that is the figure to read. \
         Several kernels carry large initialized data that swamps everything \
         else: `prime-sieve` is 178 bytes of nub code inside a 158,182-byte \
         blob, 0.1% of it. Comparing whole blobs there compares static lookup \
         tables, not code generators.\n\n\
         The code figure is `code` for nub, `code + jump table + bitmask` for \
         PolkaVM, and `Code + Type + Function + Table + Element + Global` for \
         wasm. PolkaVM's two extras and wasm's aux sections are code \
         information held *outside* the instruction stream — instruction \
         boundaries, indirect-branch targets, function signatures — all of \
         which RV64EMC encodes inline. The breakdown tables below show every \
         component so the definition can be checked rather than taken on \
         trust; note it is deliberately broader than upstream PolkaVM's own \
         disassembler, which labels only `code` as \"code size\".\n\n\
         `native` is absent: a host `.so` is a different kind of object — ELF \
         program headers, relocations, a dynamic symbol table, and whatever of \
         `std` got linked in — not a bigger or smaller one.\n\n\
         **No compression is involved anywhere.** Trailing-zero trimming in \
         nub and PolkaVM is BSS elision, exactly what ELF does with \
         `p_filesz < p_memsz`, and wasm data segments carry no trailing zeros \
         either. The varint/LEB128 encoding in PolkaVM and wasm is instruction \
         encoding, not a container compressor: it cannot be disabled, and it \
         is precisely the axis these formats trade on.\n\n",
    );

    out.push_str("### Raw code\n\n");
    out.push_str(&matrix(&rows, |s| s.code));
    out.push_str("\n### Whole blob\n\n");
    out.push_str(&matrix(&rows, |s| s.file));

    out.push_str("\n### Breakdown\n\n");
    out.push_str("Every row sums to the file size.\n");
    for family in SIZE_FAMILIES {
        out.push_str(&breakdown(&rows, family));
    }

    let failures: Vec<String> = rows
        .iter()
        .flat_map(|r| {
            r.sizes.iter().filter_map(move |(f, s)| {
                s.as_ref()
                    .err()
                    .map(|e| format!("- `{}` / `{}`: {e:#}\n", r.program, f.dir()))
            })
        })
        .collect();
    if !failures.is_empty() {
        out.push_str("\nUnparseable artifacts (shown as `-` above):\n\n");
        for f in &failures {
            out.push_str(f);
        }
    }
    out
}

/// A program × family matrix, cells `{bytes} ({ratio}x)`, smallest bold.
fn matrix(rows: &[Row], pick: impl Fn(&Sizes) -> u64) -> String {
    let mut out = String::from("| Program |");
    for f in SIZE_FAMILIES {
        out.push_str(&format!(" `{}` |", f.dir()));
    }
    out.push_str("\n|---|");
    for _ in SIZE_FAMILIES {
        out.push_str("--:|");
    }
    out.push('\n');

    for row in rows {
        out.push_str(&format!("| {} |", row.program));
        let best = row
            .sizes
            .iter()
            .filter_map(|(_, s)| s.as_ref().ok().map(&pick))
            .min()
            .unwrap_or(0);
        for family in SIZE_FAMILIES {
            match row.sizes.iter().find(|(f, _)| *f == family) {
                Some((_, Ok(s))) => {
                    let v = pick(s);
                    let mark = if v == best { "**" } else { "" };
                    let ratio = if best > 0 {
                        format!(" ({:.2}x)", v as f64 / best as f64)
                    } else {
                        String::new()
                    };
                    out.push_str(&format!(" {mark}{}{mark}{ratio} |", commas(v)));
                }
                _ => out.push_str(" - |"),
            }
        }
        out.push('\n');
    }
    out.push_str("\nBold = smallest for that program; the multiple is versus it.\n");
    out
}

/// One family's per-component table.
fn breakdown(rows: &[Row], family: Family) -> String {
    let cols: Vec<&'static str> = match rows
        .iter()
        .filter_map(|r| r.sizes.iter().find(|(f, _)| *f == family))
        .find_map(|(_, s)| s.as_ref().ok())
    {
        Some(s) => s.parts.iter().map(|(n, _)| *n).collect(),
        None => return String::new(),
    };

    let mut out = format!("\n#### `{}`\n\n| Program |", family.dir());
    for c in &cols {
        out.push_str(&format!(" {c} |"));
    }
    // The code figure is a sum of components for two of the three
    // families, so name it explicitly rather than leaving the reader to
    // add up columns.
    out.push_str(" = code | file |\n|---|");
    for _ in &cols {
        out.push_str("--:|");
    }
    out.push_str("--:|--:|\n");

    for row in rows {
        let Some((_, Ok(s))) = row.sizes.iter().find(|(f, _)| *f == family) else {
            continue;
        };
        out.push_str(&format!("| {} |", row.program));
        for c in &cols {
            out.push_str(&format!(" {} |", commas(s.part(c))));
        }
        out.push_str(&format!(" **{}** | {} |\n", commas(s.code), commas(s.file)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PolkaVM's varint is not LEB128 — the leading-ones count gives
    /// the extra byte count and the first byte's low bits are the
    /// value's *high* bits. A LEB128 implementation passes for values
    /// under 128 and silently diverges above, so test both sides.
    #[test]
    fn polkavm_varint_is_not_leb128() {
        // Single byte: no leading ones, value in the low 7 bits.
        assert_eq!(pvm_varint(&[0x00], 0).unwrap(), (0, 1));
        assert_eq!(pvm_varint(&[0x7f], 0).unwrap(), (127, 1));
        // One leading one => one extra byte; low 6 bits of the first
        // byte are the high bits.
        assert_eq!(pvm_varint(&[0x80, 0x80], 0).unwrap(), (128, 2));
        assert_eq!(pvm_varint(&[0x80, 0xff], 0).unwrap(), (255, 2));
        assert_eq!(pvm_varint(&[0x81, 0x00], 0).unwrap(), (256, 2));
        // Four leading ones => four extra bytes, first byte carries no
        // value bits.
        assert_eq!(
            pvm_varint(&[0xf0, 0x78, 0x56, 0x34, 0x12], 0).unwrap(),
            (0x1234_5678, 5)
        );
    }

    #[test]
    fn leb128_matches_spec() {
        assert_eq!(leb128(&[0x00], 0).unwrap(), (0, 1));
        assert_eq!(leb128(&[0x7f], 0).unwrap(), (127, 1));
        assert_eq!(leb128(&[0x80, 0x01], 0).unwrap(), (128, 2));
        assert_eq!(leb128(&[0xe5, 0x8e, 0x26], 0).unwrap(), (624_485, 3));
    }

    #[test]
    fn rejects_foreign_containers() {
        assert!(nub(b"PVM\0nope").is_err());
        assert!(polkavm(b"NUBPnope").is_err());
        assert!(wasm(b"NUBPnope").is_err());
    }

    /// Every artifact present must reconcile: the components have to
    /// account for every byte of the file.
    ///
    /// `artifacts/` is gitignored and nothing in it is tracked, so this
    /// skips rather than fails on a clean checkout or in CI.
    #[test]
    fn artifacts_reconcile() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut checked = 0;
        for family in SIZE_FAMILIES {
            let dir = root.join("artifacts").join(family.dir());
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some(family.ext()) {
                    continue;
                }
                let bytes = std::fs::read(&path).expect("read artifact");
                let sizes =
                    measure(&bytes, family).unwrap_or_else(|e| panic!("{}: {e:#}", path.display()));
                assert!(
                    sizes.code <= sizes.file,
                    "{}: code {} exceeds file {}",
                    path.display(),
                    sizes.code,
                    sizes.file
                );
                checked += 1;
            }
        }
        if checked == 0 {
            eprintln!("skipped: no artifacts built (run `cargo run -p bench-build --release`)");
        }
    }
}
