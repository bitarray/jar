//! RISC-V ELF to JAM PVM transpiler.
//!
//! Converts RISC-V rv32em/rv64em ELF binaries into PVM program blobs
//! suitable for execution by the Grey PVM (Appendix A of the Gray Paper).
//!
//! Also provides utilities to hand-assemble PVM programs directly.

pub mod elf;
pub mod riscv;
pub mod emitter;
pub mod assembler;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum TranspileError {
    #[error("ELF parse error: {0}")]
    ElfParse(String),
    #[error("unsupported RISC-V instruction at offset {offset:#x}: {detail}")]
    UnsupportedInstruction { offset: usize, detail: String },
    #[error("unsupported relocation: {0}")]
    UnsupportedRelocation(String),
    #[error("register mapping error: RISC-V register {0} has no PVM equivalent")]
    RegisterMapping(u8),
    #[error("code too large: {0} bytes")]
    CodeTooLarge(usize),
    #[error("invalid section: {0}")]
    InvalidSection(String),
}

/// Path to the pre-compiled sample service ELF.
pub const SAMPLE_SERVICE_ELF_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../services/sample-service/target/riscv32im-unknown-none-elf/release/sample-service"
);

/// Path to the pre-compiled pixels service ELF.
pub const PIXELS_SERVICE_ELF_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../services/pixels-service/target/riscv32im-unknown-none-elf/release/pixels-service"
);

/// Path to the pre-compiled pixels authorizer ELF.
pub const PIXELS_AUTHORIZER_ELF_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../services/pixels-authorizer/target/riscv32im-unknown-none-elf/release/pixels-authorizer"
);

/// Transpile a RISC-V ELF binary into a PVM standard program blob.
///
/// The ELF must target rv32em or rv64em with no_std.
/// Returns the complete blob ready for `initialize_program()`.
pub fn transpile_elf(elf_data: &[u8]) -> Result<Vec<u8>, TranspileError> {
    let elf = elf::Elf::parse(elf_data)?;
    let mut ctx = riscv::TranslationContext::new(elf.is_64bit);

    for section in &elf.code_sections {
        ctx.translate_section(&section.data, section.address)?;
    }

    Ok(emitter::build_standard_program(
        &elf.ro_data,
        &elf.rw_data,
        elf.heap_pages,
        elf.stack_size,
        &ctx.code,
        &ctx.bitmask,
        &ctx.jump_table,
    ))
}

/// Transpile a RISC-V ELF binary into a JAM service PVM blob.
///
/// A JAM service has two entry points:
/// - PC=0: refine (called via `_start` / `refine` symbol)
/// - PC=5: accumulate (called via `accumulate` symbol)
///
/// The generated PVM code has a dispatch header:
/// - Bytes 0-4: `jump <refine_code>` (opcode 40 + 4-byte target)
/// - Bytes 5-9: `jump <accumulate_code>` (opcode 40 + 4-byte target)
/// - Bytes 10+: translated RISC-V code
///
/// The ELF must export `refine` (or `_start`) and `accumulate` symbols.
pub fn transpile_elf_service(elf_data: &[u8]) -> Result<Vec<u8>, TranspileError> {
    let elf = elf::Elf::parse(elf_data)?;

    // Find entry point symbols
    let refine_addr = elf.symbol_address("refine")
        .or_else(|| elf.symbol_address("_start"))
        .ok_or_else(|| TranspileError::InvalidSection(
            "no 'refine' or '_start' symbol found".into()
        ))?;

    let accumulate_addr = elf.symbol_address("accumulate")
        .ok_or_else(|| TranspileError::InvalidSection(
            "no 'accumulate' symbol found".into()
        ))?;

    let mut ctx = riscv::TranslationContext::new(elf.is_64bit);

    // Reserve 10 bytes for dispatch header (2 x jump instructions)
    let header_size = 10u32;
    for _ in 0..header_size {
        ctx.code.push(0);
        ctx.bitmask.push(0);
    }
    ctx.bitmask[0] = 1; // jump at byte 0
    ctx.bitmask[5] = 1; // jump at byte 5

    for section in &elf.code_sections {
        ctx.translate_section(&section.data, section.address)?;
    }

    // Resolve entry points to PVM offsets
    let refine_pvm = ctx.address_map.get(&refine_addr)
        .copied()
        .ok_or_else(|| TranspileError::InvalidSection(
            format!("refine symbol at {:#x} not in translated code", refine_addr)
        ))?;

    let accumulate_pvm = ctx.address_map.get(&accumulate_addr)
        .copied()
        .ok_or_else(|| TranspileError::InvalidSection(
            format!("accumulate symbol at {:#x} not in translated code", accumulate_addr)
        ))?;

    // Patch dispatch header: jump to refine at byte 0, jump to accumulate at byte 5
    // PVM jump offset is PC-relative: target = pc + imm, so imm = target - pc
    ctx.code[0] = 40; // jump opcode
    let refine_rel = (refine_pvm as i32) - 0; // pc=0
    ctx.code[1..5].copy_from_slice(&refine_rel.to_le_bytes());

    ctx.code[5] = 40; // jump opcode
    let acc_rel = (accumulate_pvm as i32) - 5; // pc=5
    ctx.code[6..10].copy_from_slice(&acc_rel.to_le_bytes());

    Ok(emitter::build_standard_program(
        &elf.ro_data,
        &elf.rw_data,
        elf.heap_pages,
        elf.stack_size,
        &ctx.code,
        &ctx.bitmask,
        &ctx.jump_table,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_sample_elf() -> Vec<u8> {
        std::fs::read(SAMPLE_SERVICE_ELF_PATH)
            .expect("sample service ELF not found — run: cd services/sample-service && cargo build --release --target riscv32im-unknown-none-elf")
    }

    #[test]
    fn test_elf_parse_sample_service() {
        let elf_data = load_sample_elf();
        let elf = elf::Elf::parse(&elf_data).unwrap();
        assert!(!elf.is_64bit);
        assert!(!elf.code_sections.is_empty());

        let refine = elf.symbol_address("refine");
        let accumulate = elf.symbol_address("accumulate");
        assert!(refine.is_some(), "refine symbol not found");
        assert!(accumulate.is_some(), "accumulate symbol not found");
    }

    #[test]
    fn test_transpile_sample_service() {
        let elf_data = load_sample_elf();
        let blob = transpile_elf_service(&elf_data).unwrap();
        assert!(!blob.is_empty());

        let pvm = javm::program::initialize_program(&blob, &[], 10_000);
        assert!(pvm.is_some(), "transpiled service blob should be loadable by PVM");
    }

    #[test]
    fn test_transpiled_service_refine_halts() {
        let elf_data = load_sample_elf();
        let blob = transpile_elf_service(&elf_data).unwrap();

        let mut pvm = javm::program::initialize_program(&blob, &[], 10_000)
            .expect("blob should be loadable");

        let (result, _gas) = pvm.run();
        assert_eq!(result, javm::vm::ExitReason::Halt,
            "refine should halt; got {:?}", result);
    }

    #[test]
    fn test_transpiled_service_accumulate_host_write() {
        let elf_data = load_sample_elf();
        let blob = transpile_elf_service(&elf_data).unwrap();

        let mut pvm = javm::program::initialize_program(&blob, &[], 10_000)
            .expect("blob should be loadable");
        pvm.pc = 5;

        let (result, _gas) = pvm.run();
        match result {
            javm::vm::ExitReason::HostCall(id) => {
                assert_eq!(id, 4, "expected host_write (ID=4), got ID={}", id);
            }
            other => panic!("expected HostCall(4), got {:?}", other),
        }
    }
}
