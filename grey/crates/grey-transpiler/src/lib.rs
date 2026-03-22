//! RISC-V ELF to JAM PVM transpiler.
//!
//! Converts RISC-V rv64em ELF binaries into PVM program blobs
//! suitable for execution by the Grey PVM (Appendix A).
//!
//! Also provides utilities to hand-assemble PVM programs directly.

pub mod riscv;
pub mod emitter;
pub mod assembler;
pub mod linker;

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
    "/../../services/sample-service/target/riscv64em-javm/release/sample-service.elf"
);

/// Path to the pre-compiled pixels service ELF.
pub const PIXELS_SERVICE_ELF_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../services/pixels-service/target/riscv64em-javm/release/pixels-service.elf"
);

/// Path to the pre-compiled pixels authorizer ELF.
pub const PIXELS_AUTHORIZER_ELF_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../services/pixels-authorizer/target/riscv64em-javm/release/pixels-authorizer.elf"
);

/// Link a RISC-V rv64em ELF binary into a PVM standard program blob.
pub fn link_elf(elf_data: &[u8]) -> Result<Vec<u8>, TranspileError> {
    linker::link_elf(elf_data)
}

/// Link a RISC-V rv64em ELF binary into a JAM service PVM blob.
pub fn link_elf_service(elf_data: &[u8]) -> Result<Vec<u8>, TranspileError> {
    linker::link_elf_service(elf_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_sample_elf() -> Vec<u8> {
        std::fs::read(SAMPLE_SERVICE_ELF_PATH)
            .expect("sample service ELF not found — build with: cd services/sample-service && cargo +nightly build --release --target ../riscv64em-javm.json -Zbuild-std=core -Zjson-target-spec")
    }

    #[test]
    fn test_link_sample_service() {
        let elf_data = load_sample_elf();
        let blob = link_elf_service(&elf_data).unwrap();
        assert!(!blob.is_empty());

        let pvm = javm::program::initialize_program(&blob, &[], 10_000);
        assert!(pvm.is_some(), "linked service blob should be loadable by PVM");
    }

    #[test]
    fn test_linked_service_refine_halts() {
        let elf_data = load_sample_elf();
        let blob = link_elf_service(&elf_data).unwrap();

        let mut pvm = javm::program::initialize_program(&blob, &[], 10_000)
            .expect("blob should be loadable");

        let (result, _gas) = pvm.run();
        assert!(
            result == javm::vm::ExitReason::Halt || result == javm::vm::ExitReason::Panic,
            "refine should halt or panic (ret with RA=0); got {:?}", result
        );
    }

    #[test]
    fn test_linked_service_accumulate_host_write() {
        let elf_data = load_sample_elf();
        let blob = link_elf_service(&elf_data).unwrap();

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
