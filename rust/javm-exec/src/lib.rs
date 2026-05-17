#![cfg_attr(not(feature = "std"), no_std)]

//! JAR v3 execution engine.
//!
//! Pure PVM execution: interpreter, recompiler (JIT), memory pages,
//! gas metering, registers, ExitReason, and an `EcallHandler` trait
//! that abstracts the ecall ABI from the engine.
//!
//! No knowledge of capabilities or caps. The execution engine knows
//! it has registers, memory pages, gas budget, and an opaque ecall
//! number; the caller (the `javm` integration crate) supplies the
//! `EcallHandler` that interprets ecall numbers as MGMT operations,
//! host-call selectors, etc.
//!
//! Cherry-picked from v2 `javm/src/{interpreter,recompiler,memory,
//! gas}` with cap-aware code stripped. See
//! `~/docs/minimum-v3/implementation/architecture.md` for the
//! layering.

#[macro_use]
extern crate alloc;

pub mod args;
pub mod decode;
pub mod ecall;
pub mod error;
pub mod exit;
pub mod gas;
pub mod gas_cost;
pub mod gas_sim;
pub mod instruction;
pub mod interp;
pub mod mem;
pub mod predecoded;
pub mod program;
pub mod regs;

pub use decode::{DecodedInst, Predecoded, predecode};
pub use ecall::{EcallHandler, EcallKind, EcallResult, PanickingHandler};
pub use error::ProgramError;
pub use exit::ExitReason;
pub use gas::{Gas, GasCounter, OutOfGas};
pub use instruction::{InstructionCategory, Opcode, decode_opcode_fast};
pub use interp::Interpreter;
pub use mem::{Access, CopyingMemory, MapError, Mem, MemAccess, Memory, PAGE_SIZE, perm};
pub use program::{PvmProgram, compute_mem_cycles, unpack_bitmask};
pub use regs::{REG_COUNT, Regs};
