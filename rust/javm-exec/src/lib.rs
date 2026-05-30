#![cfg_attr(not(feature = "std"), no_std)]

//! JAR v3 execution engine.
//!
//! Pure PVM2 (RV+C+Zbb+Zba+Zbs+Zicond+custom-0) execution:
//! interpreter, recompiler (JIT, lives in the `javm-recompiler-x86`
//! crate), memory pages, gas metering, registers, ExitReason, and an
//! `EcallHandler` trait that abstracts the ecall ABI from the engine.
//!
//! No knowledge of capabilities or caps. The execution engine knows
//! it has registers, memory pages, gas budget, and an opaque ecall
//! number; the caller (the `javm` integration crate) supplies the
//! `EcallHandler` that interprets ecall numbers as MGMT operations,
//! host-call selectors, etc.

#[macro_use]
extern crate alloc;

pub mod ecall;
pub mod exit;
pub mod gas;
pub mod gas_cost;
pub mod gas_sim;
pub mod instruction;
pub mod interp;
pub mod mem;
pub mod predecode;
pub mod regs;

pub use ecall::{EcallHandler, EcallKind, EcallResult, PanickingHandler};
pub use exit::ExitReason;
pub use gas::{Gas, GasCounter, OutOfGas};
pub use mem::{Access, CopyingMemory, MapError, Mem, MemAccess, Memory, PAGE_SIZE, perm};
pub use regs::{REG_COUNT, Regs};
