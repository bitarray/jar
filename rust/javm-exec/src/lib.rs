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

pub mod exit;
pub mod gas;
pub mod mem;
pub mod regs;

pub use exit::ExitReason;
pub use gas::{Gas, GasCounter, OutOfGas};
pub use mem::{Mem, MemAccess, PAGE_SIZE, Page, Perm};
pub use regs::{REG_COUNT, Regs};
