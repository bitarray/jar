//! `ExitReason`: terminal status from an execution batch.
//!
//! The interpreter / recompiler run until one of these reasons is
//! produced. The caller decides what to do next (handle the host
//! call, route the page fault, top up gas and continue, etc.).

/// Terminal status from a single `execute()` call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitReason {
    /// Normal halt (program executed a halt opcode).
    Halt,
    /// Deliberate trap (opcode 0). Program-initiated termination.
    Trap,
    /// Runtime error: invalid opcode, bad dynamic jump, etc.
    Panic,
    /// Gas counter reached zero mid-execution.
    OutOfGas,
    /// Memory access at a page the address space doesn't map.
    /// The argument is the page-aligned faulting address.
    PageFault(u32),
    /// Host-call with the given opcode (the integration layer
    /// supplies an `EcallHandler` that interprets the opcode).
    HostCall(u32),
    /// PVM `ecall` (opcode 3, no immediate). The recompiler-side
    /// counterpart to the interpreter's EcallKind::Ecall routing.
    /// In the kernel, the integration layer reads φ\[11\] (mgmt op)
    /// and φ\[12\] (subject|object) to dispatch; the bench harness
    /// loops on this to skip the prologue's MGMT_MAP calls.
    Ecall,
}
