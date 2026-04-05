//! VM instance pool and state machine for the capability-based JAVM v2.
//!
//! Each VM has a state (Idle/Running/WaitingForReply/Halted/Faulted),
//! a cap table, register state, and a reference to its CODE cap.
//! Only IDLE VMs can be CALLed — this prevents reentrancy by construction.

use crate::PVM_REGISTER_COUNT;
use crate::cap::CapTable;

/// VM lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    /// Waiting for a CALL. Only state that accepts incoming calls.
    Idle,
    /// Currently executing PVM code.
    Running,
    /// Blocked at a CALL ecalli, waiting for the callee to reply.
    WaitingForReply,
    /// Clean exit (REPLY from root VM).
    Halted,
    /// Abnormal termination (panic, OOG, page fault).
    Faulted,
}

/// A single VM instance in the pool.
#[derive(Debug)]
pub struct VmInstance {
    /// Current lifecycle state.
    pub state: VmState,
    /// Index of the CODE cap this VM runs (in the kernel's code_caps list).
    pub code_cap_id: u16,
    /// PVM registers (13 × 64-bit).
    pub registers: [u64; PVM_REGISTER_COUNT],
    /// Program counter.
    pub pc: u32,
    /// Per-VM capability table.
    pub cap_table: CapTable,
    /// Who called this VM (for REPLY routing). None if called by kernel.
    pub caller: Option<u16>,
    /// Jump table entry index (used on first CALL).
    pub entry_index: u32,
    /// Gas remaining for this VM.
    pub gas: u64,
}

impl VmInstance {
    /// Create a new VM in IDLE state.
    pub fn new(code_cap_id: u16, entry_index: u32, cap_table: CapTable, gas: u64) -> Self {
        let registers = [0u64; PVM_REGISTER_COUNT];
        Self {
            state: VmState::Idle,
            code_cap_id,
            registers,
            pc: 0, // Will be set to jump_table[entry_index] on first CALL
            cap_table,
            caller: None,
            entry_index,
            gas,
        }
    }

    /// Transition to a new state. Returns error if the transition is invalid.
    pub fn transition(&mut self, new_state: VmState) -> Result<(), VmStateError> {
        use VmState::*;
        let valid = matches!(
            (self.state, new_state),
            (Idle, Running)
                | (Running, Idle) // REPLY
                | (Running, WaitingForReply) // CALL to another VM
                | (Running, Halted) // halt
                | (Running, Faulted) // panic/OOG/page fault
                | (WaitingForReply, Running) // callee replied, caller resumes
        );
        if !valid {
            return Err(VmStateError {
                from: self.state,
                to: new_state,
            });
        }
        self.state = new_state;
        Ok(())
    }

    /// Whether this VM can be CALLed.
    pub fn can_call(&self) -> bool {
        self.state == VmState::Idle
    }
}

/// Call frame saved on the kernel's call stack when a VM calls another.
#[derive(Debug)]
pub struct CallFrame {
    /// VM that initiated the CALL.
    pub caller_vm_id: u16,
    /// Cap slot in the caller that held the IPC DATA cap (for auto-return on REPLY).
    pub ipc_cap_idx: Option<u8>,
    /// If the IPC DATA cap was mapped, its original mapping state (for auto-remap on REPLY).
    pub ipc_was_mapped: Option<(u32, crate::cap::Access)>,
}

/// Errors from VM state transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmStateError {
    pub from: VmState,
    pub to: VmState,
}

impl core::fmt::Display for VmStateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "invalid VM state transition: {:?} -> {:?}",
            self.from, self.to
        )
    }
}

/// Maximum number of CODE caps per invocation.
pub const MAX_CODE_CAPS: usize = 5;

/// Maximum number of VMs (HANDLEs) per invocation.
pub const MAX_VMS: usize = 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_state_transitions() {
        let mut vm = VmInstance::new(0, 0, CapTable::new(), 1_000_000);
        assert_eq!(vm.state, VmState::Idle);
        assert!(vm.can_call());

        // Idle -> Running
        assert!(vm.transition(VmState::Running).is_ok());
        assert!(!vm.can_call());

        // Running -> WaitingForReply
        assert!(vm.transition(VmState::WaitingForReply).is_ok());
        assert!(!vm.can_call());

        // WaitingForReply -> Running (callee replied)
        assert!(vm.transition(VmState::Running).is_ok());

        // Running -> Idle (REPLY)
        assert!(vm.transition(VmState::Idle).is_ok());
        assert!(vm.can_call());
    }

    #[test]
    fn test_invalid_transitions() {
        let mut vm = VmInstance::new(0, 0, CapTable::new(), 1_000_000);

        // Idle -> WaitingForReply (invalid — must go through Running)
        assert!(vm.transition(VmState::WaitingForReply).is_err());

        // Idle -> Halted (invalid)
        assert!(vm.transition(VmState::Halted).is_err());

        vm.transition(VmState::Running).unwrap();
        vm.transition(VmState::Halted).unwrap();

        // Halted -> anything (terminal)
        assert!(vm.transition(VmState::Idle).is_err());
        assert!(vm.transition(VmState::Running).is_err());
    }

    #[test]
    fn test_vm_initial_registers() {
        let vm = VmInstance::new(0, 5, CapTable::new(), 1_000_000);
        assert_eq!(vm.registers[0], 0); // no halt address, all regs start at 0
        for i in 1..13 {
            assert_eq!(vm.registers[i], 0);
        }
        assert_eq!(vm.entry_index, 5);
    }

    #[test]
    fn test_faulted_is_terminal() {
        let mut vm = VmInstance::new(0, 0, CapTable::new(), 1_000_000);
        vm.transition(VmState::Running).unwrap();
        vm.transition(VmState::Faulted).unwrap();
        assert!(!vm.can_call());
        assert!(vm.transition(VmState::Idle).is_err());
    }
}
