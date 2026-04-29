//! VM-execution abstraction + invocation driver.
//!
//! The kernel calls into a guest VM via the `VmExec` trait. The real impl
//! wraps `javm::InvocationKernel`; tests use `ScriptVm` to drive scripted
//! ProtocolCall sequences without compiling PVM blobs.
//!
//! `drive_invocation` runs the VM until Halt / Fault / OutOfGas, dispatching
//! every `ProtocolCall(slot)` via `host_calls::dispatch_host_call`.

use std::collections::VecDeque;

use jar_types::{Caller, Command, KResult, KernelError, KernelRole, StorageMode, VaultId};

use crate::attest::AttestCursor;
use crate::frame::Frame;
use crate::host_abi::HostCall;
use crate::reach::ReachSet;
use crate::runtime::Hardware;
use jar_types::AttestationEntry;
use jar_types::ResultEntry;
use jar_types::SlotContent;

/// Outcome of a single VM `run()` step.
#[derive(Debug)]
pub enum VmStep {
    Halt(u64),
    Fault(String),
    OutOfGas,
    ProtocolCall(u8),
}

/// Minimal abstraction over a running VM.
pub trait VmExec {
    fn step(&mut self) -> VmStep;
    fn resume(&mut self, r0: u64, r1: u64);
    fn reg(&self, idx: usize) -> u64;
    fn set_reg(&mut self, idx: usize, val: u64);
    fn read_mem(&self, addr: u32, len: u32) -> Option<Vec<u8>>;
    fn write_mem(&mut self, addr: u32, data: &[u8]) -> bool;
    fn gas(&self) -> u64;
}

/// Per-invocation kernel-side context. Carried by reference into every
/// host-call handler.
pub struct InvocationCtx<'a, H: Hardware> {
    pub state: &'a mut jar_types::State<H>,
    pub role: KernelRole,
    pub storage_mode: StorageMode,
    pub current_vault: VaultId,
    pub frame: Frame,
    pub caller: Caller,
    pub commands: &'a mut Vec<Command<H>>,
    pub reach: &'a mut ReachSet,
    pub attest_cursor: &'a mut AttestCursor,
    pub attestation_trace: &'a mut Vec<AttestationEntry<H>>,
    pub result_trace: &'a mut Vec<ResultEntry>,
    /// Step-3-only: the slot emission, populated by `cap_call` or
    /// `slot_clear`. The kernel rejects if set twice.
    pub slot_emission: &'a mut Option<SlotContent<H>>,
    pub hw: &'a H,
}

/// The result of running one top-level invocation.
#[derive(Debug)]
pub struct InvocationResult {
    pub halt_value: Option<u64>,
    pub fault: Option<String>,
}

impl InvocationResult {
    pub fn ok(rv: u64) -> Self {
        Self {
            halt_value: Some(rv),
            fault: None,
        }
    }
    pub fn fault(reason: impl Into<String>) -> Self {
        Self {
            halt_value: None,
            fault: Some(reason.into()),
        }
    }
    pub fn is_ok(&self) -> bool {
        self.fault.is_none()
    }
}

/// Drive a VM until terminal. Routes every ProtocolCall to the host-call
/// dispatcher.
pub fn drive_invocation<V: VmExec, H: Hardware>(
    vm: &mut V,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<InvocationResult> {
    loop {
        match vm.step() {
            VmStep::Halt(rv) => return Ok(InvocationResult::ok(rv)),
            VmStep::Fault(reason) => return Ok(InvocationResult::fault(reason)),
            VmStep::OutOfGas => return Err(KernelError::OutOfGas),
            VmStep::ProtocolCall(slot) => {
                let call = HostCall::from_slot(slot)?;
                let (r0, r1) = crate::host_calls::dispatch_host_call(call, vm, ctx)?;
                vm.resume(r0, r1);
            }
        }
    }
}

// -----------------------------------------------------------------------------
// ScriptVm — test-side VmExec that scripts a sequence of ProtocolCall steps.
// -----------------------------------------------------------------------------

/// One step in a ScriptVm script. Each step yields a VmStep and (optionally)
/// observes the resume values written back by the host-call handler.
pub enum ScriptStep {
    /// Issue a ProtocolCall. Before running, kernel reads our staged
    /// register values; after resume, we receive (r0, r1) which is captured
    /// in the script's `observed` log.
    ProtocolCall { slot: u8, regs: [u64; 13] },
    /// Halt the VM with the given return value (φ[7]).
    Halt { rv: u64 },
    /// Fault the VM with the given reason.
    Fault { reason: String },
}

/// Entries observed by the script — the (r0, r1) the host-call handler
/// produced after each ProtocolCall.
#[derive(Debug, Default, Clone)]
pub struct ScriptObservation {
    pub resumes: Vec<(u64, u64)>,
}

/// A test VmExec that runs a queued sequence of ScriptSteps.
pub struct ScriptVm {
    steps: VecDeque<ScriptStep>,
    regs: [u64; 13],
    memory: std::collections::BTreeMap<u32, u8>,
    pub observation: ScriptObservation,
    last_proto_call: bool,
}

impl ScriptVm {
    pub fn new(steps: Vec<ScriptStep>) -> Self {
        Self {
            steps: steps.into(),
            regs: [0u64; 13],
            memory: Default::default(),
            observation: ScriptObservation::default(),
            last_proto_call: false,
        }
    }

    pub fn write_mem_bytes(&mut self, addr: u32, data: &[u8]) {
        for (i, b) in data.iter().enumerate() {
            self.memory.insert(addr + i as u32, *b);
        }
    }
}

impl VmExec for ScriptVm {
    fn step(&mut self) -> VmStep {
        match self.steps.pop_front() {
            Some(ScriptStep::ProtocolCall { slot, regs }) => {
                self.regs = regs;
                self.last_proto_call = true;
                VmStep::ProtocolCall(slot)
            }
            Some(ScriptStep::Halt { rv }) => {
                self.regs[7] = rv;
                VmStep::Halt(rv)
            }
            Some(ScriptStep::Fault { reason }) => VmStep::Fault(reason),
            None => VmStep::Halt(self.regs[7]),
        }
    }

    fn resume(&mut self, r0: u64, r1: u64) {
        if self.last_proto_call {
            self.observation.resumes.push((r0, r1));
            self.regs[7] = r0;
            self.regs[8] = r1;
            self.last_proto_call = false;
        }
    }

    fn reg(&self, idx: usize) -> u64 {
        self.regs[idx]
    }

    fn set_reg(&mut self, idx: usize, val: u64) {
        self.regs[idx] = val;
    }

    fn read_mem(&self, addr: u32, len: u32) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(len as usize);
        for i in 0..len {
            let b = *self.memory.get(&(addr + i))?;
            out.push(b);
        }
        Some(out)
    }

    fn write_mem(&mut self, addr: u32, data: &[u8]) -> bool {
        for (i, b) in data.iter().enumerate() {
            self.memory.insert(addr + i as u32, *b);
        }
        true
    }

    fn gas(&self) -> u64 {
        u64::MAX
    }
}

// -----------------------------------------------------------------------------
// JavmVm — wraps javm::InvocationKernel for real PVM execution.
// -----------------------------------------------------------------------------

pub struct JavmVm {
    pub inner: javm::kernel::InvocationKernel,
}

impl JavmVm {
    pub fn new(blob: &[u8], args: &[u8], gas: u64) -> Result<Self, javm::kernel::KernelError> {
        let inner = javm::kernel::InvocationKernel::new(blob, args, gas)?;
        Ok(Self { inner })
    }
}

impl VmExec for JavmVm {
    fn step(&mut self) -> VmStep {
        match self.inner.run() {
            javm::kernel::KernelResult::Halt(rv) => VmStep::Halt(rv),
            javm::kernel::KernelResult::Panic => VmStep::Fault("panic".into()),
            javm::kernel::KernelResult::OutOfGas => VmStep::OutOfGas,
            javm::kernel::KernelResult::PageFault(addr) => {
                VmStep::Fault(format!("page fault at {:#x}", addr))
            }
            javm::kernel::KernelResult::ProtocolCall { slot } => VmStep::ProtocolCall(slot),
        }
    }

    fn resume(&mut self, r0: u64, r1: u64) {
        self.inner.resume_protocol_call(r0, r1);
    }

    fn reg(&self, idx: usize) -> u64 {
        self.inner.active_reg(idx)
    }

    fn set_reg(&mut self, idx: usize, val: u64) {
        self.inner.set_active_reg(idx, val);
    }

    fn read_mem(&self, addr: u32, len: u32) -> Option<Vec<u8>> {
        self.inner.read_data_cap_window(addr, len)
    }

    fn write_mem(&mut self, addr: u32, data: &[u8]) -> bool {
        self.inner.write_data_cap_window(addr, data)
    }

    fn gas(&self) -> u64 {
        self.inner.active_gas()
    }
}
