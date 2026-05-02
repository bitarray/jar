//! Invocation driver for `javm::kernel::InvocationKernel<ProtocolCap>`.
//!
//! `drive_invocation` runs a real PVM VM until terminal (Halt / Panic /
//! PageFault / OutOfGas / host Fault). Host-call dispatch happens
//! synchronously inside javm's run loop via
//! `<InvocationHost as ProtocolCapHost<ProtocolCap>>::call`; there is
//! no yield/resume protocol any more.
//!
//! [`InvocationHost`] bundles per-invocation kernel state — σ pointer,
//! role, current vault, command queue, traces, hardware ref — into the
//! single `ProtocolCapHost` adapter that javm calls. Both the
//! foreign-frame slot ops (`get` / `take` / `set` / `clone` / `drop` /
//! `is_empty`) and the CALL dispatch (`call`) share access to that
//! state.
//!
//! Memory windows in the kernel are not flat: the guest reads/writes its
//! own DATA caps. The kernel routes through `read_data_cap_window` /
//! `write_data_cap_window`; failures are guest-driven faults, not kernel
//! errors.

use crate::types::{
    AttestationEntry, Caller, Command, KResult, KernelError, KernelRole, ResultEntry, State,
    VaultId,
};

pub mod foreign_cnode;
pub mod host_abi;
pub mod host_calls;

use crate::cap::ProtocolCap;
use crate::cap::attest::AttestCursor;
use crate::reach::ReachSet;
use crate::runtime::Hardware;
use javm::cap::{CallOutcome, Cap, ProtocolCapHost};

/// Convenience alias: the `InvocationKernel` parameterized over the
/// kernel's protocol-cap payload.
pub type Vm = javm::kernel::InvocationKernel<ProtocolCap>;

/// Construct a fresh `Vm` ready to run `Vault.initialize` on the given
/// home Vault. Walks `vault.slots` via [`crate::state::vault_init::build_init_cap_table`],
/// then hands the resulting artifacts to javm's `new_from_artifacts`.
///
/// `code_cache` is consulted for each persistent CodeCap; pass
/// `Some(&mut node.code_cache)` from the dispatch / transact entry
/// points so re-runs of the same blob hit the JIT cache.
pub fn new_vm_from_vault(
    state: &State,
    vault_id: VaultId,
    gas: u64,
    memory_pages: u32,
    code_cache: Option<&mut javm::CodeCache>,
) -> KResult<Vm> {
    let artifacts = crate::state::vault_init::build_init_cap_table(
        state,
        vault_id,
        memory_pages,
        code_cache,
        javm::PvmBackend::Default,
    )?;
    javm::kernel::InvocationKernel::new_from_artifacts(artifacts, gas, javm::PvmBackend::Default)
        .map_err(|e| KernelError::Internal(format!("javm init: {:?}", e)))
}

/// Per-invocation kernel-side host. Implements
/// `ProtocolCapHost<ProtocolCap>` — javm calls into this for:
///
/// - foreign-frame slot ops (`get` / `take` / `set` / `clone` / `drop`
///   / `is_empty`) on `vault.slots[…]` reachable via VaultRef cap-ref
///   crossings;
/// - synchronous CALL dispatch (`call`), which routes to the
///   `host_calls::*` handlers based on the cap variant.
///
/// All borrows are explicit so the type can be reconstructed cheaply
/// per invocation. Lives on the stack of `transact::run_one` /
/// `dispatch::handle_inbound` and is dropped at invocation end.
pub struct InvocationHost<'a, H: Hardware> {
    pub state: &'a mut State,
    pub role: KernelRole,
    pub current_vault: VaultId,
    pub caller: Caller,
    pub commands: &'a mut Vec<Command>,
    pub reach: &'a mut ReachSet,
    pub attest_cursor: &'a mut AttestCursor,
    pub attestation_trace: &'a mut Vec<AttestationEntry>,
    pub result_trace: &'a mut Vec<ResultEntry>,
    pub hw: &'a H,
}

impl<H: Hardware> ProtocolCapHost<ProtocolCap> for InvocationHost<'_, H> {
    fn call(&mut self, cap: ProtocolCap, vm: &mut Vm) -> CallOutcome {
        use crate::vm::host_calls::{attest, emit, score};
        match cap {
            ProtocolCap::EmitEvent => emit::host_emit_event(vm, self),
            ProtocolCap::MintAttestCap => attest::host_mint_attest_cap(vm, self),
            ProtocolCap::SetScore => score::host_set_score(vm, self),
            other => CallOutcome::Fault(format!("CALL on non-callable cap: {other:?}")),
        }
    }

    fn get(&self, vault: VaultId, slot: u8) -> Option<Cap<ProtocolCap>> {
        foreign_cnode::get(self.state, vault, slot)
    }

    fn take(
        &mut self,
        vault: VaultId,
        slot: u8,
        rights: crate::cap::VaultRights,
    ) -> Option<Cap<ProtocolCap>> {
        foreign_cnode::take(self.state, vault, slot, rights)
    }

    fn set(
        &mut self,
        vault: VaultId,
        slot: u8,
        rights: crate::cap::VaultRights,
        cap: Cap<ProtocolCap>,
    ) -> Result<(), Cap<ProtocolCap>> {
        foreign_cnode::set(self.state, vault, slot, rights, cap)
    }

    fn clone(
        &mut self,
        vault: VaultId,
        slot: u8,
        rights: crate::cap::VaultRights,
    ) -> Option<Cap<ProtocolCap>> {
        foreign_cnode::clone(self.state, vault, slot, rights)
    }

    fn drop(&mut self, vault: VaultId, slot: u8, rights: crate::cap::VaultRights) -> bool {
        foreign_cnode::drop(self.state, vault, slot, rights)
    }

    fn is_empty(&self, vault: VaultId, slot: u8) -> bool {
        foreign_cnode::is_empty(self.state, vault, slot)
    }
}

/// The result of running one top-level invocation.
#[derive(Debug)]
pub struct InvocationResult {
    pub halt_value: Option<u64>,
    pub fault: Option<String>,
    /// Public Callable produced by `Vault.initialize`: the FrameRef at
    /// `BARE_ARG_SLOT` (the synchronous arg-in / result-out channel)
    /// after the init program halts.
    pub initialize_callable: Option<javm::vm_pool::VmId>,
}

impl InvocationResult {
    pub fn ok(rv: u64) -> Self {
        Self {
            halt_value: Some(rv),
            fault: None,
            initialize_callable: None,
        }
    }
    pub fn fault(reason: impl Into<String>) -> Self {
        Self {
            halt_value: None,
            fault: Some(reason.into()),
            initialize_callable: None,
        }
    }
    pub fn is_ok(&self) -> bool {
        self.fault.is_none()
    }
}

/// MainFrame slot where the kernel pins the running VM's `SelfCap`.
pub const SELF_SLOT: u8 = 2;

/// Drive a real javm VM to a terminal state. CALL dispatch happens
/// inside javm via `InvocationHost::call`; this function just
/// translates the run loop's terminal `KernelResult` into an
/// `InvocationResult`.
pub fn drive_invocation<H: Hardware>(
    vm: &mut Vm,
    host: &mut InvocationHost<'_, H>,
) -> KResult<InvocationResult> {
    match vm.run_with_host(host) {
        javm::kernel::KernelResult::Halt(rv) => {
            // After the init program halts, recover any public Callable
            // it placed at the BareFrame ARG/RESULT slot. Empty /
            // non-FrameRef ⇒ `None`; not a fault.
            let initialize_callable = match vm.read_bare_frame_slot(javm::kernel::BARE_ARG_SLOT) {
                Some(javm::cap::Cap::FrameRef(f)) => Some(f.vm_id),
                _ => None,
            };
            Ok(InvocationResult {
                halt_value: Some(rv),
                fault: None,
                initialize_callable,
            })
        }
        javm::kernel::KernelResult::Panic => Ok(InvocationResult::fault("guest panic")),
        javm::kernel::KernelResult::OutOfGas => Err(KernelError::OutOfGas),
        javm::kernel::KernelResult::PageFault(addr) => Ok(InvocationResult::fault(format!(
            "page fault at {:#x}",
            addr
        ))),
        javm::kernel::KernelResult::Fault(reason) => Ok(InvocationResult::fault(reason)),
    }
}
