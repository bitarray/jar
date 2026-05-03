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
pub mod vault_init;

use crate::cap::{AttestCursor, ProtocolCap};
use crate::runtime::Hardware;
use crate::transact::ReachSet;
use javm::cap::{CallOutcome, Cap, ProtocolCapHost};

/// Convenience alias: the `InvocationKernel` parameterized over the
/// kernel's protocol-cap payload.
pub type Vm = javm::kernel::InvocationKernel<ProtocolCap>;

/// Construct a fresh `Vm` ready to run `Vault.initialize` on the given
/// home Vault. Walks `vault.slots` via [`vault_init::build_init_cap_table`],
/// injects the kernel-managed protocol caps (`EmitEvent`,
/// `MintAttestCap`, `SetScore`, `AttestationScope` where applicable),
/// then hands the artifacts to javm's `new_from_artifacts`.
///
/// `role` selects which caps get injected: `Verify` gets all four;
/// `Process` gets only `EmitEvent`. `attestation_scope` is the scope
/// cap to place at [`crate::cap::KERNEL_CAP_SLOT`] for verify
/// invocations (`Unlimited` for transact, `Restricted(seen)` for
/// dispatch) — `None` for process.
///
/// `code_cache` is consulted for each persistent CodeCap; pass
/// `Some(&mut node.code_cache)` from the dispatch / transact entry
/// points so re-runs of the same blob hit the JIT cache.
#[allow(clippy::too_many_arguments)]
pub fn new_vm_from_vault(
    state: &State,
    vault_id: VaultId,
    gas: u64,
    memory_pages: u32,
    code_cache: Option<&mut javm::CodeCache>,
    role: crate::types::KernelRole,
    attestation_scope: Option<crate::cap::AttestationScopeCap>,
) -> KResult<Vm> {
    use crate::cap::{KERNEL_CAP_SLOT, ProtocolCap};
    use crate::vm::host_abi::{EMIT_EVENT_SLOT, MINT_ATTEST_CAP_SLOT, SET_SCORE_SLOT};
    use javm::cap::Cap as JavmCap;

    let mut artifacts = vault_init::build_init_cap_table(
        state,
        vault_id,
        memory_pages,
        code_cache,
        javm::PvmBackend::Default,
    )?;

    artifacts
        .cap_table
        .set(EMIT_EVENT_SLOT, JavmCap::Protocol(ProtocolCap::EmitEvent));

    if matches!(role, crate::types::KernelRole::Verify) {
        artifacts.cap_table.set(
            MINT_ATTEST_CAP_SLOT,
            JavmCap::Protocol(ProtocolCap::MintAttestCap),
        );
        artifacts
            .cap_table
            .set(SET_SCORE_SLOT, JavmCap::Protocol(ProtocolCap::SetScore));
        if let Some(scope) = attestation_scope {
            artifacts.cap_table.set(
                KERNEL_CAP_SLOT,
                JavmCap::Protocol(ProtocolCap::AttestationScope(scope)),
            );
        }
    }

    javm::kernel::InvocationKernel::new_from_artifacts(artifacts, gas, javm::PvmBackend::Default)
        .map_err(|e| KernelError::Internal(format!("javm init: {:?}", e)))
}

/// After a process invocation halts, walk the home Vault's DataCap
/// slots and replace each `RegCap::Data` in σ with the post-execution
/// page contents read from the active VM's cap-table copy.
///
/// Only currently-mapped DataCaps are snapshotted; unmapped caps are
/// left untouched (`vm.read_data_cap` returns `None`). Chain authors
/// that mutate persistent state must keep the relevant DataCap mapped
/// across halt — `simple-chain` follows this convention.
pub fn snapshot_data_caps(vm: &Vm, vault_id: VaultId, state: &mut State) {
    use std::sync::Arc;

    let arc = match state.vaults.get(&vault_id) {
        Some(a) => a.clone(),
        None => return,
    };
    let mut new_vault: crate::types::Vault = (*arc).clone();
    let mut changed = false;
    for slot in 0u8..=255 {
        let page_count = match new_vault.slots.get(slot) {
            Some(crate::cap::RegCap::Data(d)) => d.page_count,
            _ => continue,
        };
        let total_bytes = page_count.saturating_mul(javm::PVM_PAGE_SIZE);
        let Some(bytes) = vm.read_data_cap(slot, 0, total_bytes) else {
            continue;
        };
        new_vault.slots.set(
            slot,
            Some(crate::cap::RegCap::Data(crate::cap::DataCap {
                content: Arc::new(bytes),
                page_count,
            })),
        );
        changed = true;
    }
    if changed {
        state.vaults.insert(vault_id, Arc::new(new_vault));
    }
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
    /// Slot index of this invocation's endpoint in
    /// `σ.transact_endpoints` (transact context) or
    /// `σ.dispatch_endpoints` (dispatch context). Used by `setScore`
    /// to address the per-(endpoint, cycle) pool entry, and by
    /// `emit_event` in dispatch context to record signers in the
    /// per-endpoint `MintSeenSet`.
    pub endpoint_idx: usize,
    /// True iff this invocation is a dispatch-context fire (off-chain).
    /// Distinguishes which endpoint list `endpoint_idx` indexes and
    /// gates dispatch-only behaviors like seen-set recording.
    pub dispatch_context: bool,
    /// The blob being verified by this invocation. `setScore` captures
    /// it into the resulting `PoolEntry` so the proposer can replay
    /// the blob in a later block. Empty in process role.
    pub event_blob: &'a [u8],
    pub commands: &'a mut Vec<Command>,
    pub reach: &'a mut ReachSet,
    pub attest_cursor: &'a mut AttestCursor,
    pub attestation_trace: &'a mut Vec<AttestationEntry>,
    pub result_trace: &'a mut Vec<ResultEntry>,
    pub pool: &'a mut crate::pool::CyclePool,
    pub hw: &'a H,
}

impl<H: Hardware> ProtocolCapHost<ProtocolCap> for InvocationHost<'_, H> {
    fn call(&mut self, cap: ProtocolCap, vm: &mut Vm) -> CallOutcome {
        use crate::vm::host_calls::{host_emit_event, host_mint_attest_cap, host_set_score};
        match cap {
            ProtocolCap::EmitEvent => host_emit_event(vm, self),
            ProtocolCap::MintAttestCap => host_mint_attest_cap(vm, self),
            ProtocolCap::SetScore => host_set_score(vm, self),
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
