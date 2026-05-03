//! Transact-phase per-slot execution.
//!
//! The kernel walks `σ.transact_endpoints` in slot order; for each slot
//! `apply_block` calls `run_verify` once per body event (fresh
//! `Vault.initialize` against a clone of σ — ro-σ semantics) and then
//! calls `run_process` once for the slot (rw-σ). Schedule slots have no
//! body events; their kernel-fed `schedule_attestation_traces` slice is
//! consumed by a single verify pass before process fires.
//!
//! Verify may panic (the block panics with it). Process may not fail
//! logic-wise; a process fault from a chain-author bug is reported as a
//! block panic for now (kept from the v1 stubs).
//!
//! The same harness drives off-chain dispatch invocations
//! (`dispatch::handle_inbound`); `dispatch_context = true` selects the
//! dispatch-only host-call behaviors (mint-seen-set tracking,
//! `Restricted` AttestationScope, ro-σ process).

use std::collections::BTreeSet;

use crate::cap::{AttestCursor, AttestationScopeCap};
use crate::pool::CyclePool;
use crate::runtime::Hardware;
use crate::types::{
    AttestationEntry, Caller, Command, EventEndpointCap, KResult, KernelError, KernelRole,
    ReachEntry, ResultEntry, State, VaultId,
};
use crate::vm::{InvocationHost, InvocationResult, drive_invocation, new_vm_from_vault};

/// One fresh `Vault.initialize` against a clone of σ for the verify
/// phase. Returns the invocation result; the caller decides whether to
/// panic the block on `result.fault`.
#[allow(clippy::too_many_arguments)]
pub fn run_verify<H: Hardware>(
    state: &State,
    endpoint: &EventEndpointCap,
    endpoint_idx: usize,
    dispatch_context: bool,
    event_blob: &[u8],
    attestation_traces: &[AttestationEntry],
    pool: &mut CyclePool,
    commands: &mut Vec<Command>,
    hw: &H,
) -> KResult<InvocationResult> {
    let mut state_ro = state.clone();
    run_one(
        &mut state_ro,
        endpoint,
        endpoint_idx,
        dispatch_context,
        KernelRole::Verify,
        event_blob,
        attestation_traces,
        pool,
        commands,
        hw,
    )
}

/// One `Vault.initialize` against the live σ for the process phase.
/// Mutations persist on `state`. The caller decides what to do with a
/// process fault — apply_block treats it as a block panic.
///
/// `event_blob` is the slot's single body-event blob (v1 single-event-
/// per-slot constraint); empty for Schedule slots and dispatch-process.
/// Multi-event-per-slot lands when the body→process plumbing accepts
/// a slice rather than a single blob.
#[allow(clippy::too_many_arguments)]
pub fn run_process<H: Hardware>(
    state: &mut State,
    endpoint: &EventEndpointCap,
    endpoint_idx: usize,
    dispatch_context: bool,
    event_blob: &[u8],
    pool: &mut CyclePool,
    commands: &mut Vec<Command>,
    hw: &H,
) -> KResult<InvocationResult> {
    run_one(
        state,
        endpoint,
        endpoint_idx,
        dispatch_context,
        KernelRole::Process,
        event_blob,
        &[],
        pool,
        commands,
        hw,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_one<H: Hardware>(
    state: &mut State,
    endpoint: &EventEndpointCap,
    endpoint_idx: usize,
    dispatch_context: bool,
    role: KernelRole,
    event_blob: &[u8],
    attestation_traces: &[AttestationEntry],
    pool: &mut CyclePool,
    commands: &mut Vec<Command>,
    hw: &H,
) -> KResult<InvocationResult> {
    // v1 always injects `Unlimited` for verify (lets any signer be
    // vouched for). The `Restricted(seen_keys)` variant — used by the
    // chain-author DA pattern that gates mint authority on the
    // per-(dispatch_endpoint, cycle) seen-set — is a future opt-in.
    let _ = (dispatch_context, &pool);
    let scope = (role == KernelRole::Verify).then_some(AttestationScopeCap::Unlimited);
    let mut vm = new_vm_from_vault(
        state,
        endpoint.vault_id,
        endpoint.gas_budget,
        endpoint.memory_budget,
        None,
        role,
        scope,
    )?;
    if !event_blob.is_empty() {
        vm.set_args(event_blob).map_err(|e| {
            crate::types::KernelError::Internal(format!("vm.set_args failed: {:?}", e))
        })?;
    }
    let mut reach = ReachSet::default();
    let mut cursor = AttestCursor::new();
    let mut attestation_trace: Vec<AttestationEntry> = attestation_traces.to_vec();
    let mut result_trace: Vec<ResultEntry> = Vec::new();
    let result = {
        let mut host = InvocationHost {
            state,
            role,
            current_vault: endpoint.vault_id,
            caller: Caller::Kernel(role),
            endpoint_idx,
            dispatch_context,
            event_blob,
            commands,
            reach: &mut reach,
            attest_cursor: &mut cursor,
            attestation_trace: &mut attestation_trace,
            result_trace: &mut result_trace,
            pool,
            hw,
        };
        drive_invocation(&mut vm, &mut host)?
    };
    // Persistence is now guest-driven: the chain author writes to
    // σ via foreign-frame MGMT_COPY through the home VaultRef
    // before halting. The kernel does not auto-snapshot DataCap
    // pages back into σ.
    Ok(result)
}

// =============================================================================
// Reach tracking + verifier-mode strict-equality check
// =============================================================================

/// Per-invocation reach: which Vaults were touched (initialized) during one
/// top-level invocation.
#[derive(Clone, Default, Debug)]
pub struct ReachSet {
    pub vaults: BTreeSet<VaultId>,
}

impl ReachSet {
    pub fn note(&mut self, v: VaultId) {
        self.vaults.insert(v);
    }

    pub fn into_entry(self, entrypoint: VaultId, event_idx: u32) -> ReachEntry {
        ReachEntry {
            entrypoint,
            event_idx,
            vaults: self.vaults.into_iter().collect(),
        }
    }
}

/// Verifier-mode strict equality check. Order-insensitive (reach is a set);
/// we compare sorted vectors.
pub fn check_strict_equality(actual: &ReachSet, recorded: &ReachEntry) -> KResult<()> {
    let actual_sorted: Vec<VaultId> = actual.vaults.iter().copied().collect();
    let mut recorded_sorted = recorded.vaults.clone();
    recorded_sorted.sort();
    if actual_sorted != recorded_sorted {
        return Err(KernelError::TraceDivergence(format!(
            "reach mismatch: actual {:?} vs recorded {:?}",
            actual_sorted, recorded_sorted
        )));
    }
    Ok(())
}
