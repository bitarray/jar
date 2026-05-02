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
//! Trace consumption is wired via `mint_attest_cap` inside the verify
//! VM (Stage C/D). Today the host calls are stubbed, so the halt-blob
//! genesis fixtures simply halt cleanly.

use std::collections::BTreeSet;

use crate::cap::AttestCursor;
use crate::runtime::Hardware;
use crate::types::{
    AttestationEntry, Caller, Command, EventEndpointCap, KResult, KernelError, KernelRole,
    ReachEntry, ResultEntry, State, VaultId,
};
use crate::vm::{InvocationHost, InvocationResult, drive_invocation, new_vm_from_vault};

/// Run one fresh `Vault.initialize` against a clone of σ for the verify
/// phase. Returns the invocation result; the caller decides whether to
/// panic the block on `result.fault`.
pub fn run_verify<H: Hardware>(
    state: &State,
    endpoint: &EventEndpointCap,
    commands: &mut Vec<Command>,
    hw: &H,
) -> KResult<InvocationResult> {
    let mut state_ro = state.clone();
    run_one(&mut state_ro, endpoint, KernelRole::Verify, commands, hw)
}

/// Run one `Vault.initialize` against the live σ for the process phase.
/// Mutations persist on `state`. The caller decides what to do with a
/// process fault — apply_block treats it as a block panic.
pub fn run_process<H: Hardware>(
    state: &mut State,
    endpoint: &EventEndpointCap,
    commands: &mut Vec<Command>,
    hw: &H,
) -> KResult<InvocationResult> {
    run_one(state, endpoint, KernelRole::Process, commands, hw)
}

fn run_one<H: Hardware>(
    state: &mut State,
    endpoint: &EventEndpointCap,
    role: KernelRole,
    commands: &mut Vec<Command>,
    hw: &H,
) -> KResult<InvocationResult> {
    let mut vm = new_vm_from_vault(
        state,
        endpoint.vault_id,
        endpoint.gas_budget,
        endpoint.memory_budget,
        None,
    )?;
    let mut reach = ReachSet::default();
    let mut cursor = AttestCursor::new();
    let mut attestation_trace: Vec<AttestationEntry> = Vec::new();
    let mut result_trace: Vec<ResultEntry> = Vec::new();
    let mut host = InvocationHost {
        state,
        role,
        current_vault: endpoint.vault_id,
        caller: Caller::Kernel(role),
        commands,
        reach: &mut reach,
        attest_cursor: &mut cursor,
        attestation_trace: &mut attestation_trace,
        result_trace: &mut result_trace,
        hw,
    };
    drive_invocation(&mut vm, &mut host)
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
