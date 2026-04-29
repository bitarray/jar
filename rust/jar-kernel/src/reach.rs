//! Reach tracking + verifier-mode strict-equality check.

use std::collections::BTreeSet;

use crate::types::{KResult, KernelError, ReachEntry, VaultId};

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
