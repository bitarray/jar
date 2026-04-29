//! σ snapshot for per-event Transact rollback.
//!
//! `State` uses `Arc<Vault>` for vault contents; cloning σ clones the outer
//! BTreeMaps + bumps Arc refcounts (cheap). On a Transact-event fault, the
//! kernel restores from the snapshot — modified vaults are dropped because
//! `Arc::make_mut` had cloned the inner `Vault` on first write.

use jar_types::{Crypto, State};

/// Cheap-copy snapshot of σ. Backed by Arc-shared vault bodies.
#[derive(Clone)]
pub struct StateSnapshot<C: Crypto>(pub State<C>);

impl<C: Crypto> StateSnapshot<C> {
    pub fn take(state: &State<C>) -> Self {
        StateSnapshot(state.clone())
    }

    /// Restore σ from snapshot. Mutates the live state in place.
    pub fn restore(self, state: &mut State<C>) {
        *state = self.0;
    }
}
