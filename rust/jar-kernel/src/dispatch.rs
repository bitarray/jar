//! Off-chain dispatch processing — stub for the event-redesign migration.
//!
//! In the new design, dispatch endpoints in `σ.dispatch_endpoints` run
//! verify (fresh per arriving event) and process (one per cycle).
//! Concrete implementation lands in Stage D.

use crate::runtime::{Hardware, NodeOffchain};
use crate::types::{Command, KResult, State, VaultId};

/// Stub: handle inbound emit. Returns no commands.
pub fn handle_inbound<H: Hardware>(
    _state: &State,
    _node: &mut NodeOffchain,
    _target_path: &[u8],
    _blob: &[u8],
    _hw: &H,
) -> KResult<Vec<Command>> {
    Ok(Vec::new())
}

/// Stub: legacy entrypoint for the dispatch handler. Returns no commands.
pub fn handle_inbound_dispatch<H: Hardware>(
    _state: &State,
    _node: &mut NodeOffchain,
    _entrypoint: VaultId,
    _payload: Vec<u8>,
    _caps: Vec<u8>,
    _hw: &H,
) -> KResult<Vec<Command>> {
    Ok(Vec::new())
}
