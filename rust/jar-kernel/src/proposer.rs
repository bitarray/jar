//! Proposer-side body assembly — stub for the event-redesign migration.
//!
//! In the event-redesign, the proposer drains its local pool of events
//! targeting `σ.transact_endpoints` (no slot model). Concrete
//! implementation lands in Stage C/D.

use crate::runtime::NodeOffchain;
use crate::types::{Body, KResult, State};

/// Stub: returns an empty Body. Concrete implementation in Stage C/D.
pub fn drain_for_body(_node: &NodeOffchain, _state: &State) -> KResult<Body> {
    Ok(Body::default())
}
