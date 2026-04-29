//! Off-chain aggregation slot content. Per-(node, Dispatch entrypoint).

use crate::{AttestationEntry, ResultEntry, VaultId};

/// One Dispatch event arriving at an entrypoint, or one Transact event in
/// a block body. Same shape; used for both surfaces.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct Event {
    pub payload: Vec<u8>,
    /// Caps the sender attached. Wire-side caps are encoded as opaque bytes
    /// the receiver re-interprets; for in-process tests we just carry
    /// already-allocated cap-ids out-of-band.
    pub caps: Vec<u8>,
    pub attestation_trace: Vec<AttestationEntry>,
    pub result_trace: Vec<ResultEntry>,
}

/// Per-(node, Dispatch entrypoint) slot content. Updated by step-3 emissions.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub enum SlotContent {
    /// Step-3 produced an aggregated dispatch — used for further aggregation
    /// upward (parent reads this child's slot).
    AggregatedDispatch {
        payload: Vec<u8>,
        caps: Vec<u8>,
        attestation_trace: Vec<AttestationEntry>,
        result_trace: Vec<ResultEntry>,
    },
    /// Step-3 produced a transact-bound payload. The proposer drains this
    /// into `body.events[target]`.
    AggregatedTransact {
        target: VaultId,
        payload: Vec<u8>,
        caps: Vec<u8>,
        attestation_trace: Vec<AttestationEntry>,
        result_trace: Vec<ResultEntry>,
    },
    #[default]
    Empty,
}
