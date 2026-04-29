//! Off-chain aggregation slot content. Per-(node, Dispatch entrypoint).
//!
//! Manual trait impls (not `#[derive]`) so bounds are on `C`'s associated
//! types rather than on `C` itself.

use crate::{AttestationEntry, Crypto, ResultEntry, VaultId};

/// One Dispatch event arriving at an entrypoint, or one Transact event in
/// a block body. Same shape; used for both surfaces.
pub struct Event<C: Crypto> {
    pub payload: Vec<u8>,
    /// Caps the sender attached. Wire-side caps are encoded as opaque bytes
    /// the receiver re-interprets; for in-process tests we just carry
    /// already-allocated cap-ids out-of-band.
    pub caps: Vec<u8>,
    pub attestation_trace: Vec<AttestationEntry<C>>,
    pub result_trace: Vec<ResultEntry>,
}

impl<C: Crypto> Clone for Event<C> {
    fn clone(&self) -> Self {
        Self {
            payload: self.payload.clone(),
            caps: self.caps.clone(),
            attestation_trace: self.attestation_trace.clone(),
            result_trace: self.result_trace.clone(),
        }
    }
}

impl<C: Crypto> PartialEq for Event<C> {
    fn eq(&self, other: &Self) -> bool {
        self.payload == other.payload
            && self.caps == other.caps
            && self.attestation_trace == other.attestation_trace
            && self.result_trace == other.result_trace
    }
}

impl<C: Crypto> Eq for Event<C> {}

impl<C: Crypto> core::fmt::Debug for Event<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Event")
            .field("payload", &self.payload)
            .field("caps", &self.caps)
            .field("attestation_trace", &self.attestation_trace)
            .field("result_trace", &self.result_trace)
            .finish()
    }
}

impl<C: Crypto> Default for Event<C> {
    fn default() -> Self {
        Self {
            payload: Vec::new(),
            caps: Vec::new(),
            attestation_trace: Vec::new(),
            result_trace: Vec::new(),
        }
    }
}

/// Per-(node, Dispatch entrypoint) slot content. Updated by step-3 emissions.
pub enum SlotContent<C: Crypto> {
    /// Step-3 produced an aggregated dispatch — used for further aggregation
    /// upward (parent reads this child's slot).
    AggregatedDispatch {
        payload: Vec<u8>,
        caps: Vec<u8>,
        attestation_trace: Vec<AttestationEntry<C>>,
        result_trace: Vec<ResultEntry>,
    },
    /// Step-3 produced a transact-bound payload. The proposer drains this
    /// into `body.events[target]`.
    AggregatedTransact {
        target: VaultId,
        payload: Vec<u8>,
        caps: Vec<u8>,
        attestation_trace: Vec<AttestationEntry<C>>,
        result_trace: Vec<ResultEntry>,
    },
    Empty,
}

impl<C: Crypto> Clone for SlotContent<C> {
    fn clone(&self) -> Self {
        match self {
            SlotContent::AggregatedDispatch {
                payload,
                caps,
                attestation_trace,
                result_trace,
            } => SlotContent::AggregatedDispatch {
                payload: payload.clone(),
                caps: caps.clone(),
                attestation_trace: attestation_trace.clone(),
                result_trace: result_trace.clone(),
            },
            SlotContent::AggregatedTransact {
                target,
                payload,
                caps,
                attestation_trace,
                result_trace,
            } => SlotContent::AggregatedTransact {
                target: *target,
                payload: payload.clone(),
                caps: caps.clone(),
                attestation_trace: attestation_trace.clone(),
                result_trace: result_trace.clone(),
            },
            SlotContent::Empty => SlotContent::Empty,
        }
    }
}

impl<C: Crypto> PartialEq for SlotContent<C> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                SlotContent::AggregatedDispatch {
                    payload: p1,
                    caps: c1,
                    attestation_trace: at1,
                    result_trace: rt1,
                },
                SlotContent::AggregatedDispatch {
                    payload: p2,
                    caps: c2,
                    attestation_trace: at2,
                    result_trace: rt2,
                },
            ) => p1 == p2 && c1 == c2 && at1 == at2 && rt1 == rt2,
            (
                SlotContent::AggregatedTransact {
                    target: t1,
                    payload: p1,
                    caps: c1,
                    attestation_trace: at1,
                    result_trace: rt1,
                },
                SlotContent::AggregatedTransact {
                    target: t2,
                    payload: p2,
                    caps: c2,
                    attestation_trace: at2,
                    result_trace: rt2,
                },
            ) => t1 == t2 && p1 == p2 && c1 == c2 && at1 == at2 && rt1 == rt2,
            (SlotContent::Empty, SlotContent::Empty) => true,
            _ => false,
        }
    }
}

impl<C: Crypto> Eq for SlotContent<C> {}

impl<C: Crypto> core::fmt::Debug for SlotContent<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SlotContent::AggregatedDispatch {
                payload,
                caps,
                attestation_trace,
                result_trace,
            } => f
                .debug_struct("AggregatedDispatch")
                .field("payload", payload)
                .field("caps", caps)
                .field("attestation_trace", attestation_trace)
                .field("result_trace", result_trace)
                .finish(),
            SlotContent::AggregatedTransact {
                target,
                payload,
                caps,
                attestation_trace,
                result_trace,
            } => f
                .debug_struct("AggregatedTransact")
                .field("target", target)
                .field("payload", payload)
                .field("caps", caps)
                .field("attestation_trace", attestation_trace)
                .field("result_trace", result_trace)
                .finish(),
            SlotContent::Empty => f.write_str("Empty"),
        }
    }
}

impl<C: Crypto> Default for SlotContent<C> {
    fn default() -> Self {
        SlotContent::Empty
    }
}
