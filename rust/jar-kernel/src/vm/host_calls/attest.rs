//! `mint_attest_cap` host call (verify-only).
//!
//! In the event-redesign the AttestationCap is the proof itself —
//! its existence in a Vault slot or Frame means the kernel vouched
//! that `key` signed `blob_hash` (or that `key == IDENTITY_KEY` and
//! the kernel vouched for the computation directly). There is no
//! separate `attest()` exercise call; the gate is mint-time.
//!
//! Mint authority comes from the `AttestationAuthority` cap the
//! kernel injects into verify. Scope = `Unlimited` (apply_block-
//! context verifies and network-arrived event verifies) or
//! `Restricted(seen_keys)` (dispatch-context emits, where the
//! authority is scoped to the per-(dispatch_endpoint, cycle) seen
//! set). Mint attempts for a key outside the authority's scope
//! return `RC_AUTHORITY`.
//!
//! Concrete implementation is stubbed; Stage D wires the parameter
//! decoding (authority cap-ref, key bytes, blob hash, optional sig
//! bytes), the scope check, and the cap-registry insert.

use crate::runtime::Hardware;
use crate::types::KResult;
use crate::vm::{HostCallOutcome, InvocationCtx, Vm};

/// Stub: mint_attest_cap not yet wired. Always faults.
pub fn host_mint_attest_cap<H: Hardware>(
    _vm: &mut Vm,
    _ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    Ok(HostCallOutcome::Fault(
        "mint_attest_cap is stubbed; concrete handler lands in Stage D".into(),
    ))
}
