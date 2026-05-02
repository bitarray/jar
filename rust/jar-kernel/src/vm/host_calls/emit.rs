//! `emit_event(target_path, blob)` host call.
//!
//! Available in both verify and process. Reads `(target_path_ptr,
//! target_path_len, blob_ptr, blob_len)` from φ[7..11] via the guest's
//! mapped DataCaps, then routes the emit through `Command::Emit` so
//! the runtime can broadcast (or short-circuit via
//! `Hardware::is_self_only_subscribed`).
//!
//! In dispatch context the kernel additionally records the originating
//! signer keys into the per-(dispatch_endpoint, cycle) `MintSeenSet`
//! so subsequent `mint_attest_cap` calls with a `Restricted`
//! AttestationScope can be checked. Recording is wired in Stage D when
//! the parameter decoding lands.

use crate::runtime::Hardware;
use crate::vm::{InvocationHost, Vm};
use javm::cap::CallOutcome;

/// Stub: emit_event not yet wired. Always faults.
pub fn host_emit_event<H: Hardware>(
    _vm: &mut Vm,
    _host: &mut InvocationHost<'_, H>,
) -> CallOutcome {
    CallOutcome::Fault("emit_event is stubbed; concrete handler lands in Stage D".into())
}
