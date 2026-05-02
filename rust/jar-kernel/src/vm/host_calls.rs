//! Kernel host-call handlers.
//!
//! Three callable `ProtocolCap` variants are dispatched from
//! `InvocationHost::call`:
//!
//! - `emit_event(target_path, blob)` — available in verify and process.
//!   Reads `(target_path_ptr, target_path_len, blob_ptr, blob_len)`
//!   from φ[7..11]; routes through `Command::Emit` so the runtime can
//!   broadcast (or short-circuit via `Hardware::is_self_only_subscribed`).
//!   In dispatch context the kernel additionally records the originating
//!   signer key in the per-(dispatch_endpoint, cycle) `MintSeenSet` so
//!   subsequent `mint_attest_cap` calls with a `Restricted`
//!   AttestationScope can be checked.
//!
//! - `mint_attest_cap(scope, key, blob, sig?)` — verify-only. Mint
//!   authority comes from the `AttestationScopeCap` injected at frame
//!   init: `Unlimited` (apply_block-context) or `Restricted(seen_keys)`
//!   (dispatch-context). The cap's existence is the proof; there is no
//!   separate exercise call.
//!
//! - `setScore(identifier, score)` — verify-only. Buffers the verifying
//!   event into a per-(endpoint, cycle) max-register.
//!
//! All three are stubbed today and fault on call. Stage D wires:
//! parameter decoding, scope/quota checks, and the
//! `InvocationHost → NodeOffchain.pool` plumbing.

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

/// Stub: mint_attest_cap not yet wired. Always faults.
pub fn host_mint_attest_cap<H: Hardware>(
    _vm: &mut Vm,
    _host: &mut InvocationHost<'_, H>,
) -> CallOutcome {
    CallOutcome::Fault("mint_attest_cap is stubbed; concrete handler lands in Stage D".into())
}

/// Stub: setScore not yet wired. Always faults.
pub fn host_set_score<H: Hardware>(_vm: &mut Vm, _host: &mut InvocationHost<'_, H>) -> CallOutcome {
    CallOutcome::Fault("setScore is stubbed; concrete handler lands in Stage D".into())
}

// =============================================================================
// Memory window helpers (used by handlers once parameter decoding lands)
// =============================================================================

/// Read a guest memory window or return a guest fault outcome.
#[allow(dead_code)] // stubbed during event-redesign migration; rewired in Stage D
pub(crate) fn read_window(vm: &Vm, addr: u32, len: u32, what: &str) -> Result<Vec<u8>, String> {
    if len == 0 {
        return Ok(Vec::new());
    }
    vm.read_data_cap_window(addr, len)
        .ok_or_else(|| format!("{what}: bad read window @ {addr:#x}+{len}"))
}

/// Write to a guest memory window or return a guest fault outcome.
#[allow(dead_code)] // stubbed during event-redesign migration; rewired in Stage D
pub(crate) fn write_window(vm: &mut Vm, addr: u32, data: &[u8], what: &str) -> Result<(), String> {
    if data.is_empty() {
        return Ok(());
    }
    if vm.write_data_cap_window(addr, data) {
        Ok(())
    } else {
        Err(format!(
            "{}: bad write window @ {:#x}+{}",
            what,
            addr,
            data.len()
        ))
    }
}
