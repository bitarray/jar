//! Kernel host-call handlers.
//!
//! Three callable `ProtocolCap` variants are dispatched from
//! `InvocationHost::call`:
//!
//! - `emit_event(target_path, blob)` — verify and process. Pushes a
//!   `Command::Emit` onto `host.commands`. In dispatch verify
//!   context, additionally records each attached attestation entry's
//!   signer key into the per-(dispatch_endpoint, cycle)
//!   `MintSeenSet` so subsequent `mint_attest_cap` calls with a
//!   `Restricted` AttestationScope can be checked.
//!
//! - `mint_attest_cap(dst_slot, key, blob, sig?)` — verify-only. Validates
//!   the key against the AttestationScope cap injected at
//!   `KERNEL_CAP_SLOT`, verifies the signature via
//!   `crypto::verify`, and mints `Cap::Protocol(Attestation(...))`
//!   into the active VM's cap table at `dst_slot`. The cap's
//!   existence is the proof.
//!
//! - `setScore(identifier, score)` — dispatch-verify only. Buffers
//!   the verifying event (its blob + accumulated attestation traces)
//!   into `host.pool.entry(host.endpoint_idx)` keyed by `identifier`.
//!   Same identifier + same blob keeps the higher score; same
//!   identifier + different blob is a collision and defers to the
//!   next cycle.
//!
//! ABI register layout: see `vm/host_abi.rs`.

use crate::cap::{AttestationCap, AttestationScopeCap, ProtocolCap};
use crate::crypto;
use crate::pool::PoolEntry;
use crate::runtime::Hardware;
use crate::types::{AttestationEntry, Command, KernelRole, KeyId, Signature};
use crate::vm::host_abi::{
    BARE_ATTESTATION_SCOPE_SLOT, RC_AUTHORITY, RC_BAD_CAP, RC_BAD_SIG, RC_OK, RC_READONLY,
};
use crate::vm::{InvocationHost, Vm};
use javm::cap::{CallOutcome, Cap};

/// Read the AttestationScope cap from BareFrame, if present.
fn bare_attestation_scope(vm: &Vm) -> Option<AttestationScopeCap> {
    let bare_idx = vm.bare_frame_id.index();
    match vm
        .vm_arena
        .vm(bare_idx)
        .cap_table
        .get(BARE_ATTESTATION_SCOPE_SLOT)
    {
        Some(Cap::Protocol(ProtocolCap::AttestationScope(s))) => Some(s.clone()),
        _ => None,
    }
}

fn rc(value: u64) -> CallOutcome {
    CallOutcome::Resume {
        phi7: value,
        phi8: 0,
    }
}

/// `emit_event(target_path, blob)`:
///   φ[7]=path_ptr, φ[8]=path_len, φ[9]=blob_ptr, φ[10]=blob_len.
pub fn host_emit_event<H: Hardware>(vm: &mut Vm, host: &mut InvocationHost<'_, H>) -> CallOutcome {
    let path_ptr = vm.active_reg(7) as u32;
    let path_len = vm.active_reg(8) as u32;
    let blob_ptr = vm.active_reg(9) as u32;
    let blob_len = vm.active_reg(10) as u32;

    let target_path = match read_window(vm, path_ptr, path_len, "emit_event target_path") {
        Ok(v) => v,
        Err(reason) => return CallOutcome::Fault(reason),
    };
    let blob = match read_window(vm, blob_ptr, blob_len, "emit_event blob") {
        Ok(v) => v,
        Err(reason) => return CallOutcome::Fault(reason),
    };

    let attestation_traces = host.attestation_trace.clone();

    // Dispatch-verify: record signers from the trace into the seen-set
    // so subsequent mint_attest_cap with Restricted scope can verify.
    if host.dispatch_context && matches!(host.role, KernelRole::Verify) {
        for entry in &attestation_traces {
            host.pool
                .mint_seen_set(host.endpoint_idx)
                .record(entry.key.clone());
        }
    }

    host.commands.push(Command::Emit {
        target_path,
        blob,
        attestation_traces,
    });
    rc(RC_OK)
}

/// `mint_attest_cap(dst_slot, key_ptr, blob, sig_ptr)`:
///   φ[7]=dst_slot,
///   φ[8]=key_ptr (0 = IDENTITY_KEY; otherwise 32-byte ed25519 pubkey),
///   φ[9]=blob_ptr, φ[10]=blob_len,
///   φ[11]=sig_ptr (0 = no signature; otherwise 64-byte ed25519 sig).
pub fn host_mint_attest_cap<H: Hardware>(
    vm: &mut Vm,
    host: &mut InvocationHost<'_, H>,
) -> CallOutcome {
    if !matches!(host.role, KernelRole::Verify) {
        return rc(RC_READONLY);
    }
    const ED25519_KEY_LEN: u32 = 32;
    const ED25519_SIG_LEN: u32 = 64;

    let dst_slot = vm.active_reg(7) as u8;
    let key_ptr = vm.active_reg(8) as u32;
    let blob_ptr = vm.active_reg(9) as u32;
    let blob_len = vm.active_reg(10) as u32;
    let sig_ptr = vm.active_reg(11) as u32;

    let scope = match bare_attestation_scope(vm) {
        Some(s) => s,
        None => return rc(RC_BAD_CAP),
    };

    let key_bytes = if key_ptr == 0 {
        Vec::new()
    } else {
        match read_window(vm, key_ptr, ED25519_KEY_LEN, "mint_attest_cap key") {
            Ok(v) => v,
            Err(reason) => return CallOutcome::Fault(reason),
        }
    };
    let blob = match read_window(vm, blob_ptr, blob_len, "mint_attest_cap blob") {
        Ok(v) => v,
        Err(reason) => return CallOutcome::Fault(reason),
    };
    let sig_bytes = if sig_ptr == 0 {
        Vec::new()
    } else {
        match read_window(vm, sig_ptr, ED25519_SIG_LEN, "mint_attest_cap sig") {
            Ok(v) => v,
            Err(reason) => return CallOutcome::Fault(reason),
        }
    };

    let key = KeyId(key_bytes);
    let sig = Signature(sig_bytes);

    let scope_ok = match &scope {
        AttestationScopeCap::Unlimited => true,
        AttestationScopeCap::Restricted(keys) => keys.contains(&key),
    };
    if !scope_ok {
        return rc(RC_AUTHORITY);
    }

    // Signature verification. Empty sig is only legal for IDENTITY_KEY.
    if !sig.0.is_empty() && !crypto::verify(&key, &blob, &sig) {
        return rc(RC_BAD_SIG);
    }
    if sig.0.is_empty() && !crate::cap::is_identity_key(&key) {
        return rc(RC_BAD_SIG);
    }

    if host.dispatch_context {
        host.pool
            .mint_seen_set(host.endpoint_idx)
            .record(key.clone());
    }

    let blob_hash = crypto::hash(&blob);
    let cap = Cap::Protocol(ProtocolCap::Attestation(AttestationCap {
        key: key.clone(),
        blob_hash,
    }));
    vm.cap_table_set(dst_slot, cap);

    // Append to the trace so `emit_event` following the mint carries it.
    host.attestation_trace.push(AttestationEntry {
        key,
        blob_hash,
        signature: sig,
    });

    rc(RC_OK)
}

/// `setScore(identifier, score)`:
///   φ[7]=id_ptr, φ[8]=id_len, φ[9]=score.
pub fn host_set_score<H: Hardware>(vm: &mut Vm, host: &mut InvocationHost<'_, H>) -> CallOutcome {
    if !matches!(host.role, KernelRole::Verify) || !host.dispatch_context {
        return rc(RC_READONLY);
    }

    let id_ptr = vm.active_reg(7) as u32;
    let id_len = vm.active_reg(8) as u32;
    let score = vm.active_reg(9);

    let identifier = match read_window(vm, id_ptr, id_len, "setScore identifier") {
        Ok(v) => v,
        Err(reason) => return CallOutcome::Fault(reason),
    };

    host.pool.entry(host.endpoint_idx).insert(PoolEntry {
        identifier,
        score,
        blob: host.event_blob.to_vec(),
        attestation_traces: host.attestation_trace.clone(),
    });

    rc(RC_OK)
}

// =============================================================================
// Memory window helpers
// =============================================================================

/// Read a guest memory window or return a guest-fault error string.
pub(crate) fn read_window(vm: &Vm, addr: u32, len: u32, what: &str) -> Result<Vec<u8>, String> {
    if len == 0 {
        return Ok(Vec::new());
    }
    vm.read_data_cap_window(addr, len)
        .ok_or_else(|| format!("{what}: bad read window @ {addr:#x}+{len}"))
}

/// Write to a guest memory window or return a guest-fault error string.
#[allow(dead_code)] // kept for future host-call additions
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
