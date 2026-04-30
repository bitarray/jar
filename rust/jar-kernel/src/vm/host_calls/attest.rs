//! AttestationCap and ResultCap host calls.

use crate::cap::attest;
use crate::runtime::Hardware;
use crate::types::{AttestationScope, Capability, KResult, KernelError, ResultEntry};
use crate::vm::host_abi::*;
use crate::vm::host_calls::{fetch_kernel_cap, read_window, write_window};
use crate::vm::{HostCallOutcome, InvocationCtx, Vm};

pub fn host_attest<H: Hardware>(
    vm: &mut Vm,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    let cap_slot = vm.active_reg(7) as u8;
    let blob_ptr = vm.active_reg(8) as u32;
    let blob_len = vm.active_reg(9) as u32;
    let cap = match fetch_kernel_cap(vm, cap_slot) {
        Some(c) => c.clone(),
        None => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
    };
    let blob_owned = if blob_len > 0 {
        match read_window(vm, blob_ptr, blob_len, "attest blob") {
            Ok(b) => Some(b),
            Err(reason) => return Ok(HostCallOutcome::Fault(reason)),
        }
    } else {
        None
    };
    let scope = match &cap {
        Capability::AttestationCap(c) => c.scope,
        _ => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
    };
    let outcome = match (scope, blob_owned.as_deref()) {
        (AttestationScope::Direct, Some(blob)) => attest::attest(
            &cap,
            Some(blob),
            ctx.attest_cursor,
            ctx.attestation_trace,
            ctx.hw,
        )?,
        (AttestationScope::Direct, None) => {
            return Err(KernelError::Internal(
                "Direct attest requires a non-empty blob".into(),
            ));
        }
        (AttestationScope::Sealing, _) => {
            attest::attest(&cap, None, ctx.attest_cursor, ctx.attestation_trace, ctx.hw)?
        }
    };
    Ok(HostCallOutcome::Resume(
        if outcome.as_bool() { 1 } else { 0 },
        0,
    ))
}

pub fn host_attestation_key<H: Hardware>(
    vm: &mut Vm,
    _ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    let cap_slot = vm.active_reg(7) as u8;
    let out_ptr = vm.active_reg(8) as u32;
    let cap = match fetch_kernel_cap(vm, cap_slot) {
        Some(c) => c.clone(),
        None => return Ok(HostCallOutcome::Resume(RC_BAD_CAP, 0)),
    };
    let key = attest::key_of(&cap)?;
    let key_bytes = key.as_ref().to_vec();
    let key_len = key_bytes.len() as u64;
    if let Err(reason) = write_window(vm, out_ptr, &key_bytes, "attestation_key out") {
        return Ok(HostCallOutcome::Fault(reason));
    }
    Ok(HostCallOutcome::Resume(key_len, 0))
}

pub fn host_result_equal<H: Hardware>(
    vm: &mut Vm,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    let blob_ptr = vm.active_reg(7) as u32;
    let blob_len = vm.active_reg(8) as u32;
    let blob = match read_window(vm, blob_ptr, blob_len, "result_equal blob") {
        Ok(b) => b,
        Err(reason) => return Ok(HostCallOutcome::Fault(reason)),
    };
    if ctx.attest_cursor.result_pos < ctx.result_trace.len() {
        let recorded = &ctx.result_trace[ctx.attest_cursor.result_pos];
        let eq = recorded.blob == blob;
        ctx.attest_cursor.result_pos += 1;
        return Ok(HostCallOutcome::Resume(if eq { 1 } else { 0 }, 0));
    }
    ctx.result_trace.push(ResultEntry { blob });
    ctx.attest_cursor.result_pos += 1;
    Ok(HostCallOutcome::Resume(1, 0))
}
