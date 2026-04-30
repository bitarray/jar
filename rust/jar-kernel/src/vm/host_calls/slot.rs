//! Slot host calls (step-3-only): slot_clear, slot_read.

use crate::runtime::Hardware;
use crate::types::{KResult, KernelError, KernelRole, SlotContent};
use crate::vm::host_abi::*;
use crate::vm::host_calls::write_window;
use crate::vm::{HostCallOutcome, InvocationCtx, Vm};

pub fn host_slot_clear<H: Hardware>(
    _vm: &mut Vm,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    if !matches!(ctx.role, KernelRole::AggregateMerge) {
        return Ok(HostCallOutcome::Fault(
            "slot_clear is only valid in step-3".into(),
        ));
    }
    if ctx.slot_emission.is_some() {
        return Err(KernelError::Internal(
            "step-3 emitted more than one slot replacement".into(),
        ));
    }
    *ctx.slot_emission = Some(SlotContent::Empty);
    Ok(HostCallOutcome::Resume(RC_OK, 0))
}

pub fn host_slot_read<H: Hardware>(
    vm: &mut Vm,
    ctx: &mut InvocationCtx<'_, H>,
) -> KResult<HostCallOutcome> {
    let out_ptr = vm.active_reg(7) as u32;
    let out_max = vm.active_reg(8) as u32;
    let prev = match ctx.prev_slot {
        Some(p) => p,
        None => {
            return Ok(HostCallOutcome::Fault("slot_read outside step-3".into()));
        }
    };
    let bytes = encode_slot(prev);
    let to_write = bytes.len().min(out_max as usize);
    if to_write > 0
        && let Err(reason) = write_window(vm, out_ptr, &bytes[..to_write], "slot_read out")
    {
        return Ok(HostCallOutcome::Fault(reason));
    }
    Ok(HostCallOutcome::Resume(bytes.len() as u64, 0))
}

/// Canonical encoding of `SlotContent` for `host_slot_read`. Mirrors the
/// shape used in state-root encoding — flat, length-prefixed, kernel-static.
fn encode_slot(slot: &SlotContent) -> Vec<u8> {
    let mut buf = Vec::new();
    match slot {
        SlotContent::Empty => {
            buf.push(0);
        }
        SlotContent::AggregatedDispatch {
            payload,
            caps,
            attestation_trace,
            result_trace,
        } => {
            buf.push(1);
            push_bytes(&mut buf, payload);
            push_bytes(&mut buf, caps);
            push_u64(&mut buf, attestation_trace.len() as u64);
            for a in attestation_trace {
                push_bytes(&mut buf, &a.key.0);
                buf.extend_from_slice(a.blob_hash.as_ref());
                push_bytes(&mut buf, &a.signature.0);
            }
            push_u64(&mut buf, result_trace.len() as u64);
            for r in result_trace {
                push_bytes(&mut buf, &r.blob);
            }
        }
        SlotContent::AggregatedTransact {
            target,
            payload,
            caps,
            attestation_trace,
            result_trace,
        } => {
            buf.push(2);
            push_u64(&mut buf, target.0);
            push_bytes(&mut buf, payload);
            push_bytes(&mut buf, caps);
            push_u64(&mut buf, attestation_trace.len() as u64);
            for a in attestation_trace {
                push_bytes(&mut buf, &a.key.0);
                buf.extend_from_slice(a.blob_hash.as_ref());
                push_bytes(&mut buf, &a.signature.0);
            }
            push_u64(&mut buf, result_trace.len() as u64);
            for r in result_trace {
                push_bytes(&mut buf, &r.blob);
            }
        }
    }
    buf
}

fn push_u64(buf: &mut Vec<u8>, x: u64) {
    buf.extend_from_slice(&x.to_le_bytes());
}

fn push_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    push_u64(buf, b.len() as u64);
    buf.extend_from_slice(b);
}
