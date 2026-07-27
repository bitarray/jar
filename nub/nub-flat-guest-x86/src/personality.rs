//! The `GuestPersonality` impl — the whole of the flat kernel policy.
//!
//! Compare with `javm-guest-x86`'s `call_loop.rs` (2,156 lines): almost
//! all of that is capability semantics — sub-VM spawn, cnode resolution,
//! yield routing, per-frame gas meters. Flat has none of those, so what
//! is left is the irreducible minimum a personality must decide:
//! where a root frame comes from, who pays for gas, and what an exit
//! means.

use nub_arch_x86::jit_run::ExitInfo;
use nub_arch_x86::personality::GuestPersonality;
use nub_arch_x86::personality::ObjHash;
use nub_arch_x86::task::{Flow, StackEntry, TaskCtx};
use nub_arch_x86_abi::SCRATCHPAD_HEAD_LEN;
use nub_recompiler_x86::codegen::{EXIT_HOST_CALL, EXIT_OOG};

use crate::frame::{ERR_PROGRAM_NOT_FOUND, ERR_UNSUPPORTED_ECALL, FlatFrame};
use crate::store::{FLAT_STORE, FlatStore};

/// The clean-halt host call. `nub-rt`'s endpoint trampoline ends in a
/// bare `ecall`, which the linker rewrites to `custom-0 ecalli imm=0`;
/// the substrate surfaces it as `EXIT_HOST_CALL` with `op == 0`.
const OP_HALT: u32 = 0;

pub struct Flat;

impl GuestPersonality for Flat {
    type Frame = FlatFrame;
    /// No per-frame gas meters: the host budget is the only bank, so
    /// there is nothing to key a meter by.
    type MeterKey = ();
    /// No per-entry metadata: no owner edges, no catch sets, no gas
    /// scopes.
    type EntryMeta = ();
    type Store = FlatStore;

    fn store() -> &'static Self::Store {
        &FLAT_STORE
    }

    fn build_root_frame(
        root: &ObjHash,
        endpoint_idx: u32,
        args: [u64; 4],
    ) -> Result<(Self::Frame, Self::EntryMeta), u32> {
        let program = FLAT_STORE.get(root).ok_or(ERR_PROGRAM_NOT_FOUND)?;
        let endpoint =
            u8::try_from(endpoint_idx).map_err(|_| crate::frame::ERR_NO_SUCH_ENDPOINT)?;
        let frame = FlatFrame::new(program, endpoint, args)?;
        Ok((frame, ()))
    }

    /// Always host-budgeted. A personality with its own gas objects
    /// would return the meter covering `stack[idx]` here.
    fn active_meter(_stack: &[StackEntry<Self>], _idx: usize) -> Option<Self::MeterKey> {
        None
    }

    /// The stack is always one deep, so a halt ends the task.
    fn on_halt(ctx: &mut TaskCtx<'_, Self>, info: &ExitInfo) -> Result<Flow, u32> {
        let head = scratchpad_head(ctx, info);
        Ok(ctx.done(info.exit_reason, info.exit_arg, info.regs[7], head))
    }

    /// The only ecall a flat program can make is its own clean halt.
    ///
    /// Anything else is a program built against a richer personality's
    /// ABI — reject it loudly rather than treating an unknown operation
    /// as a halt, which would silently return whatever happened to be
    /// in the return register.
    ///
    /// The ecall floor is the personality's to charge: the interpreter
    /// bills it inside its own loop, so a personality that skips it here
    /// makes the two engines disagree on gas by exactly the floor. That
    /// is not a rounding difference — for a metered VM the backends must
    /// charge identically or they are not interchangeable.
    fn on_ecall(ctx: &mut TaskCtx<'_, Self>, op: u32, info: &ExitInfo) -> Result<Flow, u32> {
        if op != OP_HALT {
            return Err(ERR_UNSUPPORTED_ECALL);
        }

        let is_ecalli = info.exit_reason == EXIT_HOST_CALL;
        let cost = nub_exec::gas_const::ecall_dynamic_cost(is_ecalli) as i64;
        if ctx.gas.live_gas < cost {
            // Nothing to top up from — flat frames are host-budgeted —
            // so an exhausted budget at the final ecall is terminal.
            return Ok(ctx.done(EXIT_OOG, 0, info.regs[7], [0u8; SCRATCHPAD_HEAD_LEN]));
        }
        ctx.gas.live_gas -= cost;

        let head = scratchpad_head(ctx, info);
        Ok(ctx.done(info.exit_reason, info.exit_arg, info.regs[7], head))
    }
}

/// The first [`SCRATCHPAD_HEAD_LEN`] bytes of the data region, read from
/// the frame's effective memory (overlay first, then backing).
///
/// The interpreter surfaces the same window from its flat buffer, so
/// both engines return byte-identical result data.
fn scratchpad_head(ctx: &TaskCtx<'_, Flat>, _info: &ExitInfo) -> [u8; SCRATCHPAD_HEAD_LEN] {
    let mut head = [0u8; SCRATCHPAD_HEAD_LEN];
    let top = ctx.top_idx();
    if let Some(frame) = frame_at(ctx, top)
        && let Some(page) = frame.mem.page_bytes(0)
    {
        let n = SCRATCHPAD_HEAD_LEN.min(page.len());
        head[..n].copy_from_slice(&page[..n]);
    }
    head
}

fn frame_at<'a>(ctx: &'a TaskCtx<'_, Flat>, idx: usize) -> Option<&'a FlatFrame> {
    match &ctx.stack.get(idx)?.kind {
        nub_arch_x86::task::EntryKind::Instance(frame) => Some(frame),
        nub_arch_x86::task::EntryKind::Reference => None,
    }
}
