//! Pinning rules: the constraints the kernel enforces on Dispatch /
//! Transact / Schedule / DispatchRef / TransactRef caps.
//!
//! 1. Dispatch / Transact / Schedule stay in `born_in` CNode. `cnode_grant`,
//!    `cnode_move`, `cap_derive` all reject placement in any other persistent
//!    CNode.
//! 2. DispatchRef / TransactRef are Frame-only. Any persistent placement is
//!    rejected. (No ScheduleRef — Schedule is never derivable to a callable
//!    form.)
//! 3. At a top-level invocation boundary (`cap_call` to a Dispatch /
//!    DispatchRef / Transact / TransactRef target), arg caps must not be any
//!    pinned-or-ref variant (the four above plus Schedule).

use crate::types::{CNodeId, CapId, Capability, KResult, KernelError, State};

use crate::state::cap_registry;

/// Check that placing `cap` at `(target_cnode)` is permissible. `target_cnode`
/// is the CNodeId being granted into; for moves use the destination cnode.
pub fn check_grant_or_move(cap: &Capability, target_cnode: CNodeId) -> KResult<()> {
    let born_in = match cap {
        Capability::Dispatch(c) => c.born_in,
        Capability::Transact(c) => c.born_in,
        Capability::Schedule(c) => c.born_in,
        Capability::DispatchRef(_) | Capability::TransactRef(_) => {
            return Err(KernelError::Pinning(
                "DispatchRef/TransactRef are Frame-only — cannot grant to a persistent CNode"
                    .into(),
            ));
        }
        _ => return Ok(()),
    };
    if born_in != target_cnode {
        Err(KernelError::Pinning(format!(
            "Dispatch/Transact/Schedule cap pinned to {:?}; cannot place in {:?}",
            born_in, target_cnode
        )))
    } else {
        Ok(())
    }
}

/// Check that deriving from `source` to a new cap with `new_cap` is allowed,
/// given whether the destination is persistent (CNode) or ephemeral (Frame).
pub fn check_derive(
    state: &State,
    source: CapId,
    new_cap: &Capability,
    dest_persistent: bool,
) -> KResult<()> {
    let src = cap_registry::lookup(state, source)?;
    match (&src.cap, new_cap) {
        // Dispatch → Dispatch: persistent dest only.
        (Capability::Dispatch(_), Capability::Dispatch(_)) => {
            if !dest_persistent {
                return Err(KernelError::Pinning(
                    "Dispatch derivation must target a persistent CNode".into(),
                ));
            }
            Ok(())
        }
        (Capability::Dispatch(_), Capability::DispatchRef(_)) => {
            if dest_persistent {
                return Err(KernelError::Pinning(
                    "DispatchRef must be derived into a Frame, not a persistent CNode".into(),
                ));
            }
            Ok(())
        }
        (Capability::DispatchRef(_), Capability::DispatchRef(_)) => {
            if dest_persistent {
                return Err(KernelError::Pinning(
                    "DispatchRef derivation must target a Frame".into(),
                ));
            }
            Ok(())
        }
        (Capability::Transact(_), Capability::Transact(_)) => {
            if !dest_persistent {
                return Err(KernelError::Pinning(
                    "Transact derivation must target a persistent CNode".into(),
                ));
            }
            Ok(())
        }
        (Capability::Transact(_), Capability::TransactRef(_))
        | (Capability::TransactRef(_), Capability::TransactRef(_)) => {
            if dest_persistent {
                return Err(KernelError::Pinning(
                    "TransactRef derivation must target a Frame".into(),
                ));
            }
            Ok(())
        }
        // Schedule → Schedule: persistent dest only. No SchedRef variant.
        (Capability::Schedule(_), Capability::Schedule(_)) => {
            if !dest_persistent {
                return Err(KernelError::Pinning(
                    "Schedule derivation must target a persistent CNode".into(),
                ));
            }
            Ok(())
        }
        // VaultRef → VaultRef (rights subset, not enforced here): any dest OK.
        (Capability::VaultRef(_), Capability::VaultRef(_)) => Ok(()),
        // Code → Code: refcount-shared blob; any dest OK.
        (Capability::Code(_), Capability::Code(_)) => Ok(()),
        // Data → Data: Arc-shared content; any dest OK. The persistent
        // DataCap is immutable, so a derived child holding the same
        // Arc<Vec<u8>> is just an alias for refcount purposes.
        (Capability::Data(_), Capability::Data(_)) => Ok(()),
        _ => Err(KernelError::Pinning(format!(
            "unsupported derive source/destination shape: {:?} → {:?}",
            std::mem::discriminant(&src.cap),
            std::mem::discriminant(new_cap),
        ))),
    }
}

/// Arg-scan: when `cap_call` exercises a Dispatch / DispatchRef / Transact /
/// TransactRef target, the args must not contain any of those four cap types.
/// This prevents cross-sibling dispatch via arg-passing.
pub fn arg_scan(state: &State, arg_caps: &[CapId]) -> KResult<()> {
    for &c in arg_caps {
        let cap = &cap_registry::lookup(state, c)?.cap;
        if cap.is_pinned_or_ref() {
            return Err(KernelError::Pinning(
                "pinned or ephemeral cap rejected in cap_call args at invocation boundary".into(),
            ));
        }
    }
    Ok(())
}
