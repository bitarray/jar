//! State root: hash over canonically-encoded σ.
//!
//! Stub Merkle: not a tree, just a flat hash via the kernel-static `crypto::hash`.
//! Sufficient for "the chain's `Schedule(block_final)` claims this root and
//! checks it" semantics. Real Merkle-trie commitment is a follow-up.

use crate::types::{Hash, RegCap, State, VaultRights};

use crate::crypto;

/// Canonical hash digest over σ. Maps and structured data are walked in
/// `BTreeMap` order, which is canonical because every map in `State` is
/// `BTreeMap`. Hashing is kernel-static — no Hardware needed.
pub fn state_root(state: &State) -> Hash {
    let mut buf = Vec::with_capacity(4096);

    push_u64(&mut buf, state.id_counters.next_vault_id);
    push_u64(&mut buf, state.chain_index);
    push_u64(&mut buf, state.validators.len() as u64);
    for k in &state.validators {
        push_u64(&mut buf, k.0.len() as u64);
        buf.extend_from_slice(&k.0);
    }

    push_u64(&mut buf, state.transact_endpoints.len() as u64);
    for ep in &state.transact_endpoints {
        encode_endpoint(&mut buf, ep);
    }
    push_u64(&mut buf, state.dispatch_endpoints.len() as u64);
    for ep in &state.dispatch_endpoints {
        encode_endpoint(&mut buf, ep);
    }

    push_u64(&mut buf, state.vaults.len() as u64);
    for (vid, vault) in &state.vaults {
        push_u64(&mut buf, vid.0);
        buf.push(vault.init_cap);
        for (i, slot) in vault.slots.slots.iter().enumerate() {
            buf.push(i as u8);
            match slot {
                None => buf.push(0),
                Some(cap) => encode_vault_cap(&mut buf, cap),
            }
        }
    }

    crypto::hash(&buf)
}

fn encode_endpoint(buf: &mut Vec<u8>, ep: &crate::types::EventEndpointCap) {
    push_u64(buf, ep.vault_id.0);
    push_u64(buf, ep.gas_budget);
    push_u64(buf, ep.memory_budget as u64);
}

fn encode_vault_cap(buf: &mut Vec<u8>, cap: &RegCap) {
    match cap {
        RegCap::VaultRef(vr) => {
            buf.push(1);
            push_u64(buf, vr.vault_id.0);
            buf.push(vault_rights_byte(&vr.rights));
        }
        RegCap::Code(c) => {
            buf.push(2);
            push_u64(buf, c.blob.len() as u64);
            buf.extend_from_slice(&c.blob);
        }
        RegCap::Data(d) => {
            buf.push(3);
            push_u64(buf, d.content.len() as u64);
            buf.extend_from_slice(&d.content);
            push_u64(buf, d.page_count as u64);
        }
        RegCap::Resource(r) => {
            buf.push(4);
            // ResourceKind discriminant + payload encoded by debug-form.
            // Cheap and canonical (small enum, deterministic Debug).
            let dbg = format!("{:?}", r.0);
            push_u64(buf, dbg.len() as u64);
            buf.extend_from_slice(dbg.as_bytes());
        }
    }
}

fn push_u64(buf: &mut Vec<u8>, x: u64) {
    buf.extend_from_slice(&x.to_le_bytes());
}

fn vault_rights_byte(r: &VaultRights) -> u8 {
    (r.read as u8)
        | ((r.initialize as u8) << 1)
        | ((r.grant as u8) << 2)
        | ((r.revoke as u8) << 3)
        | ((r.derive as u8) << 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_state_root_is_stable() {
        let s1 = State::empty();
        let s2 = State::empty();
        assert_eq!(state_root(&s1), state_root(&s2));
    }
}
