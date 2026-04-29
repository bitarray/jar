//! State root: blake2b over canonically-encoded σ.
//!
//! Stub Merkle: not a tree, just a flat hash. Sufficient for "the chain's
//! `block_finalization_cap` claims this root and checks it" semantics. Real
//! Merkle-trie commitment is a follow-up.

use jar_crypto::blake2b_256;
use jar_types::{Hash, State};

/// Canonical blake2b digest over σ. Maps and structured data are walked in
/// `BTreeMap` order, which is canonical because every map in `State` is
/// `BTreeMap`.
pub fn state_root(state: &State) -> Hash {
    let mut buf = Vec::with_capacity(4096);

    push_u64(&mut buf, state.id_counters.next_vault_id);
    push_u64(&mut buf, state.id_counters.next_cnode_id);
    push_u64(&mut buf, state.id_counters.next_cap_id);

    push_u64(&mut buf, state.transact_space_cnode.0);
    push_u64(&mut buf, state.dispatch_space_cnode.0);

    push_u64(&mut buf, state.vaults.len() as u64);
    for (vid, vault) in &state.vaults {
        push_u64(&mut buf, vid.0);
        buf.extend_from_slice(&vault.code_hash.0);
        push_u64(&mut buf, vault.quota_items);
        push_u64(&mut buf, vault.quota_bytes);
        push_u64(&mut buf, vault.total_footprint);
        for (i, slot) in vault.slots.slots.iter().enumerate() {
            buf.push(i as u8);
            push_u64(&mut buf, slot.map(|c| c.0).unwrap_or(0));
        }
        push_u64(&mut buf, vault.storage.len() as u64);
        for (k, v) in &vault.storage {
            push_u64(&mut buf, k.len() as u64);
            buf.extend_from_slice(k);
            push_u64(&mut buf, v.len() as u64);
            buf.extend_from_slice(v);
        }
    }

    push_u64(&mut buf, state.cnodes.len() as u64);
    for (cid, cnode) in &state.cnodes {
        push_u64(&mut buf, cid.0);
        for (i, slot) in cnode.slots.iter().enumerate() {
            buf.push(i as u8);
            push_u64(&mut buf, slot.map(|c| c.0).unwrap_or(0));
        }
    }

    push_u64(&mut buf, state.cap_registry.len() as u64);
    for (cap_id, record) in &state.cap_registry {
        push_u64(&mut buf, cap_id.0);
        push_u64(&mut buf, record.issuer.map(|c| c.0).unwrap_or(0));
        push_u64(&mut buf, record.narrowing.len() as u64);
        buf.extend_from_slice(&record.narrowing);
        // The Capability discriminant + payload encoded by debug-form. Cheap
        // and canonical given the BTreeMap iteration order.
        let cap_dbg = format!("{:?}", record.cap);
        push_u64(&mut buf, cap_dbg.len() as u64);
        buf.extend_from_slice(cap_dbg.as_bytes());
    }

    blake2b_256(&buf)
}

fn push_u64(buf: &mut Vec<u8>, x: u64) {
    buf.extend_from_slice(&x.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use jar_types::State;

    #[test]
    fn empty_state_root_is_stable() {
        let s1 = State::empty();
        let s2 = State::empty();
        assert_eq!(state_root(&s1), state_root(&s2));
    }
}
