# GRANDPA Chain Selection — Design (GP §19)

Issue: https://github.com/jarchain/jar/issues/173
Date: 2026-04-01
Scope: 3 PRs

---

## Problem

`update_best_block()` uses a bare slot-height rule (`if new_slot > best_slot`).
GP §19 requires:
1. **Acceptability check** — a block is only a valid voting candidate if it passes 3 conditions.
2. **Chain metric** — among acceptable blocks, prefer the one with more ticket-sealed blocks in the unfinalized suffix.
3. **Proper GHOST** — `prevote_ghost()` should use the standard GHOST algorithm on the ancestry tree, not a heuristic.

---

## Data Model Changes (`GrandpaState` in `finality.rs`)

Two new fields:

```rust
/// Unfinalized block ancestry: hash → (parent_hash, timeslot, is_ticket_sealed).
/// Populated via register_block(), pruned on finalization.
ancestry: HashMap<Hash, (Hash, Timeslot, bool)>,

/// Timeslots at which two distinct blocks exist in the unfinalized chain.
/// Used by is_acceptable() check 3.
chain_equivocations: HashSet<Timeslot>,
```

New public method:

```rust
/// Call before update_best_block() whenever a block arrives (authored or imported).
pub fn register_block(&mut self, hash: Hash, parent: Hash, slot: Timeslot, ticket_sealed: bool)
```

`register_block` also detects same-slot equivocations: if a different block at the same `slot` already exists in `ancestry`, add `slot` to `chain_equivocations`.

Private helper:

```rust
/// Walk ancestry from `hash` back toward finalized block.
/// Returns hashes in child→ancestor order, stopping at (and including) finalized_hash.
fn ancestors(&self, hash: Hash) -> Vec<Hash>
```

Pruning: on finalization, drop all `ancestry` and `chain_equivocations` entries at slots ≤ `finalized_slot`.

---

## `is_acceptable` (GP §19)

```rust
fn is_acceptable(&self, hash: Hash, completed_audits: &BTreeSet<Hash>) -> bool {
    let chain = self.ancestors(hash);

    // Check 1: last finalized block is an ancestor
    if !chain.contains(&self.finalized_hash) { return false; }

    // Check 2: all work reports in unfinalized suffix are audited
    // (stubbed in PR 1 & 2; full integration deferred)
    let _ = completed_audits;

    // Check 3: no same-slot block equivocations in this chain
    for &h in &chain {
        let (_, slot, _) = self.ancestry[&h];
        if self.chain_equivocations.contains(&slot) { return false; }
    }
    true
}
```

---

## Chain Metric (GP §19.4)

```rust
fn chain_metric(&self, hash: Hash) -> u32 {
    self.ancestors(hash)
        .iter()
        .filter(|&&h| self.ancestry.get(&h).map(|&(_, _, sealed)| sealed).unwrap_or(false))
        .count() as u32
}
```

---

## Replaced `update_best_block`

```rust
pub fn update_best_block(&mut self, hash: Hash, completed_audits: &BTreeSet<Hash>) {
    if !self.is_acceptable(hash, completed_audits) { return; }
    let metric = self.chain_metric(hash);
    let best_metric = self.chain_metric(self.best_block_hash);
    if metric > best_metric {
        self.best_block_hash = hash;
        self.best_block_slot = self.ancestry.get(&hash).map(|e| e.1).unwrap_or(0);
    }
}
```

Callers in `node.rs` pass `&audit_state.completed_audits`.

---

## Proper GHOST Prevote Target (GP §19)

Standard GHOST: starting from `finalized_hash`, greedily pick the child with the most prevotes in its subtree.

```rust
pub fn prevote_ghost(&self) -> Option<(Hash, Timeslot)> {
    // Build children map from ancestry
    let mut children: HashMap<Hash, Vec<Hash>> = HashMap::new();
    for (&hash, &(parent, _, _)) in &self.ancestry {
        children.entry(parent).or_default().push(hash);
    }

    fn subtree_votes(
        hash: Hash,
        children: &HashMap<Hash, Vec<Hash>>,
        prevotes: &BTreeMap<ValidatorIndex, Vote>,
    ) -> usize {
        let direct = prevotes.values().filter(|v| v.block_hash == hash).count();
        let child_sum: usize = children.get(&hash)
            .map(|cs| cs.iter().map(|&c| subtree_votes(c, children, prevotes)).sum())
            .unwrap_or(0);
        direct + child_sum
    }

    let mut current = self.finalized_hash;
    loop {
        let best_child = children.get(&current)
            .and_then(|cs| cs.iter().max_by_key(|&&c| subtree_votes(c, &children, &self.prevotes)));
        match best_child {
            Some(&child) if subtree_votes(child, &children, &self.prevotes) > 0 => {
                current = child;
            }
            _ => break,
        }
    }

    if current == self.finalized_hash { return None; }
    let slot = self.ancestry.get(&current)?.1;
    Some((current, slot))
}
```

---

## 3-PR Delivery Plan

| PR | Title | Key changes |
|----|-------|-------------|
| 1 | Ancestry tracking in GrandpaState | `register_block`, `ancestors`, `chain_equivocations`, pruning, node.rs wiring |
| 2 | is_acceptable + chain metric + best-block selection | `is_acceptable`, `chain_metric`, replace `update_best_block` |
| 3 | Proper GHOST prevote target | Replace heuristic `prevote_ghost` with subtree-vote GHOST |

Each PR is independent, reviewable, and mergeable on its own.

---

## Research Areas (GP §19)

Before implementing, read these sections of the Gray Paper:

- **§19.1–19.2**: GRANDPA overview, round structure
- **§19.3**: `is_acceptable` — the three conditions verbatim
- **§19.4**: Chain metric `m` — ticket-sealed block count definition
- **§19.5**: GHOST target `G` — algorithm definition
- **Appendix B**: Bandersnatch ticket sealing vs fallback sealing (needed to understand `is_ticket_sealed`)
