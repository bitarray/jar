# GRANDPA Chain Selection — 3-PR Implementation Plans

Issue: https://github.com/jarchain/jar/issues/173
Date: 2026-04-01
See also: 2026-04-01-grandpa-chain-selection-design.md

---

## PR 1 — Ancestry Tracking

**Goal:** Give `GrandpaState` the ability to walk block history. No behavior change yet — pure data plumbing.

**Files to change:**
- `grey/crates/grey/src/finality.rs` — main work
- `grey/crates/grey/src/node.rs` — two call sites

**Steps:**

1. Add `use std::collections::HashMap` and `use std::collections::HashSet` to imports in `finality.rs`

2. Add two fields to `GrandpaState`:
   ```rust
   ancestry: HashMap<Hash, (Hash, Timeslot, bool)>,
   chain_equivocations: HashSet<Timeslot>,
   ```

3. Initialize both to empty in `GrandpaState::new()`

4. Implement `register_block`:
   ```rust
   pub fn register_block(&mut self, hash: Hash, parent: Hash, slot: Timeslot, ticket_sealed: bool) {
       // detect same-slot equivocation before inserting
       let equivocation = self.ancestry.values().any(|&(_, s, _)| s == slot);
       if equivocation { self.chain_equivocations.insert(slot); }
       self.ancestry.insert(hash, (parent, slot, ticket_sealed));
   }
   ```

5. Implement `ancestors`:
   ```rust
   fn ancestors(&self, hash: Hash) -> Vec<Hash> {
       let mut result = vec![hash];
       let mut current = hash;
       while current != self.finalized_hash {
           match self.ancestry.get(&current) {
               Some(&(parent, _, _)) => { result.push(parent); current = parent; }
               None => break,
           }
       }
       result
   }
   ```

6. In `check_finality` (where `finalized_slot` is updated), add pruning:
   ```rust
   self.ancestry.retain(|_, &mut (_, slot, _)| slot > self.finalized_slot);
   self.chain_equivocations.retain(|&slot| slot > self.finalized_slot);
   ```
   Note: `chain_equivocations` stores timeslots — pruning removes slots that are now finalized.

7. In `node.rs`, at both `update_best_block` call sites, add `register_block` call just before:
   ```rust
   // SealKeySeries lives on epoch state, not the header.
   // Ticket-sealed = current epoch is in ticket mode (not fallback).
   let ticket_sealed = grey_consensus::safrole::is_ticket_sealed(&state.safrole.seal_key_series);
   grandpa.register_block(header_hash, header.parent_hash, header.timeslot, ticket_sealed);
   grandpa.update_best_block(header_hash, header.timeslot); // unchanged for now
   ```
   Note: use `header.timeslot` (the `Header` field), not any local `current_slot` variable.

8. Write tests in `finality.rs`:
   - `test_register_single_block` — register one block, ancestors returns it
   - `test_ancestors_chain` — register A→B→C, ancestors(C) = [C, B, A]
   - `test_chain_equivocation_detected` — two blocks at same slot trigger `chain_equivocations`
   - `test_pruning_on_finalize` — after finalizing slot 5, ancestry has no entries ≤ 5

**GP §19 to read:** §19.1 for block ancestry context. No equations needed for this PR.

**Confirmed field names** (from `grey-types/src/header.rs` and `grey-types/src/state.rs`):
- `header.parent_hash: Hash` ✓
- `header.timeslot: Timeslot` ✓ (not `slot`)
- `header.seal: BandersnatchSignature` — no type tag, can't determine ticket/fallback from header alone
- `state.safrole.seal_key_series: SealKeySeries` — use this to check ticket vs fallback mode

---

## PR 2 — `is_acceptable` + Chain Metric + Best-Block Selection

**Goal:** Replace the slot-height `update_best_block` with proper §19 chain selection.

**Prerequisite:** PR 1 merged.

**Files to change:**
- `grey/crates/grey/src/finality.rs`
- `grey/crates/grey/src/node.rs` (signature change at 2 call sites)

**Steps:**

1. Add `use std::collections::BTreeSet` import if not already present (for `completed_audits` parameter)

2. Implement `is_acceptable`:
   ```rust
   fn is_acceptable(&self, hash: Hash, completed_audits: &BTreeSet<Hash>) -> bool {
       let chain = self.ancestors(hash);
       // Check 1: last finalized block is an ancestor
       if !chain.contains(&self.finalized_hash) { return false; }
       // Check 2: all work reports audited — stubbed, TODO: map block→reports
       let _ = completed_audits;
       // Check 3: no same-slot equivocations in this chain
       for &h in &chain {
           if let Some(&(_, slot, _)) = self.ancestry.get(&h) {
               if self.chain_equivocations.contains(&slot) { return false; }
           }
       }
       true
   }
   ```

3. Implement `chain_metric`:
   ```rust
   fn chain_metric(&self, hash: Hash) -> u32 {
       self.ancestors(hash)
           .iter()
           .filter(|&&h| self.ancestry.get(&h).map(|&(_, _, s)| s).unwrap_or(false))
           .count() as u32
   }
   ```

4. Replace `update_best_block`:
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

5. Update `node.rs` call sites — add `&audit_state.completed_audits` parameter.

6. Write tests:
   - `test_is_acceptable_finalized_ancestor` — block whose chain doesn't include finalized is rejected
   - `test_is_acceptable_chain_equivocation` — block with equivocating slot in ancestry is rejected
   - `test_chain_metric_prefers_ticket_sealed` — two chains, one with more ticket-sealed blocks wins
   - `test_update_best_block_rejects_unacceptable` — unacceptable block doesn't become best
   - `test_update_best_block_uses_metric` — higher-metric block replaces lower-metric even if lower slot

**GP §19 to read:** §19.3 (all three `is_acceptable` conditions verbatim), §19.4 (chain metric `m` definition). These are the equations you should implement directly.

**Research gap:** Check if `is_ticket_sealed` from PR 1 correctly maps to what GP §19 calls "ticket-sealed" vs "fallback-sealed". Verify in Appendix B.

---

## PR 3 — Proper GHOST Prevote Target

**Goal:** Replace the heuristic `prevote_ghost()` with the standard GHOST algorithm.

**Prerequisite:** PR 1 merged (needs ancestry tree). PR 2 not required.

**Files to change:**
- `grey/crates/grey/src/finality.rs` only

**Steps:**

1. Replace `prevote_ghost` body entirely with the subtree-vote algorithm:
   ```rust
   pub fn prevote_ghost(&self) -> Option<(Hash, Timeslot)> {
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

2. `subtree_votes` is a nested `fn` — Rust allows this inside `impl` methods. Recursion depth is bounded by the number of unfinalized blocks (typically very small between finalizations).

3. Keep the threshold check at the call site in `create_prevote` unchanged — it already checks `has_prevote_supermajority()` before calling `prevote_ghost()`.

4. Write tests:
   - `test_ghost_linear_chain` — A→B→C, all prevotes on C, GHOST returns C
   - `test_ghost_fork` — A forks to B and C; 3 prevotes on B-subtree, 1 on C-subtree; GHOST returns B
   - `test_ghost_empty` — no prevotes, returns None
   - `test_ghost_stops_at_finalized` — doesn't walk below `finalized_hash`
   - `test_ghost_vs_heuristic` — construct a case where old heuristic and GHOST differ; verify GHOST is correct

**GP §19 to read:** §19.5 — GHOST target `G` definition. The algorithm is exactly "greedy heaviest observed subtree" starting from the last finalized block.

**Research gap:** The GP definition uses a set of blocks `S` and a set of votes `V`. Map `S` to your `ancestry.keys()` and `V` to `prevotes.values()`. Confirm whether the GHOST target must itself have ≥ threshold votes, or just that the path to it does — the answer changes what you return when all branches are thin.
