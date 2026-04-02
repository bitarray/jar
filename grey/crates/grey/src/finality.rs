//! Simplified GRANDPA finality protocol.
//!
//! Implements a Byzantine-fault-tolerant finality gadget inspired by GRANDPA
//! (GHOST-based Recursive ANcestor Deriving Prefix Agreement) per Gray Paper Section 19.
//!
//! Validators participate in rounds:
//! 1. Prevote: vote for the best block they've seen
//! 2. Precommit: commit to a finalized block once 2/3+1 prevotes agree
//! 3. Finalization: block is final when 2/3+1 precommits agree

use grey_consensus::genesis::ValidatorSecrets;
#[cfg(test)]
use grey_types::config::Config;
use grey_types::{Ed25519Signature, Hash, Timeslot, ValidatorIndex};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Signing context for GRANDPA prevotes.
const PREVOTE_CONTEXT: &[u8] = b"jam_prevote";
/// Signing context for GRANDPA precommits.
const PRECOMMIT_CONTEXT: &[u8] = b"jam_precommit";

/// A GRANDPA vote (prevote or precommit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vote {
    /// The block hash being voted for.
    pub block_hash: Hash,
    /// The block's timeslot (height proxy).
    pub block_slot: Timeslot,
    /// The round number.
    pub round: u64,
    /// The validator who cast this vote.
    pub validator_index: ValidatorIndex,
    /// Signature over the vote.
    pub signature: Ed25519Signature,
}

/// Type of vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteType {
    Prevote,
    Precommit,
}

/// A finality vote message for network transmission.
#[derive(Debug, Clone)]
pub struct VoteMessage {
    pub vote_type: VoteType,
    pub vote: Vote,
}

/// State of the GRANDPA finality gadget.
pub struct GrandpaState {
    /// Current round number.
    pub round: u64,
    /// Prevotes received in the current round.
    pub prevotes: BTreeMap<ValidatorIndex, Vote>,
    /// Precommits received in the current round.
    pub precommits: BTreeMap<ValidatorIndex, Vote>,
    /// Best finalized block hash.
    pub finalized_hash: Hash,
    /// Best finalized block slot.
    pub finalized_slot: Timeslot,
    /// Our best candidate for voting.
    pub best_block_hash: Hash,
    /// Our best candidate slot.
    pub best_block_slot: Timeslot,
    /// Whether we've sent our prevote this round.
    pub prevoted: bool,
    /// Whether we've sent our precommit this round.
    pub precommitted: bool,
    /// Total validators (for threshold computation).
    pub total_validators: u16,
    /// Detected equivocations: validators who voted for conflicting blocks.
    pub equivocations: BTreeSet<ValidatorIndex>,
    /// Archive of prevotes from unfinalized rounds: (round, validator) → block_hash.
    /// Used to detect equivocation for votes received after round advancement.
    prevote_archive: BTreeMap<(u64, ValidatorIndex), Hash>,
    /// Archive of precommits from unfinalized rounds: (round, validator) → block_hash.
    precommit_archive: BTreeMap<(u64, ValidatorIndex), Hash>,
    /// Round at which the archive was last pruned (finalized round).
    archive_pruned_round: u64,
    /// Buffered prevotes for future rounds. Replayed when we advance to that round.
    pending_future_prevotes: Vec<Vote>,
    /// Buffered precommits for future rounds. Replayed when we advance to that round.
    pending_future_precommits: Vec<Vote>,
    /// Block ancestry: hash → (parent_hash, slot, ticket_sealed).
    /// Used for chain-selection and GHOST. Pruned on finalization.
    pub ancestry: HashMap<Hash, (Hash, Timeslot, bool)>,
    /// Slots at which two different blocks were produced (same-slot equivocation).
    /// Pruned on finalization.
    pub chain_equivocations: HashSet<Timeslot>,
}

impl GrandpaState {
    pub fn new(total_validators: u16) -> Self {
        Self {
            round: 1,
            prevotes: BTreeMap::new(),
            precommits: BTreeMap::new(),
            finalized_hash: Hash::ZERO,
            finalized_slot: 0,
            best_block_hash: Hash::ZERO,
            best_block_slot: 0,
            prevoted: false,
            precommitted: false,
            total_validators,
            equivocations: BTreeSet::new(),
            prevote_archive: BTreeMap::new(),
            precommit_archive: BTreeMap::new(),
            archive_pruned_round: 0,
            pending_future_prevotes: Vec::new(),
            pending_future_precommits: Vec::new(),
            ancestry: HashMap::new(),
            chain_equivocations: HashSet::new(),
        }
    }

    /// Load persisted votes from a previous session into the current round.
    ///
    /// `persisted_votes` is a list of `(vote_type, validator_index, block_hash, block_slot, signature)`.
    /// Vote type: 0 = prevote, 1 = precommit.
    /// Only votes matching the current round are loaded; others are ignored.
    /// Returns the number of votes loaded.
    pub fn load_persisted_votes(
        &mut self,
        round: u64,
        persisted_votes: &[(u8, u16, Hash, u32, [u8; 64])],
    ) -> usize {
        self.round = round;
        let mut loaded = 0;
        for &(vote_type, validator_index, block_hash, block_slot, signature) in persisted_votes {
            let vote = Vote {
                block_hash,
                block_slot,
                round,
                validator_index,
                signature: Ed25519Signature(signature),
            };
            match vote_type {
                0 => {
                    // Prevote
                    self.prevotes.entry(validator_index).or_insert_with(|| {
                        loaded += 1;
                        self.prevote_archive
                            .insert((round, validator_index), block_hash);
                        vote.clone()
                    });
                }
                1 => {
                    // Precommit
                    self.precommits.entry(validator_index).or_insert_with(|| {
                        loaded += 1;
                        self.precommit_archive
                            .insert((round, validator_index), block_hash);
                        vote.clone()
                    });
                }
                _ => {} // Unknown vote type, skip
            }
        }
        loaded
    }

    /// Byzantine fault tolerance threshold: 2f+1 where f = (n-1)/3.
    /// Equivalent to ceil(2n/3) for supermajority.
    fn threshold(&self) -> usize {
        let n = self.total_validators as usize;
        // 2/3 + 1 supermajority
        (n * 2).div_ceil(3)
    }

    /// Update best block (called on block import/authoring).
    pub fn update_best_block(&mut self, hash: Hash, slot: Timeslot) {
        if slot > self.best_block_slot {
            self.best_block_hash = hash;
            self.best_block_slot = slot;
        }
    }

    /// Record a new block in the ancestry map. Detects same-slot equivocations.
    ///
    /// Call this for every block (authored or imported) just before update_best_block.
    pub fn register_block(
        &mut self,
        hash: Hash,
        parent: Hash,
        slot: Timeslot,
        ticket_sealed: bool,
    ) {
        // Detect same-slot equivocation: another block already registered at this slot
        let equivocation = self.ancestry.values().any(|&(_, s, _)| s == slot);
        if equivocation {
            self.chain_equivocations.insert(slot);
        }
        self.ancestry.insert(hash, (parent, slot, ticket_sealed));
    }

    /// Walk ancestry from `hash` back to `finalized_hash` (inclusive).
    ///
    /// Returns the path as `[hash, parent, grandparent, ..., finalized_hash]`.
    /// Stops early (and omits `finalized_hash`) if ancestry is missing an entry.
    fn ancestors(&self, hash: Hash) -> Vec<Hash> {
        let mut result = vec![hash];
        let mut current = hash;
        while current != self.finalized_hash {
            match self.ancestry.get(&current) {
                Some(&(parent, _, _)) => {
                    result.push(parent);
                    current = parent;
                }
                None => break,
            }
        }
        result
    }

    /// Generate a prevote for the current round.
    pub fn create_prevote(
        &mut self,
        validator_index: u16,
        secrets: &ValidatorSecrets,
    ) -> Option<VoteMessage> {
        if self.prevoted {
            return None;
        }
        if self.best_block_slot == 0 {
            return None; // No block to vote for
        }

        let vote = sign_vote(
            &self.best_block_hash,
            self.best_block_slot,
            self.round,
            validator_index,
            secrets,
            VoteType::Prevote,
        );

        self.prevoted = true;
        self.prevote_archive
            .insert((self.round, validator_index), vote.block_hash);
        self.prevotes.insert(validator_index, vote.clone());

        Some(VoteMessage {
            vote_type: VoteType::Prevote,
            vote,
        })
    }

    /// Add a received prevote. Returns true if the threshold was just reached.
    pub fn add_prevote(&mut self, vote: Vote) -> bool {
        // Check cross-round equivocation via archive (catches votes from past rounds)
        let archive_key = (vote.round, vote.validator_index);
        if let Some(&archived_hash) = self.prevote_archive.get(&archive_key) {
            if archived_hash != vote.block_hash {
                self.equivocations.insert(vote.validator_index);
                tracing::warn!(
                    "GRANDPA cross-round equivocation: validator {} prevoted for conflicting blocks in round {}",
                    vote.validator_index,
                    vote.round
                );
            }
            return false; // Already archived a prevote from this validator for this round
        }

        if vote.round != self.round {
            // Archive the vote even though it's for a different round
            self.prevote_archive.insert(archive_key, vote.block_hash);
            // Buffer future-round votes for replay when we advance
            if vote.round > self.round {
                self.pending_future_prevotes.push(vote);
            }
            return false;
        }

        // Check for equivocation within current round
        if let Some(existing) = self.prevotes.get(&vote.validator_index) {
            if existing.block_hash != vote.block_hash {
                self.equivocations.insert(vote.validator_index);
                tracing::warn!(
                    "GRANDPA equivocation detected: validator {} prevoted for two blocks in round {}",
                    vote.validator_index,
                    self.round
                );
            }
            return false; // Already have a prevote from this validator
        }

        // Archive and add to current round
        self.prevote_archive.insert(archive_key, vote.block_hash);
        self.prevotes.insert(vote.validator_index, vote);
        self.prevote_count() == self.threshold()
    }

    /// Generate a precommit (only if prevote threshold reached).
    pub fn create_precommit(
        &mut self,
        validator_index: u16,
        secrets: &ValidatorSecrets,
    ) -> Option<VoteMessage> {
        if self.precommitted {
            return None;
        }
        if !self.has_prevote_supermajority() {
            return None;
        }

        // Find the best block that has prevote supermajority
        let target = self.prevote_ghost();
        let (hash, slot) = match target {
            Some((h, s)) => (h, s),
            None => return None,
        };

        let vote = sign_vote(
            &hash,
            slot,
            self.round,
            validator_index,
            secrets,
            VoteType::Precommit,
        );

        self.precommitted = true;
        self.precommit_archive
            .insert((self.round, validator_index), vote.block_hash);
        self.precommits.insert(validator_index, vote.clone());

        Some(VoteMessage {
            vote_type: VoteType::Precommit,
            vote,
        })
    }

    /// Add a received precommit. Returns the finalized (hash, slot) if finality was just reached.
    ///
    /// Validates that the precommit target is an ancestor-or-equal of the prevote
    /// GHOST target (i.e., precommit slot ≤ GHOST slot). Rejects precommits that
    /// violate this relationship — in GRANDPA, a validator must not precommit to
    /// a block that is not on the chain selected by prevotes.
    pub fn add_precommit(&mut self, vote: Vote) -> Option<(Hash, Timeslot)> {
        // Check cross-round equivocation via archive
        let archive_key = (vote.round, vote.validator_index);
        if let Some(&archived_hash) = self.precommit_archive.get(&archive_key) {
            if archived_hash != vote.block_hash {
                self.equivocations.insert(vote.validator_index);
                tracing::warn!(
                    "GRANDPA cross-round equivocation: validator {} precommitted for conflicting blocks in round {}",
                    vote.validator_index,
                    vote.round
                );
            }
            return None; // Already archived
        }

        if vote.round != self.round {
            // Archive the vote even though it's for a different round
            self.precommit_archive.insert(archive_key, vote.block_hash);
            // Buffer future-round votes for replay when we advance
            if vote.round > self.round {
                self.pending_future_precommits.push(vote);
            }
            return None;
        }

        // Check for equivocation within current round
        if let Some(existing) = self.precommits.get(&vote.validator_index) {
            if existing.block_hash != vote.block_hash {
                self.equivocations.insert(vote.validator_index);
                tracing::warn!(
                    "GRANDPA equivocation detected: validator {} precommitted for two blocks in round {}",
                    vote.validator_index,
                    self.round
                );
            }
            return None;
        }

        // Validate ancestor relationship: precommit target must be at or below
        // the prevote GHOST slot. A precommit for a block higher than the GHOST
        // cannot be an ancestor of the GHOST and violates the GRANDPA protocol.
        if let Some((_, ghost_slot)) = self.prevote_ghost()
            && vote.block_slot > ghost_slot
        {
            tracing::warn!(
                "GRANDPA rejecting precommit from validator {}: slot {} exceeds prevote GHOST slot {}",
                vote.validator_index,
                vote.block_slot,
                ghost_slot,
            );
            return None;
        }

        // Archive and add to current round
        self.precommit_archive.insert(archive_key, vote.block_hash);
        self.precommits.insert(vote.validator_index, vote);

        // Check if we've reached finality
        self.check_finality()
    }

    /// Count distinct prevotes.
    fn prevote_count(&self) -> usize {
        self.prevotes.len()
    }

    /// Check if prevotes have reached supermajority.
    fn has_prevote_supermajority(&self) -> bool {
        self.prevote_count() >= self.threshold()
    }

    /// Aggregate votes by block hash, returning (count, slot) per block.
    fn count_votes(votes: &BTreeMap<ValidatorIndex, Vote>) -> BTreeMap<Hash, (usize, Timeslot)> {
        let mut counts: BTreeMap<Hash, (usize, Timeslot)> = BTreeMap::new();
        for vote in votes.values() {
            let entry = counts
                .entry(vote.block_hash)
                .or_insert((0, vote.block_slot));
            entry.0 += 1;
        }
        counts
    }

    /// GHOST rule: find the block with the most prevotes.
    /// In our simplified version, we pick the block with the most votes
    /// at the highest slot.
    fn prevote_ghost(&self) -> Option<(Hash, Timeslot)> {
        Self::count_votes(&self.prevotes)
            .into_iter()
            .filter(|(_, (count, _))| *count >= self.threshold())
            .max_by_key(|(_, (count, slot))| (*count, *slot))
            .map(|(hash, (_, slot))| (hash, slot))
    }

    /// Check if precommits have reached supermajority on any block.
    fn check_finality(&mut self) -> Option<(Hash, Timeslot)> {
        for (hash, (count, slot)) in &Self::count_votes(&self.precommits) {
            if *count >= self.threshold() && *slot > self.finalized_slot {
                self.finalized_hash = *hash;
                self.finalized_slot = *slot;
                self.ancestry
                    .retain(|_, &mut (_, slot, _)| slot > self.finalized_slot);
                self.chain_equivocations
                    .retain(|&slot| slot > self.finalized_slot);
                // Prune vote archives for finalized rounds to bound memory growth.
                self.prune_archive(self.round.saturating_sub(1));
                return Some((*hash, *slot));
            }
        }

        None
    }

    /// Prune vote archives for rounds ≤ `up_to_round`.
    fn prune_archive(&mut self, up_to_round: u64) {
        if up_to_round <= self.archive_pruned_round {
            return;
        }
        self.prevote_archive
            .retain(|&(round, _), _| round > up_to_round);
        self.precommit_archive
            .retain(|&(round, _), _| round > up_to_round);
        self.archive_pruned_round = up_to_round;
    }

    /// Advance to the next round, replaying any buffered future-round votes.
    pub fn advance_round(&mut self) {
        self.round += 1;
        self.prevotes.clear();
        self.precommits.clear();
        self.prevoted = false;
        self.precommitted = false;

        // Replay buffered future prevotes that match the new round
        let prevotes: Vec<Vote> = self.pending_future_prevotes.drain(..).collect();
        let mut replayed_prevotes = 0u32;
        let mut remaining_prevotes = Vec::new();
        for vote in prevotes {
            if vote.round == self.round {
                // Re-add to current round (archive already has it)
                use std::collections::btree_map::Entry;
                if let Entry::Vacant(e) = self.prevotes.entry(vote.validator_index) {
                    e.insert(vote);
                    replayed_prevotes += 1;
                }
            } else if vote.round > self.round {
                remaining_prevotes.push(vote);
            }
            // Drop votes for past rounds
        }
        self.pending_future_prevotes = remaining_prevotes;

        // Replay buffered future precommits that match the new round
        let precommits: Vec<Vote> = self.pending_future_precommits.drain(..).collect();
        let mut replayed_precommits = 0u32;
        let mut remaining_precommits = Vec::new();
        for vote in precommits {
            if vote.round == self.round {
                use std::collections::btree_map::Entry;
                if let Entry::Vacant(e) = self.precommits.entry(vote.validator_index) {
                    e.insert(vote);
                    replayed_precommits += 1;
                }
            } else if vote.round > self.round {
                remaining_precommits.push(vote);
            }
        }
        self.pending_future_precommits = remaining_precommits;

        if replayed_prevotes > 0 || replayed_precommits > 0 {
            tracing::info!(
                "GRANDPA round {}: replayed {} buffered prevotes, {} buffered precommits",
                self.round,
                replayed_prevotes,
                replayed_precommits,
            );
        }
    }

    /// Check if the current round should advance (both prevote and precommit
    /// supermajorities reached, or timeout).
    pub fn should_advance_round(&self) -> bool {
        // Advance if precommits have reached supermajority on any block
        Self::count_votes(&self.precommits)
            .values()
            .any(|&(count, _)| count >= self.threshold())
    }
}

/// Sign a GRANDPA vote.
fn sign_vote(
    block_hash: &Hash,
    block_slot: Timeslot,
    round: u64,
    validator_index: u16,
    secrets: &ValidatorSecrets,
    vote_type: VoteType,
) -> Vote {
    let context = match vote_type {
        VoteType::Prevote => PREVOTE_CONTEXT,
        VoteType::Precommit => PRECOMMIT_CONTEXT,
    };

    let mut message = Vec::with_capacity(context.len() + 32 + 4 + 8);
    message.extend_from_slice(context);
    message.extend_from_slice(&block_hash.0);
    message.extend_from_slice(&block_slot.to_le_bytes());
    message.extend_from_slice(&round.to_le_bytes());

    let signature = secrets.ed25519.sign(&message);

    Vote {
        block_hash: *block_hash,
        block_slot,
        round,
        validator_index,
        signature,
    }
}

/// Verify a GRANDPA vote signature.
pub fn verify_vote(vote: &Vote, vote_type: VoteType, state: &grey_types::state::State) -> bool {
    let idx = vote.validator_index as usize;
    if idx >= state.current_validators.len() {
        return false;
    }
    let ed25519_key = &state.current_validators[idx].ed25519;

    let context = match vote_type {
        VoteType::Prevote => PREVOTE_CONTEXT,
        VoteType::Precommit => PRECOMMIT_CONTEXT,
    };

    let mut message = Vec::with_capacity(context.len() + 32 + 4 + 8);
    message.extend_from_slice(context);
    message.extend_from_slice(&vote.block_hash.0);
    message.extend_from_slice(&vote.block_slot.to_le_bytes());
    message.extend_from_slice(&vote.round.to_le_bytes());

    grey_crypto::ed25519_verify(ed25519_key, &message, &vote.signature)
}

/// Encode a vote message for network transmission.
/// Format: `[type(1)][block_hash(32)][block_slot(4)][round(8)][validator_index(2)][signature(64)]`
pub fn encode_vote_message(msg: &VoteMessage) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 32 + 4 + 8 + 2 + 64);
    buf.push(match msg.vote_type {
        VoteType::Prevote => 0x01,
        VoteType::Precommit => 0x02,
    });
    buf.extend_from_slice(&msg.vote.block_hash.0);
    buf.extend_from_slice(&msg.vote.block_slot.to_le_bytes());
    buf.extend_from_slice(&msg.vote.round.to_le_bytes());
    buf.extend_from_slice(&msg.vote.validator_index.to_le_bytes());
    buf.extend_from_slice(&msg.vote.signature.0);
    buf
}

/// Decode a vote message from network bytes.
pub fn decode_vote_message(data: &[u8]) -> Option<VoteMessage> {
    // 1 + 32 + 4 + 8 + 2 + 64 = 111
    if data.len() < 111 {
        return None;
    }

    let vote_type = match data[0] {
        0x01 => VoteType::Prevote,
        0x02 => VoteType::Precommit,
        _ => return None,
    };

    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&data[1..33]);

    let block_slot = u32::from_le_bytes([data[33], data[34], data[35], data[36]]);
    let round = u64::from_le_bytes([
        data[37], data[38], data[39], data[40], data[41], data[42], data[43], data[44],
    ]);
    let validator_index = u16::from_le_bytes([data[45], data[46]]);

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[47..111]);

    Some(VoteMessage {
        vote_type,
        vote: Vote {
            block_hash: Hash(block_hash),
            block_slot,
            round,
            validator_index,
            signature: Ed25519Signature(signature),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grandpa_threshold() {
        // V=6 tiny config: threshold = (6*2+2)/3 = 14/3 = 4
        let state = GrandpaState::new(6);
        assert_eq!(state.threshold(), 4);

        // V=1023 full config: threshold = (1023*2+2)/3 = 2048/3 = 682
        let state = GrandpaState::new(1023);
        assert_eq!(state.threshold(), 682);

        // V=4: threshold = (4*2+2)/3 = 10/3 = 3
        let state = GrandpaState::new(4);
        assert_eq!(state.threshold(), 3);

        // V=3: threshold = (3*2+2)/3 = 8/3 = 2
        let state = GrandpaState::new(3);
        assert_eq!(state.threshold(), 2);
    }

    #[test]
    fn test_grandpa_prevote_flow() {
        let config = Config::tiny(); // V=6
        let (chain_state, secrets) = grey_consensus::genesis::create_genesis(&config);

        let mut grandpa = GrandpaState::new(config.validators_count);
        let block_hash = Hash([42u8; 32]);
        grandpa.update_best_block(block_hash, 5);

        // Validator 0 prevotes
        let msg = grandpa.create_prevote(0, &secrets[0]);
        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert_eq!(msg.vote_type, VoteType::Prevote);
        assert_eq!(msg.vote.block_hash, block_hash);
        assert!(verify_vote(&msg.vote, VoteType::Prevote, &chain_state));

        // Can't prevote twice
        assert!(grandpa.create_prevote(0, &secrets[0]).is_none());

        // Add prevotes from other validators until threshold
        let threshold = grandpa.threshold();
        for i in 1..threshold as u16 {
            let vote = sign_vote(
                &block_hash,
                5,
                1,
                i,
                &secrets[i as usize],
                VoteType::Prevote,
            );
            let reached = grandpa.add_prevote(vote);
            if (i as usize + 1) == threshold {
                // +1 because validator 0 already voted
                assert!(reached, "threshold should be reached at i={}", i);
            }
        }

        assert!(grandpa.has_prevote_supermajority());
    }

    #[test]
    fn test_grandpa_finality() {
        let config = Config::tiny(); // V=6
        let (_chain_state, secrets) = grey_consensus::genesis::create_genesis(&config);

        let mut grandpa = GrandpaState::new(config.validators_count);
        let block_hash = Hash([42u8; 32]);
        grandpa.update_best_block(block_hash, 5);

        // All validators prevote
        for i in 0..config.validators_count {
            let vote = sign_vote(
                &block_hash,
                5,
                1,
                i,
                &secrets[i as usize],
                VoteType::Prevote,
            );
            grandpa.add_prevote(vote);
        }

        assert!(grandpa.has_prevote_supermajority());

        // Now precommit
        let precommit_msg = grandpa.create_precommit(0, &secrets[0]);
        assert!(precommit_msg.is_some());

        // Add precommits from other validators until finality
        let _threshold = grandpa.threshold();
        let mut finalized = None;
        for i in 1..config.validators_count {
            let vote = sign_vote(
                &block_hash,
                5,
                1,
                i,
                &secrets[i as usize],
                VoteType::Precommit,
            );
            if let Some(fin) = grandpa.add_precommit(vote) {
                finalized = Some(fin);
            }
        }

        assert!(finalized.is_some());
        let (fin_hash, fin_slot) = finalized.unwrap();
        assert_eq!(fin_hash, block_hash);
        assert_eq!(fin_slot, 5);
        assert_eq!(grandpa.finalized_hash, block_hash);
        assert_eq!(grandpa.finalized_slot, 5);
    }

    #[test]
    fn test_vote_encode_decode() {
        let config = Config::tiny();
        let (_, secrets) = grey_consensus::genesis::create_genesis(&config);

        let block_hash = Hash([99u8; 32]);
        let vote = sign_vote(&block_hash, 10, 3, 2, &secrets[2], VoteType::Prevote);
        let msg = VoteMessage {
            vote_type: VoteType::Prevote,
            vote,
        };

        let encoded = encode_vote_message(&msg);
        assert_eq!(encoded.len(), 111);

        let decoded = decode_vote_message(&encoded).expect("decode should succeed");
        assert_eq!(decoded.vote_type, VoteType::Prevote);
        assert_eq!(decoded.vote.block_hash, block_hash);
        assert_eq!(decoded.vote.block_slot, 10);
        assert_eq!(decoded.vote.round, 3);
        assert_eq!(decoded.vote.validator_index, 2);
        assert_eq!(decoded.vote.signature.0, msg.vote.signature.0);
    }

    #[test]
    fn test_equivocation_detection() {
        let config = Config::tiny();
        let (_, secrets) = grey_consensus::genesis::create_genesis(&config);

        let mut grandpa = GrandpaState::new(config.validators_count);
        let hash1 = Hash([1u8; 32]);
        let hash2 = Hash([2u8; 32]);

        // Validator 0 prevotes for hash1
        let vote1 = sign_vote(&hash1, 5, 1, 0, &secrets[0], VoteType::Prevote);
        grandpa.add_prevote(vote1);

        // Validator 0 tries to prevote for hash2 (equivocation)
        let vote2 = sign_vote(&hash2, 5, 1, 0, &secrets[0], VoteType::Prevote);
        grandpa.add_prevote(vote2);

        assert!(grandpa.equivocations.contains(&0));
    }

    #[test]
    fn test_cross_round_equivocation_detection() {
        let config = Config::tiny();
        let (_, secrets) = grey_consensus::genesis::create_genesis(&config);

        let mut grandpa = GrandpaState::new(config.validators_count);
        let hash1 = Hash([1u8; 32]);
        let hash2 = Hash([2u8; 32]);

        // Validator 0 prevotes for hash1 in round 1
        let vote1 = sign_vote(&hash1, 5, 1, 0, &secrets[0], VoteType::Prevote);
        grandpa.add_prevote(vote1);
        assert!(!grandpa.equivocations.contains(&0));

        // Advance to round 2 — clears current prevotes but archive remains
        grandpa.advance_round();
        assert_eq!(grandpa.round, 2);
        assert!(grandpa.prevotes.is_empty());

        // Receive a conflicting prevote for round 1 from validator 0 (late arrival)
        let vote2 = sign_vote(&hash2, 5, 1, 0, &secrets[0], VoteType::Prevote);
        grandpa.add_prevote(vote2);

        // Cross-round equivocation should be detected
        assert!(
            grandpa.equivocations.contains(&0),
            "should detect cross-round equivocation for validator 0"
        );
    }

    #[test]
    fn test_round_advancement() {
        let mut grandpa = GrandpaState::new(6);
        assert_eq!(grandpa.round, 1);

        grandpa.advance_round();
        assert_eq!(grandpa.round, 2);
        assert!(grandpa.prevotes.is_empty());
        assert!(grandpa.precommits.is_empty());
        assert!(!grandpa.prevoted);
        assert!(!grandpa.precommitted);
    }

    #[test]
    fn test_precommit_ancestor_validation() {
        let config = Config::tiny(); // V=6
        let (_, secrets) = grey_consensus::genesis::create_genesis(&config);

        let mut grandpa = GrandpaState::new(config.validators_count);
        let block_hash = Hash([42u8; 32]);
        grandpa.update_best_block(block_hash, 5);

        // All validators prevote for slot 5
        for i in 0..config.validators_count {
            let vote = sign_vote(
                &block_hash,
                5,
                1,
                i,
                &secrets[i as usize],
                VoteType::Prevote,
            );
            grandpa.add_prevote(vote);
        }
        assert!(grandpa.has_prevote_supermajority());

        // Valid precommit: slot 5 == GHOST slot 5 (accepted)
        let valid_precommit = sign_vote(&block_hash, 5, 1, 0, &secrets[0], VoteType::Precommit);
        let result = grandpa.add_precommit(valid_precommit);
        // Not finalized yet (only 1 precommit), but it was accepted
        assert!(result.is_none());
        assert!(grandpa.precommits.contains_key(&0));

        // Valid precommit: slot 3 < GHOST slot 5 (ancestor, accepted)
        let ancestor_hash = Hash([10u8; 32]);
        let ancestor_precommit =
            sign_vote(&ancestor_hash, 3, 1, 1, &secrets[1], VoteType::Precommit);
        grandpa.add_precommit(ancestor_precommit);
        assert!(grandpa.precommits.contains_key(&1));

        // Invalid precommit: slot 8 > GHOST slot 5 (rejected)
        let future_hash = Hash([99u8; 32]);
        let invalid_precommit = sign_vote(&future_hash, 8, 1, 2, &secrets[2], VoteType::Precommit);
        grandpa.add_precommit(invalid_precommit);
        assert!(
            !grandpa.precommits.contains_key(&2),
            "precommit with slot > GHOST slot should be rejected"
        );
    }

    #[test]
    fn test_vote_verification() {
        let config = Config::tiny();
        let (chain_state, secrets) = grey_consensus::genesis::create_genesis(&config);

        let block_hash = Hash([42u8; 32]);
        let vote = sign_vote(&block_hash, 5, 1, 0, &secrets[0], VoteType::Prevote);

        // Valid verification
        assert!(verify_vote(&vote, VoteType::Prevote, &chain_state));

        // Wrong vote type
        assert!(!verify_vote(&vote, VoteType::Precommit, &chain_state));

        // Tampered vote
        let mut bad_vote = vote.clone();
        bad_vote.validator_index = 1; // Wrong key
        assert!(!verify_vote(&bad_vote, VoteType::Prevote, &chain_state));
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        fn arb_vote_type() -> impl Strategy<Value = VoteType> {
            prop_oneof![Just(VoteType::Prevote), Just(VoteType::Precommit),]
        }

        proptest! {
            #[test]
            fn vote_message_encode_decode_roundtrip(
                block_hash in prop::array::uniform32(any::<u8>()),
                block_slot in any::<u32>(),
                round in any::<u64>(),
                validator_index in any::<u16>(),
                signature in prop::array::uniform32(any::<u8>())
                    .prop_flat_map(|a| prop::array::uniform32(any::<u8>()).prop_map(move |b| {
                        let mut sig = [0u8; 64];
                        sig[..32].copy_from_slice(&a);
                        sig[32..].copy_from_slice(&b);
                        sig
                    })),
                vote_type in arb_vote_type(),
            ) {
                let msg = VoteMessage {
                    vote_type,
                    vote: Vote {
                        block_hash: Hash(block_hash),
                        block_slot,
                        round,
                        validator_index,
                        signature: Ed25519Signature(signature),
                    },
                };

                let encoded = encode_vote_message(&msg);
                prop_assert_eq!(encoded.len(), 111, "encoded vote should be exactly 111 bytes");

                let decoded = decode_vote_message(&encoded);
                prop_assert!(decoded.is_some(), "decode should succeed for any valid encoding");

                let decoded = decoded.unwrap();
                prop_assert_eq!(decoded.vote_type, msg.vote_type);
                prop_assert_eq!(decoded.vote.block_hash, msg.vote.block_hash);
                prop_assert_eq!(decoded.vote.block_slot, msg.vote.block_slot);
                prop_assert_eq!(decoded.vote.round, msg.vote.round);
                prop_assert_eq!(decoded.vote.validator_index, msg.vote.validator_index);
                prop_assert_eq!(decoded.vote.signature.0, msg.vote.signature.0);
            }

            #[test]
            fn decode_rejects_short_messages(data in prop::collection::vec(any::<u8>(), 0..110)) {
                // Any message shorter than 111 bytes should fail to decode
                prop_assert!(decode_vote_message(&data).is_none());
            }

            #[test]
            fn decode_rejects_invalid_vote_type(
                rest in prop::collection::vec(any::<u8>(), 110..=110),
            ) {
                // Vote type byte must be 0x01 or 0x02; 0x00 and 0x03+ should fail
                let mut data = vec![0x00];
                data.extend_from_slice(&rest);
                prop_assert!(decode_vote_message(&data).is_none());

                data[0] = 0x03;
                prop_assert!(decode_vote_message(&data).is_none());
            }
        }
    }

    #[test]
    fn test_load_persisted_votes() {
        let mut grandpa = GrandpaState::new(6);
        let hash_a = Hash([1u8; 32]);
        let hash_b = Hash([2u8; 32]);

        let votes = vec![
            (0u8, 0u16, hash_a, 10u32, [0xAA; 64]), // prevote from v0
            (0u8, 1u16, hash_a, 10u32, [0xBB; 64]), // prevote from v1
            (1u8, 0u16, hash_a, 10u32, [0xCC; 64]), // precommit from v0
            (1u8, 2u16, hash_b, 11u32, [0xDD; 64]), // precommit from v2
            (2u8, 3u16, hash_a, 10u32, [0xEE; 64]), // unknown type, should be skipped
        ];

        let loaded = grandpa.load_persisted_votes(5, &votes);
        assert_eq!(loaded, 4, "should load 4 valid votes (skip unknown type)");
        assert_eq!(grandpa.round, 5);
        assert_eq!(grandpa.prevotes.len(), 2);
        assert_eq!(grandpa.precommits.len(), 2);

        // Verify vote contents
        assert_eq!(grandpa.prevotes[&0].block_hash, hash_a);
        assert_eq!(grandpa.prevotes[&1].block_hash, hash_a);
        assert_eq!(grandpa.precommits[&0].block_hash, hash_a);
        assert_eq!(grandpa.precommits[&2].block_hash, hash_b);

        // Archives should be populated
        assert_eq!(grandpa.prevote_archive.len(), 2);
        assert_eq!(grandpa.precommit_archive.len(), 2);
    }

    #[test]
    fn test_load_persisted_votes_no_duplicates() {
        let mut grandpa = GrandpaState::new(6);
        let hash_a = Hash([1u8; 32]);
        let hash_b = Hash([2u8; 32]);

        // Load first batch
        let votes1 = vec![(0u8, 0u16, hash_a, 10u32, [0xAA; 64])];
        grandpa.load_persisted_votes(5, &votes1);
        assert_eq!(grandpa.prevotes.len(), 1);

        // Load second batch with duplicate — should not overwrite
        let votes2 = vec![(0u8, 0u16, hash_b, 11u32, [0xBB; 64])];
        let loaded = grandpa.load_persisted_votes(5, &votes2);
        assert_eq!(loaded, 0, "duplicate should not be loaded");
        assert_eq!(
            grandpa.prevotes[&0].block_hash, hash_a,
            "original vote preserved"
        );
    }

    #[test]
    fn test_future_round_votes_replayed_on_advance() {
        let mut grandpa = GrandpaState::new(6);
        assert_eq!(grandpa.round, 1);

        let hash_a = Hash([1u8; 32]);

        // Add a prevote for round 2 (future) — should be buffered
        let future_prevote = Vote {
            round: 2,
            block_hash: hash_a,
            block_slot: 10,
            validator_index: 0,
            signature: grey_types::Ed25519Signature([0xAA; 64]),
        };
        let result = grandpa.add_prevote(future_prevote);
        assert!(!result, "future-round prevote should not trigger threshold");
        assert!(
            grandpa.prevotes.is_empty(),
            "current round should have no prevotes"
        );
        assert_eq!(
            grandpa.pending_future_prevotes.len(),
            1,
            "should be buffered"
        );

        // Add a precommit for round 2 (future)
        let future_precommit = Vote {
            round: 2,
            block_hash: hash_a,
            block_slot: 10,
            validator_index: 1,
            signature: grey_types::Ed25519Signature([0xBB; 64]),
        };
        grandpa.add_precommit(future_precommit);
        assert!(grandpa.precommits.is_empty());
        assert_eq!(grandpa.pending_future_precommits.len(), 1);

        // Advance to round 2 — should replay buffered votes
        grandpa.advance_round();
        assert_eq!(grandpa.round, 2);
        assert_eq!(
            grandpa.prevotes.len(),
            1,
            "buffered prevote should be replayed"
        );
        assert_eq!(grandpa.prevotes[&0].block_hash, hash_a);
        assert_eq!(
            grandpa.precommits.len(),
            1,
            "buffered precommit should be replayed"
        );
        assert_eq!(grandpa.precommits[&1].block_hash, hash_a);
        assert!(grandpa.pending_future_prevotes.is_empty());
        assert!(grandpa.pending_future_precommits.is_empty());
    }

    #[test]
    fn test_future_votes_for_later_round_kept_buffered() {
        let mut grandpa = GrandpaState::new(6);
        let hash_a = Hash([1u8; 32]);

        // Add prevote for round 3 while in round 1
        let vote = Vote {
            round: 3,
            block_hash: hash_a,
            block_slot: 20,
            validator_index: 2,
            signature: grey_types::Ed25519Signature([0xCC; 64]),
        };
        grandpa.add_prevote(vote);
        assert_eq!(grandpa.pending_future_prevotes.len(), 1);

        // Advance to round 2 — round 3 vote should still be buffered
        grandpa.advance_round();
        assert_eq!(grandpa.round, 2);
        assert!(
            grandpa.prevotes.is_empty(),
            "round 3 vote should not replay in round 2"
        );
        assert_eq!(
            grandpa.pending_future_prevotes.len(),
            1,
            "round 3 vote should remain buffered"
        );

        // Advance to round 3 — now it should replay
        grandpa.advance_round();
        assert_eq!(grandpa.round, 3);
        assert_eq!(grandpa.prevotes.len(), 1, "round 3 vote should replay");
        assert_eq!(grandpa.prevotes[&2].block_hash, hash_a);
    }

    #[test]
    fn test_pruning_on_finalize() {
        let config = Config::tiny(); // V=6, use for secrets
        let (_, secrets) = grey_consensus::genesis::create_genesis(&config);
        let mut grandpa = GrandpaState::new(config.validators_count);

        // Register blocks at slots 1-7
        let hashes: Vec<Hash> = (1u8..=7).map(|i| Hash([i; 32])).collect();
        grandpa.finalized_hash = hashes[0]; // slot 1 is finalized start
        for (i, &h) in hashes.iter().enumerate() {
            let parent = if i == 0 { Hash::ZERO } else { hashes[i - 1] };
            grandpa.register_block(h, parent, (i + 1) as u32, false);
        }
        // Mark slot 3 as having a chain equivocation
        grandpa.chain_equivocations.insert(3);

        // Drive finalization to slot 5 by adding 4 precommits (threshold for V=6 is 4)
        let block_hash = hashes[4]; // slot 5
        grandpa.update_best_block(block_hash, 5);
        for (i, secret) in secrets.iter().enumerate().take(4) {
            let vote = sign_vote(&block_hash, 5, 1, i as u16, secret, VoteType::Precommit);
            grandpa.add_precommit(vote);
        }
        // Finalization should have occurred at slot 5
        assert_eq!(grandpa.finalized_slot, 5);

        // ancestry entries with slot <= 5 must be gone
        for &h in &hashes {
            if let Some(&(_, slot, _)) = grandpa.ancestry.get(&h) {
                assert!(slot > 5, "slot {} should have been pruned", slot);
            }
        }
        // chain_equivocations slot 3 must be gone (3 <= 5)
        assert!(!grandpa.chain_equivocations.contains(&3));
    }

    #[test]
    fn test_ancestors_chain() {
        let mut grandpa = GrandpaState::new(6);
        let hash_a = Hash([1u8; 32]);
        let hash_b = Hash([2u8; 32]);
        let hash_c = Hash([3u8; 32]);
        // Set finalized_hash so the walk terminates
        grandpa.finalized_hash = hash_a;
        // Register A→B→C (A is finalized, B is child of A, C is child of B)
        grandpa.register_block(hash_a, Hash::ZERO, 1, false);
        grandpa.register_block(hash_b, hash_a, 2, false);
        grandpa.register_block(hash_c, hash_b, 3, false);
        let chain = grandpa.ancestors(hash_c);
        // Should be [C, B, A] — from tip back to finalized_hash
        assert_eq!(chain, vec![hash_c, hash_b, hash_a]);
    }

    #[test]
    fn test_register_single_block() {
        let mut grandpa = GrandpaState::new(6);
        let hash_a = Hash([1u8; 32]);
        let parent = Hash::ZERO; // genesis parent
        grandpa.register_block(hash_a, parent, 3, false);
        assert_eq!(grandpa.ancestry.get(&hash_a), Some(&(parent, 3, false)));
        assert!(grandpa.chain_equivocations.is_empty());
    }

    #[test]
    fn test_chain_equivocation_detected() {
        let mut grandpa = GrandpaState::new(6);
        let hash_a = Hash([1u8; 32]);
        let hash_b = Hash([2u8; 32]);
        let parent = Hash::ZERO;
        // Two different blocks at slot 5 → equivocation
        grandpa.register_block(hash_a, parent, 5, false);
        grandpa.register_block(hash_b, parent, 5, true);
        assert!(grandpa.chain_equivocations.contains(&5));
        // Both blocks are still recorded
        assert!(grandpa.ancestry.contains_key(&hash_a));
        assert!(grandpa.ancestry.contains_key(&hash_b));
    }
}
