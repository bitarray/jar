//! Chain state types (Section 4.2 of the Gray Paper).
//!
//! σ ≡ (α, β, θ, γ, δ, η, ι, κ, λ, ρ, τ, ϕ, χ, ψ, π, ω, ξ)

use crate::header::Ticket;
use crate::validator::ValidatorKey;
use crate::work::WorkReport;
use crate::{
    BandersnatchPublicKey, BandersnatchRingRoot, Ed25519PublicKey, Gas, Hash, ServiceId, Timeslot,
};
use std::collections::{BTreeMap, BTreeSet};

/// The complete JAM chain state σ (eq 4.4).
#[derive(Clone, Debug)]
pub struct State {
    /// α: Core authorizations pool — per-core list of authorized hashes.
    pub auth_pool: Vec<Vec<Hash>>,

    /// β: Recent block history.
    pub recent_blocks: RecentBlocks,

    /// θ: Most recent accumulation outputs.
    pub accumulation_outputs: Vec<(ServiceId, Hash)>,

    /// γ: Safrole consensus state.
    pub safrole: SafroleState,

    /// δ: Service accounts.
    pub services: BTreeMap<ServiceId, ServiceAccount>,

    /// η: Entropy accumulator and epochal randomness (4 hashes).
    pub entropy: [Hash; 4],

    /// ι: Prospective (queued) validator keys for the next epoch.
    pub pending_validators: Vec<ValidatorKey>,

    /// κ: Currently active validator keys.
    pub current_validators: Vec<ValidatorKey>,

    /// λ: Previous epoch's validator keys.
    pub previous_validators: Vec<ValidatorKey>,

    /// ρ: Pending work-reports per core (awaiting availability).
    pub pending_reports: Vec<Option<PendingReport>>,

    /// τ: Most recent block's timeslot.
    pub timeslot: Timeslot,

    /// ϕ: Authorization queue per core.
    pub auth_queue: Vec<Vec<Hash>>,

    /// χ: Privileged service indices.
    pub privileged_services: PrivilegedServices,

    /// ψ: Past judgments.
    pub judgments: Judgments,

    /// π: Validator activity statistics.
    pub statistics: ValidatorStatistics,

    /// ω: Accumulation queue — per-slot list of (report, unfulfilled deps).
    pub accumulation_queue: Vec<Vec<(WorkReport, Vec<Hash>)>>,

    /// ξ: Accumulation history.
    pub accumulation_history: Vec<Vec<Hash>>,
}

/// Safrole consensus state γ (eq 6.3).
#[derive(Clone, Debug)]
pub struct SafroleState {
    /// γP: Pending (next epoch) validator keys.
    pub pending_keys: Vec<ValidatorKey>,

    /// γZ: Bandersnatch ring root for ticket submissions.
    pub ring_root: BandersnatchRingRoot,

    /// γS: Current epoch's slot-sealer series.
    /// Either a sequence of tickets or a sequence of fallback Bandersnatch keys.
    pub seal_key_series: SealKeySeries,

    /// γA: Ticket accumulator for the next epoch.
    pub ticket_accumulator: Vec<Ticket>,
}

/// The seal-key series for an epoch: either tickets or fallback keys (eq 6.5).
#[derive(Clone, Debug)]
pub enum SealKeySeries {
    /// Regular operation: sequence of E tickets.
    Tickets(Vec<Ticket>),
    /// Fallback mode: sequence of E Bandersnatch keys.
    Fallback(Vec<BandersnatchPublicKey>),
}

/// Recent block history β (eq 7.1-7.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecentBlocks {
    /// βH: Information on the most recent H blocks.
    pub headers: Vec<RecentBlockInfo>,

    /// βB: Merkle mountain belt for accumulation output log.
    pub accumulation_log: Vec<Option<Hash>>,
}

/// Info retained for each recent block (eq 7.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecentBlockInfo {
    /// h: Header hash.
    pub header_hash: Hash,

    /// s: State root.
    pub state_root: Hash,

    /// b: Accumulation-result MMR root.
    pub accumulation_root: Hash,

    /// p: Work-package hashes of reported items.
    pub reported_packages: BTreeMap<Hash, Hash>,
}

/// A pending work-report assigned to a core.
#[derive(Clone, Debug)]
pub struct PendingReport {
    /// r: The work report.
    pub report: WorkReport,
    /// t: Timeslot at which it was reported.
    pub timeslot: Timeslot,
}

/// Privileged service indices χ (eq 9.9).
#[derive(Clone, Debug, Default)]
pub struct PrivilegedServices {
    /// χM: Manager (blessed) service.
    pub manager: ServiceId,
    /// χA: Assigner services (one per core).
    pub assigner: Vec<ServiceId>,
    /// χV: Designator (validator set) service.
    pub designator: ServiceId,
    /// χR: Registrar service.
    pub registrar: ServiceId,
    /// χZ: Always-accumulate services and their gas allowance.
    pub always_accumulate: BTreeMap<ServiceId, Gas>,
}

/// Past judgments ψ (eq 10.1).
#[derive(Clone, Debug, Default)]
pub struct Judgments {
    /// ψG: Work-reports judged to be correct.
    pub good: BTreeSet<Hash>,
    /// ψB: Work-reports judged to be incorrect.
    pub bad: BTreeSet<Hash>,
    /// ψW: Work-reports whose validity is unknowable.
    pub wonky: BTreeSet<Hash>,
    /// ψO: Offending validators.
    pub offenders: BTreeSet<Ed25519PublicKey>,
}

/// Service account A (eq 9.3).
#[derive(Clone, Debug)]
pub struct ServiceAccount {
    /// c: Code hash.
    pub code_hash: Hash,
    /// b: Balance.
    pub balance: u64,
    /// g: Minimum gas for accumulation.
    pub min_accumulate_gas: Gas,
    /// m: Minimum gas for on-transfer.
    pub min_on_transfer_gas: Gas,
    /// s: Storage dictionary (key → value).
    pub storage: BTreeMap<Vec<u8>, Vec<u8>>,
    /// p: Preimage lookup dictionary (hash → data).
    pub preimage_lookup: BTreeMap<Hash, Vec<u8>>,
    /// l: Preimage info dictionary ((hash, length) → timeslots).
    pub preimage_info: BTreeMap<(Hash, u32), Vec<Timeslot>>,
    /// f: Gratis (free) storage offset.
    pub free_storage_offset: u64,
    /// o: Total storage footprint.
    pub total_footprint: u64,
    /// i: Accumulation counter.
    pub accumulation_counter: u32,
    /// r: Most recent timeslot of accumulation.
    pub last_accumulation: Timeslot,
    /// a: Most recent timeslot of activity.
    pub last_activity: Timeslot,
    /// p: Number of preimage requests.
    pub preimage_count: u32,
}

/// Validator activity statistics π (eq 13.1).
#[derive(Clone, Debug, Default)]
pub struct ValidatorStatistics {
    /// πV: Per-validator statistics (current epoch accumulator).
    pub current: Vec<ValidatorRecord>,
    /// πL: Per-validator statistics (last completed epoch).
    pub last: Vec<ValidatorRecord>,
    /// πC: Per-core statistics for this block.
    pub core_stats: Vec<CoreStatistics>,
    /// πS: Per-service statistics for this block.
    pub service_stats: BTreeMap<ServiceId, ServiceStatistics>,
}

/// Per-validator performance record.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize)]
pub struct ValidatorRecord {
    /// b: Blocks produced.
    #[serde(rename = "blocks")]
    pub blocks_produced: u32,
    /// t: Tickets introduced.
    #[serde(rename = "tickets")]
    pub tickets_introduced: u32,
    /// p: Preimages introduced.
    #[serde(rename = "pre_images")]
    pub preimages_introduced: u32,
    /// d: Total preimage bytes.
    #[serde(rename = "pre_images_size")]
    pub preimage_bytes: u64,
    /// g: Reports guaranteed.
    #[serde(rename = "guarantees")]
    pub reports_guaranteed: u32,
    /// a: Availability assurances made.
    #[serde(rename = "assurances")]
    pub assurances_made: u32,
}

/// Per-core statistics for a single block (GP π_C, eq 13.1).
/// Fields ordered per GP type definition: d, p, i, x, z, e, l, u.
#[derive(Clone, Debug, Default)]
pub struct CoreStatistics {
    /// d: DA load (total bytes written to DA layer).
    pub da_load: u64,
    /// p: Popularity (number of validators assuring this core).
    pub popularity: u64,
    /// i: Segments imported from DA.
    pub imports: u64,
    /// x: Total extrinsic count.
    pub extrinsic_count: u64,
    /// z: Total extrinsic size in bytes.
    pub extrinsic_size: u64,
    /// e: Segments exported to DA.
    pub exports: u64,
    /// l: Work bundle size in bytes.
    pub bundle_size: u64,
    /// u: Gas consumed.
    pub gas_used: Gas,
}

/// Per-service statistics for a single block (GP π_S, eq 13.1).
/// Fields ordered per GP type definition: p, r, i, x, z, e, a.
#[derive(Clone, Debug, Default)]
pub struct ServiceStatistics {
    /// p.0: Preimages provided — count.
    pub provided_count: u64,
    /// p.1: Preimages provided — total size.
    pub provided_size: u64,
    /// r.0: Work items refined — count.
    pub refinement_count: u64,
    /// r.1: Work items refined — gas used.
    pub refinement_gas_used: Gas,
    /// i: Segments imported.
    pub imports: u64,
    /// x: Extrinsic count.
    pub extrinsic_count: u64,
    /// z: Extrinsic size in bytes.
    pub extrinsic_size: u64,
    /// e: Segments exported.
    pub exports: u64,
    /// a.0: Items accumulated — count.
    pub accumulate_count: u64,
    /// a.1: Items accumulated — gas used.
    pub accumulate_gas_used: Gas,
}
