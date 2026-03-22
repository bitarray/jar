//! Work-related types: reports, digests, packages (Sections 11, 14).

use crate::{CoreIndex, Gas, Hash, ServiceId, Timeslot};
use std::collections::BTreeMap;

/// Work report R (eq 11.2).
#[derive(Clone, Debug)]
pub struct WorkReport {
    /// s: Availability specification (WorkPackageSpec in ASN).
    pub package_spec: AvailabilitySpec,

    /// c: Refinement context.
    pub context: RefinementContext,

    /// c (core): Core index on which the work was done.
    pub core_index: CoreIndex,

    /// a: Authorizer hash.
    pub authorizer_hash: Hash,

    /// g: Gas consumed during Is-Authorized invocation.
    pub auth_gas_used: Gas,

    /// o: Authorization output (opaque blob).
    pub auth_output: Vec<u8>,

    /// l: Segment-root lookup dictionary.
    pub segment_root_lookup: BTreeMap<Hash, Hash>,

    /// d: Work results (WorkResult in ASN, contains digest + refine load).
    pub results: Vec<WorkDigest>,
}

/// Work-package availability specification (WorkPackageSpec in ASN, eq 11.5).
#[derive(Clone, Debug)]
pub struct AvailabilitySpec {
    /// p: Work-package hash.
    pub package_hash: Hash,

    /// l: Auditable work bundle length.
    pub bundle_length: u32,

    /// u: Erasure root.
    pub erasure_root: Hash,

    /// e: Exports root (segment root).
    pub exports_root: Hash,

    /// n: Exports count.
    pub exports_count: u16,
}

/// Refinement context C (eq 11.4).
#[derive(Clone, Debug)]
pub struct RefinementContext {
    /// a: Anchor header hash.
    pub anchor: Hash,

    /// s: Anchor posterior state root.
    pub state_root: Hash,

    /// b: Anchor accumulation output log super-peak.
    pub beefy_root: Hash,

    /// l: Lookup-anchor header hash.
    pub lookup_anchor: Hash,

    /// t: Lookup-anchor timeslot.
    pub lookup_anchor_timeslot: Timeslot,

    /// p: Prerequisite work-package hashes.
    pub prerequisites: Vec<Hash>,
}

/// Work result (WorkResult in ASN, eq 11.6).
/// Combines the work digest fields and refine load.
#[derive(Clone, Debug)]
pub struct WorkDigest {
    /// s: Service index.
    pub service_id: ServiceId,

    /// c: Code hash of the service at time of reporting.
    pub code_hash: Hash,

    /// y: Hash of the payload in the work item.
    pub payload_hash: Hash,

    /// g: Gas limit for accumulation of this item.
    pub accumulate_gas: Gas,

    /// l: Work execution result — either output blob or error.
    pub result: WorkResult,

    // --- RefineLoad fields below ---

    /// u: Actual gas used during refinement.
    pub gas_used: Gas,

    /// i: Number of segments imported.
    pub imports_count: u16,

    /// x: Number of extrinsics used.
    pub extrinsics_count: u16,

    /// z: Total size of extrinsics in octets.
    pub extrinsics_size: u32,

    /// e: Number of segments exported.
    pub exports_count: u16,
}

/// Work execution result (WorkExecResult in ASN, eq 11.7).
/// Discriminant values: ok=0, out-of-gas=1, panic=2, bad-exports=3, bad-code=4, code-oversize=5.
#[derive(Clone, Debug)]
pub enum WorkResult {
    /// Successful refinement output (discriminant 0).
    Ok(Vec<u8>),
    /// Out of gas (discriminant 1).
    OutOfGas,
    /// Panic (discriminant 2).
    Panic,
    /// Invalid export count (discriminant 3).
    BadExports,
    /// Invalid code / code not available (discriminant 4).
    BadCode,
    /// Code size exceeds limits (discriminant 5).
    CodeOversize,
}

/// Work package P (eq 14.2, WorkPackage in ASN).
#[derive(Clone, Debug)]
pub struct WorkPackage {
    /// Service ID hosting the authorization code.
    pub auth_code_host: ServiceId,

    /// Hash of the authorizer's code.
    pub auth_code_hash: Hash,

    /// Refinement context.
    pub context: RefinementContext,

    /// Authorization data.
    pub authorization: Vec<u8>,

    /// Parameters for the authorizer.
    pub authorizer_config: Vec<u8>,

    /// w: Work items.
    pub items: Vec<WorkItem>,
}

/// Work item W (eq 14.3).
#[derive(Clone, Debug)]
pub struct WorkItem {
    /// s: Service index.
    pub service_id: ServiceId,

    /// c: Code hash.
    pub code_hash: Hash,

    /// g: Gas limit for refinement.
    pub gas_limit: Gas,

    /// a: Gas limit for accumulation.
    pub accumulate_gas_limit: Gas,

    /// e: Number of exports.
    pub exports_count: u16,

    /// y: Payload.
    pub payload: Vec<u8>,

    /// i: Import segments.
    pub imports: Vec<ImportSegment>,

    /// x: Extrinsics (hash, index) pairs.
    pub extrinsics: Vec<(Hash, u32)>,
}

/// An import segment reference (ImportSpec in ASN).
#[derive(Clone, Debug)]
pub struct ImportSegment {
    /// Root hash of the segment tree.
    pub hash: Hash,
    /// Index of the segment (U16 in ASN).
    pub index: u16,
}
