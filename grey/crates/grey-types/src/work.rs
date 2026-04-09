//! Work-related types: reports, digests, packages (Sections 11, 14).

use crate::{CoreIndex, Gas, Hash, ServiceId, Timeslot};
use std::collections::BTreeMap;

/// Work report R (eq 11.2).
#[derive(Clone, Debug, Default, scale::Encode, scale::Decode)]
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
#[derive(Clone, Debug, Default, scale::Encode, scale::Decode)]
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

    /// v: Number of erasure-coding shards (GP#514). Not part of wire encoding.
    #[codec(skip)]
    pub erasure_shards: u16,
}

/// Refinement context C (eq 11.4).
#[derive(Clone, Debug, Default, scale::Encode, scale::Decode)]
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
#[derive(Clone, Debug, scale::Encode, scale::Decode)]
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
#[derive(Clone, Debug, scale::Encode, scale::Decode)]
pub enum WorkResult {
    /// Successful refinement output (discriminant 0).
    #[codec(index = 0)]
    Ok(Vec<u8>),
    /// Out of gas (discriminant 1).
    #[codec(index = 1)]
    OutOfGas,
    /// Panic (discriminant 2).
    #[codec(index = 2)]
    Panic,
    /// Invalid export count (discriminant 3).
    #[codec(index = 3)]
    BadExports,
    /// Invalid code / code not available (discriminant 4).
    #[codec(index = 4)]
    BadCode,
    /// Code size exceeds limits (discriminant 5).
    #[codec(index = 5)]
    CodeOversize,
}

/// Work package P (eq 14.2, WorkPackage in ASN).
#[derive(Clone, Debug, scale::Encode, scale::Decode)]
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
#[derive(Clone, Debug, scale::Encode, scale::Decode)]
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
#[derive(Clone, Debug, scale::Encode, scale::Decode)]
pub struct ImportSegment {
    /// Root hash of the segment tree.
    pub hash: Hash,
    /// Index of the segment (U16 in ASN).
    pub index: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hash;
    use crate::test_helpers::assert_codec_roundtrip;

    fn make_work_item() -> WorkItem {
        WorkItem {
            service_id: 42,
            code_hash: Hash([1u8; 32]),
            gas_limit: 10_000,
            accumulate_gas_limit: 5_000,
            exports_count: 0,
            payload: vec![0xDE, 0xAD],
            imports: vec![ImportSegment {
                hash: Hash([2u8; 32]),
                index: 7,
            }],
            extrinsics: vec![(Hash([3u8; 32]), 99)],
        }
    }

    #[test]
    fn test_work_result_roundtrip() {
        assert_codec_roundtrip(&WorkResult::Ok(vec![1, 2, 3]));
        assert_codec_roundtrip(&WorkResult::Ok(vec![]));
        assert_codec_roundtrip(&WorkResult::OutOfGas);
        assert_codec_roundtrip(&WorkResult::Panic);
        assert_codec_roundtrip(&WorkResult::BadExports);
        assert_codec_roundtrip(&WorkResult::BadCode);
        assert_codec_roundtrip(&WorkResult::CodeOversize);
    }

    #[test]
    fn test_work_item_roundtrip() {
        assert_codec_roundtrip(&make_work_item());
    }

    #[test]
    fn test_import_segment_roundtrip() {
        assert_codec_roundtrip(&ImportSegment {
            hash: Hash([0xAB; 32]),
            index: 42,
        });
    }

    #[test]
    fn test_work_digest_roundtrip() {
        assert_codec_roundtrip(&WorkDigest {
            service_id: 1,
            code_hash: Hash([1u8; 32]),
            payload_hash: Hash([2u8; 32]),
            accumulate_gas: 1000,
            result: WorkResult::Ok(vec![0xAB]),
            gas_used: 500,
            imports_count: 1,
            extrinsics_count: 2,
            extrinsics_size: 64,
            exports_count: 0,
        });
    }

    #[test]
    fn test_refinement_context_roundtrip() {
        assert_codec_roundtrip(&RefinementContext {
            anchor: Hash([10u8; 32]),
            state_root: Hash([20u8; 32]),
            beefy_root: Hash([30u8; 32]),
            lookup_anchor: Hash([40u8; 32]),
            lookup_anchor_timeslot: 100,
            prerequisites: vec![Hash([50u8; 32])],
        });
    }

    #[test]
    fn test_work_report_roundtrip() {
        assert_codec_roundtrip(&WorkReport {
            package_spec: AvailabilitySpec {
                package_hash: Hash([1u8; 32]),
                bundle_length: 256,
                erasure_root: Hash([2u8; 32]),
                exports_root: Hash([3u8; 32]),
                exports_count: 1,
                ..Default::default()
            },
            authorizer_hash: Hash([4u8; 32]),
            auth_gas_used: 50,
            auth_output: vec![0xFF],
            results: vec![WorkDigest {
                service_id: 42,
                code_hash: Hash([5u8; 32]),
                payload_hash: Hash([6u8; 32]),
                accumulate_gas: 1000,
                result: WorkResult::Ok(vec![]),
                gas_used: 800,
                imports_count: 0,
                extrinsics_count: 0,
                extrinsics_size: 0,
                exports_count: 0,
            }],
            ..Default::default()
        });
    }

    #[test]
    fn test_work_package_roundtrip() {
        assert_codec_roundtrip(&WorkPackage {
            auth_code_host: 1,
            auth_code_hash: Hash([10u8; 32]),
            context: RefinementContext::default(),
            authorization: vec![0xAA, 0xBB],
            authorizer_config: vec![],
            items: vec![make_work_item()],
        });
    }
}
