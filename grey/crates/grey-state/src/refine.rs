//! Refine sub-transition.
//!
//! Implements the work-package processing pipeline:
//! 1. Ψ_I (is-authorized): verify the package is authorized for its core
//! 2. Ψ_R (refine): execute each work item's refinement code
//! 3. Assemble a WorkReport from the results

use crate::pvm_backend::PvmInstance;
use grey_types::config::Config;
use grey_types::constants::GAS_IS_AUTHORIZED;
use grey_types::work::*;
use grey_types::{Hash, ServiceId};
use javm::Gas;
use javm::kernel::KernelResult;
use std::collections::BTreeMap;

/// Error during refinement.
#[derive(Debug, thiserror::Error)]
pub enum RefineError {
    /// Service code not found for the given code hash.
    #[error("code not found: 0x{}", .0.short_hex())]
    CodeNotFound(Hash),
    /// Authorization failed.
    #[error("authorization failed: {0}")]
    AuthorizationFailed(String),
    /// PVM initialization failed.
    #[error("PVM initialization failed")]
    PvmInitFailed,
}

/// Context for looking up service code and state during refinement.
pub trait RefineContext {
    fn get_code(&self, code_hash: &Hash) -> Option<Vec<u8>>;
    fn get_storage(&self, service_id: ServiceId, key: &[u8]) -> Option<Vec<u8>>;
    fn get_preimage(&self, hash: &Hash) -> Option<Vec<u8>>;
}

/// Simple in-memory refine context for testing.
pub struct SimpleRefineContext {
    pub code_blobs: BTreeMap<Hash, Vec<u8>>,
    pub storage: BTreeMap<(ServiceId, Vec<u8>), Vec<u8>>,
    pub preimages: BTreeMap<Hash, Vec<u8>>,
}

impl RefineContext for SimpleRefineContext {
    fn get_code(&self, code_hash: &Hash) -> Option<Vec<u8>> {
        self.code_blobs.get(code_hash).cloned()
    }
    fn get_storage(&self, service_id: ServiceId, key: &[u8]) -> Option<Vec<u8>> {
        self.storage.get(&(service_id, key.to_vec())).cloned()
    }
    fn get_preimage(&self, hash: &Hash) -> Option<Vec<u8>> {
        self.preimages.get(hash).cloned()
    }
}

/// Build an error RefineResult for a work item.
fn error_refine_result(item: &WorkItem, result: WorkResult, gas_used: Gas) -> RefineResult {
    RefineResult {
        digest: WorkDigest {
            service_id: item.service_id,
            code_hash: item.code_hash,
            payload_hash: grey_crypto::blake2b_256(&item.payload),
            accumulate_gas: item.gas_limit.saturating_sub(gas_used),
            result,
            gas_used,
            imports_count: 0,
            extrinsics_count: 0,
            extrinsics_size: 0,
            exports_count: 0,
        },
        exported_segments: vec![],
        expunge_requests: vec![],
    }
}

/// Read output from the kernel's active VM.
fn read_kernel_output(pvm: &PvmInstance) -> Vec<u8> {
    let packed = pvm.reg(7);
    let ptr = (packed >> 32) as u32;
    let len = (packed & 0xFFFFFFFF) as u32;
    pvm.kernel()
        .map(|k| k.read_data_cap_window(ptr, len).unwrap_or_default())
        .unwrap_or_default()
}

/// Run the Is-Authorized invocation Ψ_I (GP eq B.1-B.2).
pub fn invoke_is_authorized(
    _config: &Config,
    code_blob: &[u8],
    authorization: &[u8],
    work_package_encoding: &[u8],
    gas_limit: Gas,
) -> Result<(Vec<u8>, Gas), RefineError> {
    let mut args = Vec::with_capacity(authorization.len() + work_package_encoding.len());
    args.extend_from_slice(authorization);
    args.extend_from_slice(work_package_encoding);

    let mut pvm =
        PvmInstance::initialize(code_blob, &args, gas_limit).ok_or(RefineError::PvmInitFailed)?;

    let initial_gas = pvm.gas();

    loop {
        match pvm.kernel_run() {
            KernelResult::Halt(_) => {
                let gas_used = initial_gas - pvm.gas();
                let output = read_kernel_output(&pvm);
                return Ok((output, gas_used));
            }
            KernelResult::Panic => {
                let pc = pvm
                    .kernel()
                    .map(|k| k.vm_arena.vm(k.active_vm).pc)
                    .unwrap_or(0);
                let gas = pvm.gas();
                tracing::warn!(pc, gas, "PVM panicked during is-authorized");
                return Err(RefineError::AuthorizationFailed(format!(
                    "PVM panic at PC={pc} gas={gas}"
                )));
            }
            KernelResult::OutOfGas => {
                return Err(RefineError::AuthorizationFailed("out of gas".into()));
            }
            KernelResult::PageFault(addr) => {
                return Err(RefineError::AuthorizationFailed(format!(
                    "page fault at 0x{addr:08x}"
                )));
            }
            KernelResult::ProtocolCall { .. } => {
                // Stub: return WHAT for all protocol calls
                pvm.kernel_resume(u64::MAX - 1, 0);
            }
        }
    }
}

/// Result of a single refine invocation.
pub struct RefineResult {
    pub digest: WorkDigest,
    pub exported_segments: Vec<Vec<u8>>,
    pub expunge_requests: Vec<Hash>,
}

/// Run the Refine invocation Ψ_R for a single work item.
pub fn invoke_refine(
    _config: &Config,
    code_blob: &[u8],
    item: &WorkItem,
    _export_offset: u16,
    _import_data: &[Vec<u8>],
    _lookup_ctx: Option<&dyn RefineContext>,
) -> RefineResult {
    let mut pvm = match PvmInstance::initialize(code_blob, &item.payload, item.gas_limit) {
        Some(p) => p,
        None => return error_refine_result(item, WorkResult::BadCode, 0),
    };

    let initial_gas = pvm.gas();
    let exported_segments: Vec<Vec<u8>> = Vec::new();
    let expunge_requests: Vec<Hash> = Vec::new();

    loop {
        match pvm.kernel_run() {
            KernelResult::Halt(_) => {
                let gas_used = initial_gas - pvm.gas();
                let output = read_kernel_output(&pvm);
                let exports_count = exported_segments.len() as u16;
                let result = if item.exports_count != exports_count && item.exports_count > 0 {
                    WorkResult::BadExports
                } else {
                    WorkResult::Ok(output)
                };
                return RefineResult {
                    digest: WorkDigest {
                        service_id: item.service_id,
                        code_hash: item.code_hash,
                        payload_hash: grey_crypto::blake2b_256(&item.payload),
                        accumulate_gas: item.gas_limit.saturating_sub(gas_used),
                        result,
                        gas_used,
                        imports_count: 0,
                        extrinsics_count: 0,
                        extrinsics_size: 0,
                        exports_count,
                    },
                    exported_segments,
                    expunge_requests,
                };
            }
            KernelResult::Panic => {
                let gas_used = initial_gas - pvm.gas();
                return error_refine_result(item, WorkResult::Panic, gas_used);
            }
            KernelResult::OutOfGas => {
                return error_refine_result(item, WorkResult::OutOfGas, initial_gas);
            }
            KernelResult::PageFault(_) => {
                let gas_used = initial_gas - pvm.gas();
                return error_refine_result(item, WorkResult::Panic, gas_used);
            }
            KernelResult::ProtocolCall { .. } => {
                pvm.kernel_resume(u64::MAX - 1, 0);
            }
        }
    }
}

/// Process a work package: is-authorized check + refine each item.
pub fn process_work_package(
    config: &Config,
    package: &WorkPackage,
    ctx: &dyn RefineContext,
    _core_index: u16,
) -> Result<WorkReport, RefineError> {
    let auth_code = ctx
        .get_code(&package.auth_code_hash)
        .ok_or(RefineError::CodeNotFound(package.auth_code_hash))?;

    let wp_encoding = encode_work_package_simple(package);
    let (_auth_output, _auth_gas_used) = invoke_is_authorized(
        config,
        &auth_code,
        &package.authorization,
        &wp_encoding,
        GAS_IS_AUTHORIZED,
    )?;

    let authorizer_hash = grey_crypto::blake2b_256(&auth_code);

    let mut results = Vec::with_capacity(package.items.len());
    let mut all_exported_segments: Vec<Vec<u8>> = Vec::new();
    let mut export_offset: u16 = 0;
    for item in &package.items {
        let item_code = ctx
            .get_code(&item.code_hash)
            .ok_or(RefineError::CodeNotFound(item.code_hash))?;

        let import_data: Vec<Vec<u8>> = Vec::new();

        let refine_result =
            invoke_refine(config, &item_code, item, export_offset, &import_data, None);

        export_offset += refine_result.exported_segments.len() as u16;
        all_exported_segments.extend(refine_result.exported_segments.clone());
        results.push(refine_result.digest);
    }

    Ok(WorkReport {
        package_spec: AvailabilitySpec {
            package_hash: grey_crypto::blake2b_256(&wp_encoding),
            bundle_length: wp_encoding.len() as u32,
            erasure_root: grey_crypto::blake2b_256(&[]),
            exports_root: grey_crypto::blake2b_256(&[]),
            exports_count: all_exported_segments.len() as u16,
            erasure_shards: 0,
        },
        context: package.context.clone(),
        core_index: _core_index,
        authorizer_hash,
        auth_gas_used: _auth_gas_used,
        auth_output: _auth_output,
        results,
        segment_root_lookup: BTreeMap::new(),
    })
}

/// Simple encoding of a work package for is-authorized.
fn encode_work_package_simple(package: &WorkPackage) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&package.authorization);
    for item in &package.items {
        buf.extend_from_slice(&item.payload);
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use grey_types::Hash;
    use std::collections::BTreeMap;

    fn make_context() -> SimpleRefineContext {
        let mut ctx = SimpleRefineContext {
            code_blobs: BTreeMap::new(),
            storage: BTreeMap::new(),
            preimages: BTreeMap::new(),
        };
        let code = vec![0x01, 0x02, 0x03];
        let hash = grey_crypto::blake2b_256(&code);
        ctx.code_blobs.insert(hash, code);
        ctx.storage.insert((42, b"key".to_vec()), b"value".to_vec());
        ctx.preimages.insert(Hash([5u8; 32]), vec![0xAA, 0xBB]);
        ctx
    }

    fn make_work_item() -> WorkItem {
        WorkItem {
            service_id: 42,
            code_hash: Hash([1u8; 32]),
            gas_limit: 10_000,
            accumulate_gas_limit: 5_000,
            exports_count: 0,
            payload: vec![0xDE, 0xAD],
            imports: vec![],
            extrinsics: vec![],
        }
    }

    #[test]
    fn test_simple_context_get_code() {
        let ctx = make_context();
        let code = vec![0x01, 0x02, 0x03];
        let hash = grey_crypto::blake2b_256(&code);
        assert_eq!(ctx.get_code(&hash), Some(code));
        assert_eq!(ctx.get_code(&Hash([0u8; 32])), None);
    }

    #[test]
    fn test_simple_context_get_storage() {
        let ctx = make_context();
        assert_eq!(ctx.get_storage(42, b"key"), Some(b"value".to_vec()));
        assert_eq!(ctx.get_storage(42, b"missing"), None);
        assert_eq!(ctx.get_storage(99, b"key"), None);
    }

    #[test]
    fn test_simple_context_get_preimage() {
        let ctx = make_context();
        assert_eq!(ctx.get_preimage(&Hash([5u8; 32])), Some(vec![0xAA, 0xBB]));
        assert_eq!(ctx.get_preimage(&Hash([6u8; 32])), None);
    }

    #[test]
    fn test_error_refine_result_fields() {
        let item = make_work_item();
        let result = error_refine_result(&item, WorkResult::Panic, 3000);

        assert_eq!(result.digest.service_id, 42);
        assert_eq!(result.digest.code_hash, Hash([1u8; 32]));
        assert_eq!(result.digest.gas_used, 3000);
        // accumulate_gas = gas_limit - gas_used
        assert_eq!(result.digest.accumulate_gas, 10_000 - 3000);
        assert!(matches!(result.digest.result, WorkResult::Panic));
        assert!(result.exported_segments.is_empty());
        assert!(result.expunge_requests.is_empty());
        // payload_hash should be blake2b of the payload
        let expected_hash = grey_crypto::blake2b_256(&item.payload);
        assert_eq!(result.digest.payload_hash, expected_hash);
    }

    #[test]
    fn test_error_refine_result_out_of_gas() {
        let item = make_work_item();
        let result = error_refine_result(&item, WorkResult::OutOfGas, 10_000);

        assert_eq!(result.digest.accumulate_gas, 0); // gas_limit == gas_used
        assert!(matches!(result.digest.result, WorkResult::OutOfGas));
    }

    #[test]
    fn test_encode_work_package_simple_format() {
        let pkg = WorkPackage {
            auth_code_host: 1,
            auth_code_hash: Hash([0u8; 32]),
            context: RefinementContext {
                anchor: Hash::ZERO,
                state_root: Hash::ZERO,
                beefy_root: Hash::ZERO,
                lookup_anchor: Hash::ZERO,
                lookup_anchor_timeslot: 0,
                prerequisites: vec![],
            },
            authorization: vec![0xAA, 0xBB],
            authorizer_config: vec![],
            items: vec![
                WorkItem {
                    service_id: 1,
                    code_hash: Hash::ZERO,
                    gas_limit: 100,
                    accumulate_gas_limit: 50,
                    exports_count: 0,
                    payload: vec![0x01, 0x02],
                    imports: vec![],
                    extrinsics: vec![],
                },
                WorkItem {
                    service_id: 2,
                    code_hash: Hash::ZERO,
                    gas_limit: 200,
                    accumulate_gas_limit: 100,
                    exports_count: 0,
                    payload: vec![0x03],
                    imports: vec![],
                    extrinsics: vec![],
                },
            ],
        };

        let encoded = encode_work_package_simple(&pkg);
        // authorization + item1.payload + item2.payload
        assert_eq!(encoded, vec![0xAA, 0xBB, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_refine_error_display() {
        let e1 = RefineError::CodeNotFound(Hash([0xAB; 32]));
        assert!(e1.to_string().contains("code not found"));

        let e2 = RefineError::AuthorizationFailed("test".into());
        assert!(e2.to_string().contains("authorization failed: test"));

        let e3 = RefineError::PvmInitFailed;
        assert!(e3.to_string().contains("PVM initialization failed"));
    }
}
