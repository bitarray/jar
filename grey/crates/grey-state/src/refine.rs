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
pub enum RefineError {
    /// Service code not found for the given code hash.
    CodeNotFound(Hash),
    /// Authorization failed.
    AuthorizationFailed(String),
    /// PVM initialization failed.
    PvmInitFailed,
}

impl std::fmt::Display for RefineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RefineError::CodeNotFound(h) => {
                write!(f, "code not found: 0x{}", hex::encode(&h.0[..8]))
            }
            RefineError::AuthorizationFailed(msg) => write!(f, "authorization failed: {msg}"),
            RefineError::PvmInitFailed => write!(f, "PVM initialization failed"),
        }
    }
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
                    .map(|k| k.vms[k.active_vm as usize].pc)
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
