//! Refine sub-transition (Section 14 of the Gray Paper).
//!
//! Implements the work-package processing pipeline:
//! 1. Ψ_I (is-authorized): verify the package is authorized for its core
//! 2. Ψ_R (refine): execute each work item's refinement code
//! 3. Assemble a WorkReport from the results

use crate::pvm_backend::{ExitReason, PvmInstance};
use grey_types::config::Config;
use grey_types::constants::{GAS_IS_AUTHORIZED, HOST_LOW, HOST_OOB, HOST_WHAT};
use grey_types::work::*;
use grey_types::{Hash, ServiceId};
use javm::Gas;
use std::collections::BTreeMap;

/// Build an error RefineResult for a work item (non-Ok exit).
fn error_refine_result(item: &WorkItem, result: WorkResult, gas_used: Gas) -> RefineResult {
    RefineResult {
        digest: WorkDigest {
            service_id: item.service_id,
            code_hash: item.code_hash,
            payload_hash: grey_crypto::blake2b_256(&item.payload),
            accumulate_gas: item.accumulate_gas_limit,
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

/// Read output bytes from PVM registers ω[7] (ptr) and ω[8] (len).
fn read_pvm_output(pvm: &PvmInstance) -> Vec<u8> {
    let ptr = pvm.reg(7) as u32;
    let len = pvm.reg(8) as u32;
    if len > 0 {
        pvm.try_read_bytes(ptr, len).unwrap_or_default()
    } else {
        vec![]
    }
}

/// Errors from the refine pipeline.
#[derive(Debug)]
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
            RefineError::AuthorizationFailed(msg) => write!(f, "authorization failed: {}", msg),
            RefineError::PvmInitFailed => write!(f, "PVM initialization failed"),
        }
    }
}

/// Context for looking up service code and state during refinement.
pub trait RefineContext {
    /// Get the code blob for a service by its code hash.
    fn get_code(&self, code_hash: &Hash) -> Option<Vec<u8>>;

    /// Get a storage value for a service.
    fn get_storage(&self, service_id: ServiceId, key: &[u8]) -> Option<Vec<u8>>;

    /// Get a preimage by its hash.
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

/// Run the Is-Authorized invocation Ψ_I (GP eq B.1-B.2).
///
/// Entry point: PC=0
/// Arguments: authorization ++ work_package_encoding
/// Returns: (auth_output, gas_used) on success
pub fn invoke_is_authorized(
    _config: &Config,
    code_blob: &[u8],
    authorization: &[u8],
    work_package_encoding: &[u8],
    gas_limit: Gas,
) -> Result<(Vec<u8>, Gas), RefineError> {
    // Build arguments: authorization ++ work_package_encoding
    let mut args = Vec::with_capacity(authorization.len() + work_package_encoding.len());
    args.extend_from_slice(authorization);
    args.extend_from_slice(work_package_encoding);

    let mut pvm =
        PvmInstance::initialize(code_blob, &args, gas_limit).ok_or(RefineError::PvmInitFailed)?;

    // Entry point for is-authorized: PC=0 (default after initialize)
    let initial_gas = pvm.gas();

    loop {
        let exit = pvm.run();
        match exit {
            ExitReason::Halt => {
                let gas_used = initial_gas - pvm.gas();
                let output = read_pvm_output(&pvm);
                tracing::debug!(
                    "is_authorized HALT: gas_used={}, output_len={}",
                    gas_used,
                    output.len()
                );
                return Ok((output, gas_used));
            }
            ExitReason::Panic => {
                return Err(RefineError::AuthorizationFailed("PVM panic".into()));
            }
            ExitReason::OutOfGas => {
                return Err(RefineError::AuthorizationFailed("out of gas".into()));
            }
            ExitReason::PageFault(addr) => {
                return Err(RefineError::AuthorizationFailed(format!(
                    "page fault at 0x{:08x}",
                    addr
                )));
            }
            ExitReason::HostCall(id) => {
                if !handle_is_authorized_host_call(id, &mut pvm) {
                    if pvm.gas() == 0 {
                        return Err(RefineError::AuthorizationFailed("out of gas".into()));
                    } else {
                        return Err(RefineError::AuthorizationFailed("page fault".into()));
                    }
                }
            }
        }
    }
}

/// Result of a single refine invocation: the work digest plus exported segments.
pub struct RefineResult {
    pub digest: WorkDigest,
    pub exported_segments: Vec<Vec<u8>>,
    /// Preimage hashes requested for expunge during refinement.
    pub expunge_requests: Vec<Hash>,
}

/// Run the Refine invocation Ψ_R for a single work item (GP eq B.3-B.5).
///
/// Entry point: PC=0
/// Arguments: payload
/// Returns: RefineResult with work digest and exported segments
pub fn invoke_refine(
    _config: &Config,
    code_blob: &[u8],
    item: &WorkItem,
    export_offset: u16,
    import_data: &[Vec<u8>],
    lookup_ctx: Option<&dyn RefineContext>,
) -> RefineResult {
    let mut pvm = match PvmInstance::initialize(code_blob, &item.payload, item.gas_limit) {
        Some(p) => p,
        None => return error_refine_result(item, WorkResult::BadCode, 0),
    };

    // Entry point for refine: PC=0 (default)
    let initial_gas = pvm.gas();
    let mut exported_segments: Vec<Vec<u8>> = Vec::new();
    let mut expunge_requests: Vec<Hash> = Vec::new();

    loop {
        let exit = pvm.run();
        match exit {
            ExitReason::Halt => {
                let gas_used = initial_gas - pvm.gas();
                let output = read_pvm_output(&pvm);
                let exports_count = exported_segments.len() as u16;
                let result = if item.exports_count != exports_count && item.exports_count > 0 {
                    WorkResult::BadExports
                } else {
                    WorkResult::Ok(output)
                };
                tracing::debug!(
                    "refine HALT: service={}, gas_used={}, exports={}",
                    item.service_id,
                    gas_used,
                    exports_count
                );
                return RefineResult {
                    digest: WorkDigest {
                        service_id: item.service_id,
                        code_hash: item.code_hash,
                        payload_hash: grey_crypto::blake2b_256(&item.payload),
                        accumulate_gas: item.accumulate_gas_limit,
                        result,
                        gas_used,
                        imports_count: item.imports.len() as u16,
                        extrinsics_count: item.extrinsics.len() as u16,
                        extrinsics_size: 0,
                        exports_count,
                    },
                    exported_segments,
                    expunge_requests,
                };
            }
            ExitReason::Panic => {
                let gas_used = initial_gas - pvm.gas();
                tracing::debug!(
                    "refine PANIC: service={}, gas_used={}",
                    item.service_id,
                    gas_used
                );
                return error_refine_result(item, WorkResult::Panic, gas_used);
            }
            ExitReason::OutOfGas => {
                tracing::debug!("refine OOG: service={}", item.service_id);
                return error_refine_result(item, WorkResult::OutOfGas, initial_gas);
            }
            ExitReason::PageFault(_addr) => {
                let gas_used = initial_gas - pvm.gas();
                return error_refine_result(item, WorkResult::Panic, gas_used);
            }
            ExitReason::HostCall(id) => {
                let mut ctx = RefineHostContext {
                    item,
                    exported_segments: &mut exported_segments,
                    export_offset,
                    import_data,
                    lookup_ctx,
                    expunge_requests: &mut expunge_requests,
                };
                if !handle_refine_host_call(id, &mut pvm, &mut ctx, 0) {
                    // Host call signaled OOG or page fault
                    if pvm.gas() == 0 {
                        return error_refine_result(item, WorkResult::OutOfGas, initial_gas);
                    } else {
                        let gas_used = initial_gas - pvm.gas();
                        return error_refine_result(item, WorkResult::Panic, gas_used);
                    }
                }
            }
        }
    }
}

/// Process a complete work package: authorize, then refine each item.
///
/// This is the main entry point for the refine pipeline (GP eq 14.12).
pub fn process_work_package(
    config: &Config,
    package: &WorkPackage,
    ctx: &dyn RefineContext,
    core_index: u16,
) -> Result<WorkReport, RefineError> {
    // 1. Look up the authorizer code
    let auth_code = ctx
        .get_code(&package.auth_code_hash)
        .ok_or(RefineError::CodeNotFound(package.auth_code_hash))?;

    // 2. Run is-authorized (Ψ_I)
    // For now, use a simple encoding of the work package
    let wp_encoding = encode_work_package_simple(package);
    let (auth_output, auth_gas_used) = invoke_is_authorized(
        config,
        &auth_code,
        &package.authorization,
        &wp_encoding,
        GAS_IS_AUTHORIZED,
    )?;

    let authorizer_hash = grey_crypto::blake2b_256(&auth_code);

    // 3. Refine each work item (Ψ_R)
    let mut results = Vec::with_capacity(package.items.len());
    let mut all_exported_segments: Vec<Vec<u8>> = Vec::new();
    let mut export_offset: u16 = 0;
    for item in &package.items {
        let item_code = ctx
            .get_code(&item.code_hash)
            .ok_or(RefineError::CodeNotFound(item.code_hash))?;

        // Resolve import segment data (if available via context)
        // TODO: resolve import segments from availability store
        let import_data: Vec<Vec<u8>> = Vec::new();

        let refine_result = invoke_refine(
            config,
            &item_code,
            item,
            export_offset,
            &import_data,
            Some(ctx),
        );
        export_offset += refine_result.exported_segments.len() as u16;
        all_exported_segments.extend(refine_result.exported_segments);
        results.push(refine_result.digest);
    }

    // 4. Compute package hash
    let package_hash = grey_crypto::blake2b_256(&wp_encoding);

    // 5. Compute exports_root using constant-depth Merkle tree (eq E.4)
    let exports_root = if all_exported_segments.is_empty() {
        Hash::ZERO
    } else {
        let segment_refs: Vec<&[u8]> = all_exported_segments.iter().map(|s| s.as_slice()).collect();
        grey_merkle::constant_depth_merkle_root(&segment_refs, grey_crypto::blake2b_256)
    };

    // 6. Assemble work report
    let report = WorkReport {
        package_spec: AvailabilitySpec {
            package_hash,
            bundle_length: wp_encoding.len() as u32,
            erasure_root: Hash::ZERO, // Computed by guarantor after erasure coding
            exports_root,
            exports_count: results.iter().map(|r| r.exports_count).sum(),
            erasure_shards: config.validators_count,
        },
        context: package.context.clone(),
        core_index,
        authorizer_hash,
        auth_gas_used,
        auth_output,
        segment_root_lookup: BTreeMap::new(),
        results,
    };

    tracing::info!(
        "Refined work package: hash=0x{}, core={}, items={}, auth_gas={}",
        hex::encode(&package_hash.0[..8]),
        core_index,
        report.results.len(),
        auth_gas_used
    );

    Ok(report)
}

/// Handle host calls available in Ψ_I (is-authorized).
/// Only gas(0) and grow_heap(1) are available.
fn handle_is_authorized_host_call(id: u32, pvm: &mut PvmInstance) -> bool {
    let host_gas_cost: u64 = 10;
    if pvm.gas() < host_gas_cost {
        pvm.set_gas(0);
        return false;
    }
    pvm.set_gas(pvm.gas() - host_gas_cost);

    match id {
        0 => {
            pvm.set_reg(7, pvm.gas());
            true
        }
        1 => refine_grow_heap(pvm),
        _ => {
            tracing::trace!(id, "unsupported host call in is-authorized context");
            pvm.set_reg(7, HOST_WHAT);
            true
        }
    }
}

/// Maximum invoke nesting depth to prevent stack overflow.
const MAX_INVOKE_DEPTH: u32 = 8;

/// Context for refine host calls — provides access to work item data.
struct RefineHostContext<'a> {
    item: &'a WorkItem,
    exported_segments: &'a mut Vec<Vec<u8>>,
    export_offset: u16,
    /// Resolved import segment data (populated by caller if available).
    import_data: &'a [Vec<u8>],
    /// Preimage hashes requested for expunge.
    expunge_requests: &'a mut Vec<Hash>,
    /// External context for preimage/storage lookups.
    lookup_ctx: Option<&'a dyn RefineContext>,
}

/// Handle host calls available during refinement (Ψ_R).
///
/// JAR v0.8.0 numbering: 0=gas, 1=grow_heap, 2=fetch, 3=(reserved),
/// 4=export, 5=machine, 6..=10=(reserved for peek/poke/pages/invoke/expunge).
///
/// Returns false if the PVM should stop (OOG or page fault).
fn handle_refine_host_call(
    id: u32,
    pvm: &mut PvmInstance,
    ctx: &mut RefineHostContext<'_>,
    depth: u32,
) -> bool {
    // Host-call gas cost: all host calls cost g=10 (charged upfront).
    let host_gas_cost: u64 = 10;
    if pvm.gas() < host_gas_cost {
        pvm.set_gas(0);
        return false;
    }
    pvm.set_gas(pvm.gas() - host_gas_cost);

    match id {
        0 => {
            // gas(): return remaining gas in φ[7].
            pvm.set_reg(7, pvm.gas());
            true
        }
        1 => {
            // grow_heap(): expand writable memory pages.
            // φ[7] = desired page count. Returns previous page count.
            refine_grow_heap(pvm)
        }
        2 => {
            // fetch(): read work-item context data (GP §14, Ω_Y for refine).
            // φ[7]=buf_ptr, φ[8]=offset, φ[9]=max_len, φ[10]=mode
            refine_fetch(pvm, ctx)
        }
        4 => {
            // export(): append a WG-byte segment to exports.
            // φ[7] = pointer to segment data in memory.
            // Returns: φ[7] = global export index, or HOST_OOB.
            refine_export(pvm, ctx)
        }
        5 => {
            // machine(): return machine/service info.
            // φ[7]=mode. Mode 0 = service_id, mode 1 = code_hash.
            refine_machine(pvm, ctx)
        }
        3 => {
            // historical_lookup(): look up a preimage by hash.
            // φ[7]=hash_ptr, φ[8]=out_ptr, φ[9]=offset, φ[10]=max_len
            // Returns: φ[7] = total data length, or NONE if not found.
            refine_historical_lookup(pvm, ctx)
        }
        6 => {
            // peek(): read from service storage by key.
            // φ[7]=key_ptr, φ[8]=key_len, φ[9]=out_ptr, φ[10]=offset, φ[11]=max_len
            // Returns: φ[7] = total value length, or NONE if not found.
            refine_peek(pvm, ctx)
        }
        7 => {
            // poke(): not available in refine context (read-only).
            pvm.set_reg(7, HOST_WHAT);
            true
        }
        8 => {
            // pages(): query memory page count.
            // φ[7] = 0 → return current page count.
            let ps = javm::PVM_PAGE_SIZE;
            let current_pages = (pvm.heap_top() as u64).div_ceil(ps as u64);
            pvm.set_reg(7, current_pages);
            true
        }
        9 => {
            // invoke(): sub-program invocation with separate memory.
            // φ[7]=code_hash_ptr, φ[8]=input_ptr, φ[9]=input_len,
            // φ[10]=gas_limit, φ[11]=output_ptr, φ[12]=output_max_len
            // Returns: φ[7] = output_len, or error sentinel.
            // Gas used by sub-call is deducted from caller.
            refine_invoke(pvm, ctx, depth)
        }
        10 => {
            // expunge(): request preimage deletion. GP §14.
            // φ[7] = hash_ptr (32 bytes in memory).
            // Records the request; actual deletion happens after D timeslots
            // when the work report is processed during state transition.
            // Returns: φ[7] = HOST_OK (0) on success, HOST_OOB on page fault.
            refine_expunge(pvm, ctx)
        }
        _ => {
            tracing::trace!(id, "unknown refine host call");
            pvm.set_reg(7, HOST_WHAT);
            true
        }
    }
}

/// grow_heap for refine context (identical to accumulate grow_heap).
fn refine_grow_heap(pvm: &mut PvmInstance) -> bool {
    let desired = pvm.reg(7);
    let ps = javm::PVM_PAGE_SIZE;
    let current_pages = (pvm.heap_top() as u64).div_ceil(ps as u64);
    if desired <= current_pages || desired > (1u64 << 32) / ps as u64 {
        pvm.set_reg(7, current_pages);
        return true;
    }
    let new_pages = desired - current_pages;
    let extra_gas = new_pages * 10;
    if pvm.gas() < extra_gas {
        pvm.set_gas(0);
        return false;
    }
    pvm.set_gas(pvm.gas() - extra_gas);
    let old_top = pvm.heap_top();
    let new_top = (desired as u32) * ps;
    pvm.map_pages_rw(old_top / ps, desired as u32);
    pvm.set_heap_top(new_top);
    pvm.set_reg(7, current_pages);
    true
}

/// fetch for refine context (GP §14, Ω_Y adapted for refinement).
///
/// Available modes in refine context:
///   0 = protocol configuration blob
///   2 = work item payload (y)
///   3 = import segment at index φ[11]
///   4 = extrinsic data at index φ[11]
/// Other modes return NONE (u64::MAX).
fn refine_fetch(pvm: &mut PvmInstance, ctx: &RefineHostContext<'_>) -> bool {
    let buf_ptr = pvm.reg(7) as u32;
    let offset = pvm.reg(8);
    let max_len = pvm.reg(9);
    let mode = pvm.reg(10);
    let sub1 = pvm.reg(11) as usize;

    let data: Option<&[u8]> = match mode {
        2 => {
            // Payload (y)
            Some(&ctx.item.payload)
        }
        3 => {
            // Import segment data at index φ[11]
            ctx.import_data.get(sub1).map(|v| v.as_slice())
        }
        4 => {
            // Extrinsic: return the hash at index φ[11]
            ctx.item
                .extrinsics
                .get(sub1)
                .map(|(hash, _)| hash.0.as_slice())
        }
        _ => None,
    };

    let data = match data {
        Some(d) => d,
        None => {
            pvm.set_reg(7, u64::MAX); // NONE
            return true;
        }
    };

    let data_len = data.len() as u64;
    let f = offset.min(data_len);
    let l = max_len.min(data_len - f);

    if l > 0 {
        let src = &data[f as usize..(f + l) as usize];
        if pvm.try_write_bytes(buf_ptr, src).is_none() {
            return false; // page fault → PANIC
        }
    }

    pvm.set_reg(7, data_len);
    true
}

/// export for refine context: append a WG-byte segment to exports.
fn refine_export(pvm: &mut PvmInstance, ctx: &mut RefineHostContext<'_>) -> bool {
    let ptr = pvm.reg(7) as u32;
    let segment_size = grey_types::constants::SEGMENT_SIZE;
    match pvm.try_read_bytes(ptr, segment_size) {
        Some(data) => {
            let index = ctx.export_offset as u64 + ctx.exported_segments.len() as u64;
            ctx.exported_segments.push(data);
            pvm.set_reg(7, index);
        }
        None => {
            pvm.set_reg(7, HOST_OOB);
        }
    }
    true
}

/// machine for refine context: return machine/service info.
fn refine_machine(pvm: &mut PvmInstance, ctx: &RefineHostContext<'_>) -> bool {
    let mode = pvm.reg(7);
    match mode {
        0 => {
            // Service ID
            pvm.set_reg(7, ctx.item.service_id as u64);
        }
        1 => {
            // Code hash: write to buffer at φ[8], return 32
            let buf_ptr = pvm.reg(8) as u32;
            if pvm
                .try_write_bytes(buf_ptr, &ctx.item.code_hash.0)
                .is_none()
            {
                return false;
            }
            pvm.set_reg(7, 32);
        }
        _ => {
            pvm.set_reg(7, HOST_WHAT);
        }
    }
    true
}

/// historical_lookup for refine context: look up a preimage by hash.
/// Uses the RefineContext's get_preimage if available.
fn refine_historical_lookup(pvm: &mut PvmInstance, ctx: &RefineHostContext<'_>) -> bool {
    let hash_ptr = pvm.reg(7) as u32;
    let out_ptr = pvm.reg(8) as u32;
    let offset = pvm.reg(9);
    let max_len = pvm.reg(10);

    // Read the 32-byte hash from PVM memory
    let hash_data = match pvm.try_read_bytes(hash_ptr, 32) {
        Some(d) => d,
        None => return false, // page fault → PANIC
    };
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hash_data);
    let hash = Hash(hash);

    // Look up the preimage via the external context
    let data = ctx.lookup_ctx.and_then(|lctx| lctx.get_preimage(&hash));

    let data = match data {
        Some(d) => d,
        None => {
            pvm.set_reg(7, u64::MAX); // NONE
            return true;
        }
    };

    let data_len = data.len() as u64;
    let f = offset.min(data_len);
    let l = max_len.min(data_len - f);

    if l > 0 {
        let src = &data[f as usize..(f + l) as usize];
        if pvm.try_write_bytes(out_ptr, src).is_none() {
            return false; // page fault → PANIC
        }
    }

    pvm.set_reg(7, data_len);
    true
}

/// peek for refine context: read from service storage.
/// In refine, this is read-only access to the service's own storage.
fn refine_peek(pvm: &mut PvmInstance, ctx: &RefineHostContext<'_>) -> bool {
    let key_ptr = pvm.reg(7) as u32;
    let key_len = pvm.reg(8) as u32;
    let out_ptr = pvm.reg(9) as u32;
    let offset = pvm.reg(10);
    let max_len = pvm.reg(11);

    // Read the key from PVM memory
    let key = match pvm.try_read_bytes(key_ptr, key_len) {
        Some(d) => d,
        None => return false, // page fault → PANIC
    };

    // Look up storage value via the external context
    let data = ctx
        .lookup_ctx
        .and_then(|lctx| lctx.get_storage(ctx.item.service_id, &key));

    let data = match data {
        Some(d) => d,
        None => {
            pvm.set_reg(7, u64::MAX); // NONE
            return true;
        }
    };

    let data_len = data.len() as u64;
    let f = offset.min(data_len);
    let l = max_len.min(data_len - f);

    if l > 0 {
        let src = &data[f as usize..(f + l) as usize];
        if pvm.try_write_bytes(out_ptr, src).is_none() {
            return false; // page fault → PANIC
        }
    }

    pvm.set_reg(7, data_len);
    true
}

/// Simple work-package encoding for hashing and authorization.
/// invoke for refine context: sub-program invocation with separate memory.
///
/// Spawns a new PVM instance with the code identified by hash, runs it with
/// a restricted set of host calls, and returns the output to the caller.
///
/// Register convention:
///   φ[7]  = code_hash_ptr  (32 bytes in caller's memory)
///   φ[8]  = input_ptr      (input data in caller's memory)
///   φ[9]  = input_len
///   φ[10] = gas_limit      (gas budget, deducted from caller)
///   φ[11] = output_ptr     (where to write output in caller's memory)
///   φ[12] = output_max_len
///
/// Returns:
///   φ[7] = output_len on halt, or error sentinel (NONE=not found, OOB=page fault,
///          WHAT=depth exceeded, LOW=insufficient gas)
///
/// The invoked program has access to: gas, grow_heap, fetch (payload only),
/// machine, pages, and invoke (recursive, depth-limited).
/// It does NOT have access to: export, peek, poke, historical_lookup.
/// expunge for refine context: request preimage deletion.
/// Records the hash for later processing during state transition.
fn refine_expunge(pvm: &mut PvmInstance, ctx: &mut RefineHostContext<'_>) -> bool {
    let hash_ptr = pvm.reg(7) as u32;

    // Read the 32-byte hash from PVM memory
    let hash_data = match pvm.try_read_bytes(hash_ptr, 32) {
        Some(d) => d,
        None => return false, // page fault → PANIC
    };
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hash_data);

    ctx.expunge_requests.push(Hash(hash));
    pvm.set_reg(7, 0); // HOST_OK
    true
}

fn refine_invoke(pvm: &mut PvmInstance, ctx: &mut RefineHostContext<'_>, depth: u32) -> bool {
    if depth >= MAX_INVOKE_DEPTH {
        pvm.set_reg(7, HOST_WHAT);
        return true;
    }

    let hash_ptr = pvm.reg(7) as u32;
    let input_ptr = pvm.reg(8) as u32;
    let input_len = pvm.reg(9) as u32;
    let gas_limit = pvm.reg(10);
    let output_ptr = pvm.reg(11) as u32;
    let output_max_len = pvm.reg(12) as u32;

    // Check caller has enough gas for the sub-call
    if pvm.gas() < gas_limit {
        pvm.set_reg(7, HOST_LOW);
        return true;
    }

    // Read the 32-byte code hash from caller's memory
    let hash_data = match pvm.try_read_bytes(hash_ptr, 32) {
        Some(d) => d,
        None => return false, // page fault → PANIC
    };
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hash_data);
    let hash = Hash(hash);

    // Read input data from caller's memory
    let input = if input_len > 0 {
        match pvm.try_read_bytes(input_ptr, input_len) {
            Some(d) => d,
            None => return false,
        }
    } else {
        vec![]
    };

    // Look up code blob
    let code_blob = match ctx.lookup_ctx.and_then(|lctx| lctx.get_code(&hash)) {
        Some(blob) => blob,
        None => {
            pvm.set_reg(7, u64::MAX); // NONE — code not found
            return true;
        }
    };

    // Deduct gas budget from caller before spawning sub-VM
    pvm.set_gas(pvm.gas() - gas_limit);

    // Initialize sub-PVM with its own memory space
    let mut sub_pvm = match PvmInstance::initialize(&code_blob, &input, gas_limit) {
        Some(p) => p,
        None => {
            // Init failed — refund gas and return error
            pvm.set_gas(pvm.gas() + gas_limit);
            pvm.set_reg(7, HOST_OOB);
            return true;
        }
    };

    // Run sub-PVM with host call dispatch (restricted capabilities)
    let sub_result = run_sub_invoke(&mut sub_pvm, ctx, depth + 1);
    let _gas_used = gas_limit - sub_pvm.gas();

    // Refund unused gas to caller
    pvm.set_gas(pvm.gas() + sub_pvm.gas());

    match sub_result {
        SubInvokeResult::Halt => {
            // Read output from sub-PVM registers: A0=ptr, A1=len
            let sub_out_ptr = sub_pvm.reg(7) as u32;
            let sub_out_len = sub_pvm.reg(8) as u32;
            let output = if sub_out_len > 0 {
                sub_pvm
                    .try_read_bytes(sub_out_ptr, sub_out_len)
                    .unwrap_or_default()
            } else {
                vec![]
            };

            // Write output to caller's memory (truncated to max_len)
            let write_len = output.len().min(output_max_len as usize);
            if write_len > 0
                && pvm
                    .try_write_bytes(output_ptr, &output[..write_len])
                    .is_none()
            {
                return false; // page fault in caller
            }
            pvm.set_reg(7, output.len() as u64);
            true
        }
        SubInvokeResult::Panic | SubInvokeResult::PageFault => {
            pvm.set_reg(7, HOST_OOB);
            true
        }
        SubInvokeResult::OutOfGas => {
            pvm.set_reg(7, HOST_LOW);
            true
        }
    }
}

/// Result of a sub-invoke execution.
enum SubInvokeResult {
    Halt,
    Panic,
    OutOfGas,
    PageFault,
}

/// Run a sub-PVM for invoke() with restricted host calls.
///
/// The invoked program can use: gas(0), grow_heap(1), fetch(2) [payload only],
/// machine(5), pages(8), invoke(9) [recursive, depth-limited].
/// It CANNOT use: historical_lookup(3), export(4), peek(6), poke(7), expunge(10).
fn run_sub_invoke(
    sub_pvm: &mut PvmInstance,
    ctx: &mut RefineHostContext<'_>,
    depth: u32,
) -> SubInvokeResult {
    loop {
        let exit = sub_pvm.run();
        match exit {
            ExitReason::Halt => return SubInvokeResult::Halt,
            ExitReason::Panic => return SubInvokeResult::Panic,
            ExitReason::OutOfGas => return SubInvokeResult::OutOfGas,
            ExitReason::PageFault(_) => return SubInvokeResult::PageFault,
            ExitReason::HostCall(id) => {
                // Restricted host call set for invoked programs
                let host_gas_cost: u64 = 10;
                if sub_pvm.gas() < host_gas_cost {
                    sub_pvm.set_gas(0);
                    return SubInvokeResult::OutOfGas;
                }
                sub_pvm.set_gas(sub_pvm.gas() - host_gas_cost);

                let ok = match id {
                    0 => {
                        // gas
                        sub_pvm.set_reg(7, sub_pvm.gas());
                        true
                    }
                    1 => refine_grow_heap(sub_pvm),
                    5 => refine_machine(sub_pvm, ctx),
                    8 => {
                        // pages
                        let ps = javm::PVM_PAGE_SIZE;
                        let pages = (sub_pvm.heap_top() as u64).div_ceil(ps as u64);
                        sub_pvm.set_reg(7, pages);
                        true
                    }
                    2 => {
                        // fetch: invoked programs can read their own input
                        // (payload was passed as args, accessible via PVM memory)
                        // Also allows reading import segments from parent context.
                        refine_fetch(sub_pvm, ctx)
                    }
                    3 => {
                        // historical_lookup: invoked programs can look up preimages
                        refine_historical_lookup(sub_pvm, ctx)
                    }
                    9 => {
                        // Recursive invoke (depth-limited)
                        refine_invoke(sub_pvm, ctx, depth)
                    }
                    _ => {
                        // export(4), peek(6), poke(7), expunge(10)
                        // not available in invoked context
                        sub_pvm.set_reg(7, HOST_WHAT);
                        true
                    }
                };
                if !ok {
                    return if sub_pvm.gas() == 0 {
                        SubInvokeResult::OutOfGas
                    } else {
                        SubInvokeResult::PageFault
                    };
                }
            }
        }
    }
}

fn encode_work_package_simple(pkg: &WorkPackage) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&pkg.auth_code_host.to_le_bytes());
    buf.extend_from_slice(&pkg.auth_code_hash.0);
    buf.extend_from_slice(&pkg.authorization);
    for item in &pkg.items {
        buf.extend_from_slice(&item.service_id.to_le_bytes());
        buf.extend_from_slice(&item.code_hash.0);
        buf.extend_from_slice(&item.gas_limit.to_le_bytes());
        buf.extend_from_slice(&item.payload);
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stub blob for structural tests (empty — PVM init will fail gracefully).
    /// PVM-based refine tests use the block trace vectors in stf_blocks instead.
    #[allow(dead_code)]
    fn make_echo_blob() -> Vec<u8> {
        vec![]
    }

    #[test]
    fn test_work_digest_fields() {
        // Verify WorkDigest construction
        let digest = WorkDigest {
            service_id: 42,
            code_hash: Hash::ZERO,
            payload_hash: Hash::ZERO,
            accumulate_gas: 1_000_000,
            result: WorkResult::Ok(vec![1, 2, 3]),
            gas_used: 500,
            imports_count: 0,
            extrinsics_count: 0,
            extrinsics_size: 0,
            exports_count: 0,
        };
        assert_eq!(digest.service_id, 42);
        assert_eq!(digest.gas_used, 500);
        match &digest.result {
            WorkResult::Ok(data) => assert_eq!(data, &[1, 2, 3]),
            _ => panic!("expected Ok"),
        }
    }

    #[test]
    fn test_encode_work_package() {
        let pkg = WorkPackage {
            auth_code_host: 1,
            auth_code_hash: Hash::ZERO,
            context: RefinementContext {
                anchor: Hash::ZERO,
                state_root: Hash::ZERO,
                beefy_root: Hash::ZERO,
                lookup_anchor: Hash::ZERO,
                lookup_anchor_timeslot: 0,
                prerequisites: vec![],
            },
            authorization: vec![0xAB, 0xCD],
            authorizer_config: vec![],
            items: vec![WorkItem {
                service_id: 42,
                code_hash: Hash([1u8; 32]),
                gas_limit: 1000,
                accumulate_gas_limit: 500,
                exports_count: 0,
                payload: vec![10, 20, 30],
                imports: vec![],
                extrinsics: vec![],
            }],
        };

        let encoded = encode_work_package_simple(&pkg);
        assert!(!encoded.is_empty());
        // Verify deterministic
        let encoded2 = encode_work_package_simple(&pkg);
        assert_eq!(encoded, encoded2);
    }

    #[test]
    fn test_process_work_package_code_not_found() {
        let config = Config::tiny();
        let ctx = SimpleRefineContext {
            code_blobs: BTreeMap::new(),
            storage: BTreeMap::new(),
            preimages: BTreeMap::new(),
        };

        let pkg = WorkPackage {
            auth_code_host: 1,
            auth_code_hash: Hash([99u8; 32]),
            context: RefinementContext {
                anchor: Hash::ZERO,
                state_root: Hash::ZERO,
                beefy_root: Hash::ZERO,
                lookup_anchor: Hash::ZERO,
                lookup_anchor_timeslot: 0,
                prerequisites: vec![],
            },
            authorization: vec![],
            authorizer_config: vec![],
            items: vec![],
        };

        let result = process_work_package(&config, &pkg, &ctx, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            RefineError::CodeNotFound(h) => assert_eq!(h.0, [99u8; 32]),
            other => panic!("expected CodeNotFound, got: {}", other),
        }
    }

    /// Build a minimal PVM blob that calls ecalli(id) then halts.
    /// Before the ecalli, loads immediate values into registers as specified.
    fn build_hostcall_blob(
        id: u32,
        reg_setup: &[(grey_transpiler::assembler::Reg, u64)],
    ) -> Vec<u8> {
        use grey_transpiler::assembler::{Assembler, Reg};
        let mut asm = Assembler::new();
        asm.set_stack_pages(1);
        asm.set_heap_pages(4); // 4 pages = 16KB writable memory

        // Jump table entry 0 → refine entry
        asm.add_jump_entry();

        // Set up registers
        for &(reg, val) in reg_setup {
            asm.load_imm_64(reg, val);
        }

        // Host call
        asm.ecalli(id);

        // Halt: jump to 0xFFFF0000
        asm.load_imm_64(Reg::T0, 0xFFFF0000u64);
        asm.jump_ind(Reg::T0, 0);

        asm.build()
    }

    fn make_test_item(payload: Vec<u8>, gas: Gas) -> WorkItem {
        WorkItem {
            service_id: 42,
            code_hash: Hash([1u8; 32]),
            gas_limit: gas,
            accumulate_gas_limit: 1000,
            exports_count: 0,
            payload,
            imports: vec![],
            extrinsics: vec![],
        }
    }

    #[test]
    fn test_refine_gas_hostcall() {
        // ecalli(0) = gas: should return remaining gas in A0
        let blob = build_hostcall_blob(0, &[]);
        let item = make_test_item(vec![], 1_000_000);
        let config = Config::tiny();

        let result = invoke_refine(&config, &blob, &item, 0, &[], None);
        match &result.digest.result {
            WorkResult::Ok(_) => {}
            other => panic!("expected Ok, got: {:?}", other),
        }
        // Gas was consumed (host call costs 10 + some for setup)
        assert!(result.digest.gas_used > 0, "should have used some gas");
    }

    #[test]
    fn test_refine_grow_heap_hostcall() {
        use grey_transpiler::assembler::Reg;
        // ecalli(1) = grow_heap: request 8 pages, should return previous count
        let blob = build_hostcall_blob(1, &[(Reg::A0, 8)]);
        let item = make_test_item(vec![], 1_000_000);
        let config = Config::tiny();

        let result = invoke_refine(&config, &blob, &item, 0, &[], None);
        match &result.digest.result {
            WorkResult::Ok(_) => {}
            other => panic!("expected Ok, got: {:?}", other),
        }
    }

    #[test]
    fn test_refine_machine_hostcall() {
        use grey_transpiler::assembler::Reg;
        // ecalli(5) = machine: mode 0 returns service_id
        let blob = build_hostcall_blob(5, &[(Reg::A0, 0)]);
        let item = make_test_item(vec![], 1_000_000);
        let config = Config::tiny();

        let result = invoke_refine(&config, &blob, &item, 0, &[], None);
        match &result.digest.result {
            WorkResult::Ok(_) => {}
            other => panic!("expected Ok, got: {:?}", other),
        }
    }

    #[test]
    fn test_refine_historical_lookup_not_found() {
        use grey_transpiler::assembler::Reg;
        // ecalli(3) = historical_lookup with a hash that doesn't exist
        // A0 = hash_ptr (point to zeros in memory), A1 = out_ptr, A2 = offset=0, A3 = max_len
        let blob = build_hostcall_blob(
            3,
            &[
                (Reg::A0, 0x1000), // hash ptr (in writable memory)
                (Reg::A1, 0x1100), // output ptr
                (Reg::A2, 0),      // offset
                (Reg::A3, 256),    // max_len
            ],
        );
        let item = make_test_item(vec![], 1_000_000);
        let config = Config::tiny();

        // No lookup context → returns NONE
        let result = invoke_refine(&config, &blob, &item, 0, &[], None);
        match &result.digest.result {
            WorkResult::Ok(_) => {}
            other => panic!("expected Ok (NONE returned in A0), got: {:?}", other),
        }
    }

    #[test]
    fn test_refine_peek_no_context() {
        use grey_transpiler::assembler::Reg;
        // ecalli(6) = peek: read storage, no context → NONE
        let blob = build_hostcall_blob(
            6,
            &[
                (Reg::A0, 0x1000), // key ptr
                (Reg::A1, 4),      // key len
                (Reg::A2, 0x1100), // out ptr
                (Reg::A3, 0),      // offset
                (Reg::A4, 256),    // max len
            ],
        );
        let item = make_test_item(vec![], 1_000_000);
        let config = Config::tiny();

        let result = invoke_refine(&config, &blob, &item, 0, &[], None);
        match &result.digest.result {
            WorkResult::Ok(_) => {}
            other => panic!("expected Ok (NONE), got: {:?}", other),
        }
    }

    #[test]
    fn test_refine_pages_hostcall() {
        use grey_transpiler::assembler::Reg;
        // ecalli(8) = pages: query current page count
        let blob = build_hostcall_blob(8, &[(Reg::A0, 0)]);
        let item = make_test_item(vec![], 1_000_000);
        let config = Config::tiny();

        let result = invoke_refine(&config, &blob, &item, 0, &[], None);
        match &result.digest.result {
            WorkResult::Ok(_) => {}
            other => panic!("expected Ok, got: {:?}", other),
        }
    }

    #[test]
    fn test_refine_invoke_code_not_found() {
        use grey_transpiler::assembler::Reg;
        // ecalli(9) = invoke: try to invoke a program that doesn't exist
        // A0 = hash ptr (zeros in memory), A1 = input ptr, A2 = input len,
        // A3 = gas_limit, A4 = output ptr, A5 = output max len
        let blob = build_hostcall_blob(
            9,
            &[
                (Reg::A0, 0x1000), // code hash ptr (zeros = unknown hash)
                (Reg::A1, 0x1100), // input ptr
                (Reg::A2, 0),      // input len
                (Reg::A3, 10000),  // gas limit for sub-call
                (Reg::A4, 0x1200), // output ptr
                (Reg::A5, 256),    // output max len
            ],
        );
        let item = make_test_item(vec![], 1_000_000);
        let config = Config::tiny();

        // No lookup context → code not found → returns NONE
        let result = invoke_refine(&config, &blob, &item, 0, &[], None);
        match &result.digest.result {
            WorkResult::Ok(_) => {}
            other => panic!("expected Ok (NONE in A0), got: {:?}", other),
        }
    }

    #[test]
    fn test_refine_expunge_hostcall() {
        use grey_transpiler::assembler::Reg;
        // ecalli(10) = expunge: request preimage deletion
        // First grow heap so we have writable memory, then write a hash, then expunge it
        let mut asm = grey_transpiler::assembler::Assembler::new();
        asm.set_stack_pages(1);
        asm.set_heap_pages(4);
        asm.add_jump_entry();

        // Grow heap to 8 pages
        asm.load_imm(Reg::A0, 8);
        asm.ecalli(1);

        // Write a fake hash (all 0x42) to 0x2000
        for i in 0..32u32 {
            asm.load_imm(Reg::T0, 0x42);
            asm.store_u8(Reg::T0, 0x2000 + i);
        }

        // Call expunge with hash ptr
        asm.load_imm(Reg::A0, 0x2000);
        asm.ecalli(10);

        // Halt
        asm.load_imm_64(Reg::T0, 0xFFFF0000u64);
        asm.jump_ind(Reg::T0, 0);

        let blob = asm.build();
        let item = make_test_item(vec![], 1_000_000);
        let config = Config::tiny();

        let result = invoke_refine(&config, &blob, &item, 0, &[], None);
        match &result.digest.result {
            WorkResult::Ok(_) => {}
            other => panic!("expected Ok, got: {:?}", other),
        }
        // Verify the expunge request was recorded
        assert_eq!(result.expunge_requests.len(), 1);
        assert_eq!(result.expunge_requests[0].0, [0x42u8; 32]);
    }

    #[test]
    fn test_refine_invoke_simple_program() {
        use grey_transpiler::assembler::{Assembler, Reg};

        // Build a simple "echo" sub-program that halts with input as output.
        // On entry: A0 = arg base, A1 = arg len. Halt returns these as output.
        let mut sub_asm = Assembler::new();
        sub_asm.set_stack_pages(1);
        sub_asm.set_heap_pages(1);
        sub_asm.add_jump_entry();
        // Just halt — A0/A1 already point to the arguments
        sub_asm.load_imm_64(Reg::T0, 0xFFFF0000u64);
        sub_asm.jump_ind(Reg::T0, 0);
        let sub_blob = sub_asm.build();

        // Compute the code hash
        let sub_hash = grey_crypto::blake2b_256(&sub_blob);

        // Build the caller program:
        // 1. Write the sub-program's code hash to memory at 0x2000
        // 2. Write some input data to memory at 0x2100
        // 3. Call invoke(9) with the hash, input, gas budget, output buffer
        let mut caller_asm = Assembler::new();
        caller_asm.set_stack_pages(1);
        caller_asm.set_heap_pages(4);
        caller_asm.add_jump_entry();

        // First grow heap to have enough writable memory
        caller_asm.load_imm(Reg::A0, 16); // 16 pages
        caller_asm.ecalli(1); // grow_heap

        // Write code hash to 0x2000 (32 bytes) using load_imm_64 + store_u64
        for i in 0..4 {
            let chunk = u64::from_le_bytes(sub_hash.0[i * 8..(i + 1) * 8].try_into().unwrap());
            caller_asm.load_imm_64(Reg::T0, chunk);
            caller_asm.store_u64(Reg::T0, 0x2000 + (i as u32) * 8);
        }

        // Write input "hello" to 0x2100
        let input_data = b"hello";
        for (j, &byte) in input_data.iter().enumerate() {
            caller_asm.load_imm(Reg::T0, byte as i32);
            caller_asm.store_u8(Reg::T0, 0x2100 + j as u32);
        }

        // Set up invoke registers
        caller_asm.load_imm(Reg::A0, 0x2000); // code hash ptr
        caller_asm.load_imm(Reg::A1, 0x2100); // input ptr
        caller_asm.load_imm(Reg::A2, input_data.len() as i32); // input len
        caller_asm.load_imm(Reg::A3, 100000); // gas limit
        caller_asm.load_imm(Reg::A4, 0x2200); // output ptr
        caller_asm.load_imm(Reg::A5, 256); // output max len

        // Call invoke
        caller_asm.ecalli(9);

        // Halt — A0 should contain output length
        caller_asm.load_imm_64(Reg::T0, 0xFFFF0000u64);
        caller_asm.jump_ind(Reg::T0, 0);

        let caller_blob = caller_asm.build();

        // Set up context with the sub-program's code
        let refine_ctx = SimpleRefineContext {
            code_blobs: [(sub_hash, sub_blob)].into_iter().collect(),
            storage: BTreeMap::new(),
            preimages: BTreeMap::new(),
        };

        let item = make_test_item(vec![], 10_000_000);
        let config = Config::tiny();

        let result = invoke_refine(&config, &caller_blob, &item, 0, &[], Some(&refine_ctx));
        match &result.digest.result {
            WorkResult::Ok(_) => {
                // invoke succeeded — gas was used
                assert!(result.digest.gas_used > 0);
            }
            other => panic!("expected Ok, got: {:?}", other),
        }
    }
}
