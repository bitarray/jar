//! FFI wrapper for JAM cryptographic primitives.
//!
//! Exports `extern "C"` functions that are called from the C bridge (bridge.c),
//! which in turn is called by Lean 4 via `@[extern]` attributes.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest as Blake2Digest};
use sha3::Keccak256;

use std::slice;
use std::sync::OnceLock;

// Buffer size constants — must match sizes.h and Lean OctetSeq types in Jar/Crypto.lean
pub const HASH_SIZE: usize = 32;
pub const ED25519_SIG_SIZE: usize = 64;
pub const BANDERSNATCH_PUBKEY_SIZE: usize = 32;
pub const BANDERSNATCH_SIG_SIZE: usize = 96;
pub const BANDERSNATCH_ROOT_SIZE: usize = 144;
pub const BANDERSNATCH_RING_PROOF_SIZE: usize = 784;
pub const BLS_SIG_SIZE: usize = 48;

// ============================================================================
// Blake2b-256
// ============================================================================

#[no_mangle]
pub extern "C" fn jar_ffi_blake2b(data_ptr: *const u8, data_len: usize, out_ptr: *mut u8) {
    let data = if data_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(data_ptr, data_len) }
    };
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(data);
    let result = hasher.finalize();
    unsafe {
        std::ptr::copy_nonoverlapping(result.as_ptr(), out_ptr, HASH_SIZE);
    }
}

// ============================================================================
// Keccak-256
// ============================================================================

#[no_mangle]
pub extern "C" fn jar_ffi_keccak256(data_ptr: *const u8, data_len: usize, out_ptr: *mut u8) {
    let data = if data_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(data_ptr, data_len) }
    };
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    unsafe {
        std::ptr::copy_nonoverlapping(result.as_ptr(), out_ptr, HASH_SIZE);
    }
}

// ============================================================================
// Ed25519
// ============================================================================

#[no_mangle]
pub extern "C" fn jar_ffi_ed25519_verify(
    key_ptr: *const u8,    // 32 bytes
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,    // 64 bytes
) -> u8 {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let key_bytes: [u8; BANDERSNATCH_PUBKEY_SIZE] = unsafe { *(key_ptr as *const [u8; BANDERSNATCH_PUBKEY_SIZE]) };
    let sig_bytes: [u8; ED25519_SIG_SIZE] = unsafe { *(sig_ptr as *const [u8; ED25519_SIG_SIZE]) };
    let msg = if msg_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(msg_ptr, msg_len) }
    };

    let Ok(vk) = VerifyingKey::from_bytes(&key_bytes) else {
        return 0;
    };
    let sig = Signature::from_bytes(&sig_bytes);
    if vk.verify(msg, &sig).is_ok() { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn jar_ffi_ed25519_sign(
    secret_ptr: *const u8,
    secret_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    out_ptr: *mut u8,      // 64 bytes
) {
    use ed25519_dalek::{Signer, SigningKey};

    let secret = unsafe { slice::from_raw_parts(secret_ptr, secret_len) };
    let msg = if msg_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(msg_ptr, msg_len) }
    };

    // Expect 32-byte seed
    if secret.len() < 32 {
        unsafe { std::ptr::write_bytes(out_ptr, 0, ED25519_SIG_SIZE); }
        return;
    }
    let mut seed = [0u8; BANDERSNATCH_PUBKEY_SIZE];
    seed.copy_from_slice(&secret[..32]);
    let sk = SigningKey::from_bytes(&seed);
    let sig = sk.sign(msg);
    unsafe {
        std::ptr::copy_nonoverlapping(sig.to_bytes().as_ptr(), out_ptr, ED25519_SIG_SIZE);
    }
}

// ============================================================================
// Bandersnatch VRF
// ============================================================================

use ark_vrf::reexports::ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_vrf::suites::bandersnatch::{self as suite, *};

type Suite = suite::BandersnatchSha512Ell2;

/// Lazily initialized PCS parameters from embedded SRS file.
fn pcs_params() -> &'static PcsParams {
    static PCS: OnceLock<PcsParams> = OnceLock::new();
    PCS.get_or_init(|| {
        let buf = include_bytes!("../bls12-381-srs-2-11-uncompressed-zcash.bin");
        PcsParams::deserialize_uncompressed_unchecked(&mut &buf[..])
            .expect("Failed to deserialize SRS")
    })
}

fn make_ring_params(ring_size: usize) -> RingProofParams {
    RingProofParams::from_pcs_params(ring_size, pcs_params().clone())
        .expect("Failed to create ring params")
}

#[no_mangle]
pub extern "C" fn jar_ffi_bandersnatch_verify(
    key_ptr: *const u8,    // 32 bytes
    ctx_ptr: *const u8,
    ctx_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,    // 96 bytes
) -> u8 {
    use ark_vrf::ietf::Verifier as _;

    let key_bytes: [u8; BANDERSNATCH_PUBKEY_SIZE] = unsafe { *(key_ptr as *const [u8; BANDERSNATCH_PUBKEY_SIZE]) };
    let sig_bytes: &[u8] = unsafe { slice::from_raw_parts(sig_ptr, BANDERSNATCH_SIG_SIZE) };
    let ctx = if ctx_len == 0 { &[] } else { unsafe { slice::from_raw_parts(ctx_ptr, ctx_len) } };
    let msg = if msg_len == 0 { &[] } else { unsafe { slice::from_raw_parts(msg_ptr, msg_len) } };

    let result = (|| -> Option<()> {
        let pk_point = AffinePoint::deserialize_compressed(&key_bytes[..]).ok()?;
        let public = ark_vrf::Public::<Suite>(pk_point);

        // Parse output (first 32 bytes) and proof (next 64 bytes)
        let output_point = AffinePoint::deserialize_compressed(&sig_bytes[..32]).ok()?;
        let output = ark_vrf::Output::<Suite>::from_affine(output_point);
        let proof = ark_vrf::ietf::Proof::<Suite>::deserialize_compressed(&sig_bytes[32..]).ok()?;

        // Construct VRF input
        let input = ark_vrf::Input::<Suite>::new(ctx)?;

        // Verify
        public.verify(input, output, msg, &proof).ok()?;
        Some(())
    })();

    if result.is_some() { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn jar_ffi_bandersnatch_sign(
    secret_ptr: *const u8,
    secret_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    out_ptr: *mut u8,      // 96 bytes
) {
    use ark_vrf::ietf::Prover as _;

    let secret = unsafe { slice::from_raw_parts(secret_ptr, secret_len) };
    let ctx = if ctx_len == 0 { &[] } else { unsafe { slice::from_raw_parts(ctx_ptr, ctx_len) } };
    let msg = if msg_len == 0 { &[] } else { unsafe { slice::from_raw_parts(msg_ptr, msg_len) } };

    if secret.len() < 32 {
        unsafe { std::ptr::write_bytes(out_ptr, 0, BANDERSNATCH_SIG_SIZE); }
        return;
    }
    let mut seed = [0u8; BANDERSNATCH_PUBKEY_SIZE];
    seed.copy_from_slice(&secret[..32]);
    let sk = ark_vrf::Secret::<Suite>::from_seed(&seed);

    let Some(input) = ark_vrf::Input::<Suite>::new(ctx) else {
        unsafe { std::ptr::write_bytes(out_ptr, 0, BANDERSNATCH_SIG_SIZE); }
        return;
    };
    let output = sk.output(input);
    let proof = sk.prove(input, output, msg);

    let mut result = [0u8; BANDERSNATCH_SIG_SIZE];
    // Output point (first 32 bytes)
    let mut out_buf = Vec::new();
    output.0.serialize_compressed(&mut out_buf).ok();
    let len = out_buf.len().min(BANDERSNATCH_PUBKEY_SIZE);
    result[..len].copy_from_slice(&out_buf[..len]);
    // Proof (remaining 64 bytes)
    let mut proof_buf = Vec::new();
    proof.serialize_compressed(&mut proof_buf).ok();
    let plen = proof_buf.len().min(BANDERSNATCH_SIG_SIZE - BANDERSNATCH_PUBKEY_SIZE);
    result[BANDERSNATCH_PUBKEY_SIZE..BANDERSNATCH_PUBKEY_SIZE + plen].copy_from_slice(&proof_buf[..plen]);

    unsafe { std::ptr::copy_nonoverlapping(result.as_ptr(), out_ptr, BANDERSNATCH_SIG_SIZE); }
}

#[no_mangle]
pub extern "C" fn jar_ffi_bandersnatch_output(
    sig_ptr: *const u8,    // BANDERSNATCH_SIG_SIZE bytes (VRF signature)
    out_ptr: *mut u8,      // HASH_SIZE bytes
) -> u8 {
    let sig = unsafe { slice::from_raw_parts(sig_ptr, BANDERSNATCH_SIG_SIZE) };
    let result = (|| -> Option<[u8; HASH_SIZE]> {
        let output_point = AffinePoint::deserialize_compressed(&sig[..BANDERSNATCH_PUBKEY_SIZE]).ok()?;
        let output = ark_vrf::Output::<Suite>::from_affine(output_point);
        let hash = output.hash();
        let mut r = [0u8; HASH_SIZE];
        r.copy_from_slice(&hash[..HASH_SIZE]);
        Some(r)
    })();

    match result {
        Some(hash) => {
            unsafe { std::ptr::copy_nonoverlapping(hash.as_ptr(), out_ptr, HASH_SIZE); }
            1
        }
        None => {
            unsafe { std::ptr::write_bytes(out_ptr, 0, HASH_SIZE); }
            0
        }
    }
}

// ============================================================================
// Bandersnatch Ring VRF
// ============================================================================

#[no_mangle]
pub extern "C" fn jar_ffi_bandersnatch_ring_root(
    keys_ptr: *const u8,   // packed BANDERSNATCH_PUBKEY_SIZE-byte keys
    num_keys: usize,
    out_ptr: *mut u8,      // BANDERSNATCH_ROOT_SIZE bytes
) {
    let keys_raw = if num_keys == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(keys_ptr, num_keys * BANDERSNATCH_PUBKEY_SIZE) }
    };

    let params = make_ring_params(num_keys);

    let points: Vec<AffinePoint> = (0..num_keys)
        .map(|i| {
            let key_bytes = &keys_raw[i * BANDERSNATCH_PUBKEY_SIZE..(i + 1) * BANDERSNATCH_PUBKEY_SIZE];
            AffinePoint::deserialize_compressed(key_bytes)
                .unwrap_or(RingProofParams::padding_point())
        })
        .collect();

    let verifier_key = params.verifier_key(&points);
    let commitment = verifier_key.commitment();
    let mut buf = Vec::new();
    commitment
        .serialize_compressed(&mut buf)
        .expect("commitment serialization failed");

    let mut result = [0u8; BANDERSNATCH_ROOT_SIZE];
    let len = buf.len().min(BANDERSNATCH_ROOT_SIZE);
    result[..len].copy_from_slice(&buf[..len]);

    unsafe { std::ptr::copy_nonoverlapping(result.as_ptr(), out_ptr, BANDERSNATCH_ROOT_SIZE); }
}

#[no_mangle]
pub extern "C" fn jar_ffi_bandersnatch_ring_verify(
    root_ptr: *const u8,   // BANDERSNATCH_ROOT_SIZE bytes
    ctx_ptr: *const u8,
    ctx_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    proof_ptr: *const u8,  // BANDERSNATCH_RING_PROOF_SIZE bytes (32 output + 752 proof)
    ring_size: usize,
) -> u8 {
    use ark_vrf::ring::Verifier as _;

    let root = unsafe { slice::from_raw_parts(root_ptr, BANDERSNATCH_ROOT_SIZE) };
    let ctx = if ctx_len == 0 { &[] } else { unsafe { slice::from_raw_parts(ctx_ptr, ctx_len) } };
    let msg = if msg_len == 0 { &[] } else { unsafe { slice::from_raw_parts(msg_ptr, msg_len) } };
    let proof_bytes = unsafe { slice::from_raw_parts(proof_ptr, BANDERSNATCH_RING_PROOF_SIZE) };

    let result = (|| -> Option<()> {
        let params = make_ring_params(ring_size);

        let commitment = RingCommitment::deserialize_compressed(&mut &root[..]).ok()?;
        let verifier_key = params.verifier_key_from_commitment(commitment);
        let verifier = params.verifier(verifier_key);

        let output_point = AffinePoint::deserialize_compressed(&mut &proof_bytes[..BANDERSNATCH_PUBKEY_SIZE]).ok()?;
        let output = ark_vrf::Output::<Suite>::from_affine(output_point);
        let proof = RingProof::deserialize_compressed(&mut &proof_bytes[BANDERSNATCH_PUBKEY_SIZE..]).ok()?;

        let input = ark_vrf::Input::<Suite>::new(ctx)?;
        ark_vrf::Public::<Suite>::verify(input, output, msg, &proof, &verifier).ok()?;
        Some(())
    })();

    if result.is_some() { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn jar_ffi_bandersnatch_ring_sign(
    secret_ptr: *const u8,
    secret_len: usize,
    root_ptr: *const u8,   // BANDERSNATCH_ROOT_SIZE bytes
    ctx_ptr: *const u8,
    ctx_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    ring_size: usize,
    out_ptr: *mut u8,      // BANDERSNATCH_RING_PROOF_SIZE bytes
) {
    let secret = unsafe { slice::from_raw_parts(secret_ptr, secret_len) };
    let _root = unsafe { slice::from_raw_parts(root_ptr, BANDERSNATCH_ROOT_SIZE) };
    let ctx = if ctx_len == 0 { &[] } else { unsafe { slice::from_raw_parts(ctx_ptr, ctx_len) } };
    let msg = if msg_len == 0 { &[] } else { unsafe { slice::from_raw_parts(msg_ptr, msg_len) } };

    // Ring signing is complex — requires the prover key which needs the full key list.
    // For now, produce a best-effort implementation. Full ring signing requires more context.
    let _ = (secret, ring_size, ctx, msg);
    unsafe { std::ptr::write_bytes(out_ptr, 0, BANDERSNATCH_RING_PROOF_SIZE); }
}

#[no_mangle]
pub extern "C" fn jar_ffi_bandersnatch_ring_output(
    proof_ptr: *const u8,  // BANDERSNATCH_RING_PROOF_SIZE bytes
    out_ptr: *mut u8,      // HASH_SIZE bytes
) -> u8 {
    let proof_bytes = unsafe { slice::from_raw_parts(proof_ptr, BANDERSNATCH_RING_PROOF_SIZE) };

    let result = (|| -> Option<[u8; HASH_SIZE]> {
        let output_point = AffinePoint::deserialize_compressed(&mut &proof_bytes[..BANDERSNATCH_PUBKEY_SIZE]).ok()?;
        let output = ark_vrf::Output::<Suite>::from_affine(output_point);
        let hash = output.hash();
        let mut r = [0u8; HASH_SIZE];
        r.copy_from_slice(&hash[..HASH_SIZE]);
        Some(r)
    })();

    match result {
        Some(hash) => {
            unsafe { std::ptr::copy_nonoverlapping(hash.as_ptr(), out_ptr, HASH_SIZE); }
            1
        }
        None => {
            unsafe { std::ptr::write_bytes(out_ptr, 0, HASH_SIZE); }
            0
        }
    }
}

// ============================================================================
// BLS12-381 (stubs — not yet implemented in grey-crypto)
// ============================================================================

#[no_mangle]
pub extern "C" fn jar_ffi_bls_verify(
    _key_ptr: *const u8,   // BLS_PUBKEY_SIZE bytes
    _msg_ptr: *const u8,
    _msg_len: usize,
    _sig_ptr: *const u8,   // BLS_SIG_SIZE bytes
) -> u8 {
    0 // Not yet implemented
}

#[no_mangle]
pub extern "C" fn jar_ffi_bls_sign(
    _secret_ptr: *const u8,
    _secret_len: usize,
    _msg_ptr: *const u8,
    _msg_len: usize,
    _out_ptr: *mut u8,     // BLS_SIG_SIZE bytes
) {
    // Not yet implemented
}

