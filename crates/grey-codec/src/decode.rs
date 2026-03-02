//! Decoding functions (Appendix C of the Gray Paper).

use crate::error::CodecError;
use grey_types::config::Config;

/// Trait for types that can be decoded from the JAM wire format.
pub trait Decode: Sized {
    /// Decode a value from the given byte slice, returning the value
    /// and the number of bytes consumed.
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError>;
}

/// Trait for types whose decoding depends on protocol configuration (V, C, E).
///
/// Some JAM types have fixed-size arrays whose lengths depend on protocol
/// parameters (e.g., EpochMarker has V validator entries, Assurance has
/// ceil(C/8) bitfield bytes). This trait provides config-aware decoding.
pub trait DecodeWithConfig: Sized {
    fn decode_with_config(data: &[u8], config: &Config) -> Result<(Self, usize), CodecError>;
}

/// Decode a JAM compact/variable-length natural number (inverse of encode_natural/encode_compact).
///
/// JAM prefix-length encoding: leading 1-bits of the first byte indicate
/// the number of additional bytes. The first byte also carries high bits
/// of the value; remaining bytes are little-endian.
///
/// Returns `(value, bytes_consumed)`.
pub fn decode_natural(data: &[u8]) -> Result<(usize, usize), CodecError> {
    let (val, consumed) = decode_compact(data)?;
    Ok((val as usize, consumed))
}

/// Decode a JAM compact-encoded u64 value.
///
/// Returns `(value, bytes_consumed)`.
pub fn decode_compact(data: &[u8]) -> Result<(u64, usize), CodecError> {
    ensure_bytes(data, 1)?;
    let header = data[0];
    let len = header.leading_ones() as usize; // 0..=8

    if len == 8 {
        // 0xFF: read next 8 bytes as u64 LE
        ensure_bytes(data, 9)?;
        let value = u64::from_le_bytes(data[1..9].try_into().unwrap());
        return Ok((value, 9));
    }

    ensure_bytes(data, 1 + len)?;

    // Threshold: the minimum header value for this length class
    let threshold: u64 = if len == 0 {
        0
    } else {
        256 - (1u64 << (8 - len))
    };

    // High bits from header byte
    let header_value = (header as u64) - threshold;

    // Low bits from remaining bytes (little-endian)
    let mut low: u64 = 0;
    for i in 0..len {
        low |= (data[1 + i] as u64) << (8 * i);
    }

    let value = (header_value << (8 * len)) | low;
    Ok((value, 1 + len))
}

fn ensure_bytes(data: &[u8], needed: usize) -> Result<(), CodecError> {
    if data.len() < needed {
        Err(CodecError::UnexpectedEof {
            needed,
            available: data.len(),
        })
    } else {
        Ok(())
    }
}

// --- Primitive type decoders ---

impl Decode for u8 {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        ensure_bytes(data, 1)?;
        Ok((data[0], 1))
    }
}

impl Decode for u16 {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        ensure_bytes(data, 2)?;
        Ok((u16::from_le_bytes([data[0], data[1]]), 2))
    }
}

impl Decode for u32 {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        ensure_bytes(data, 4)?;
        Ok((
            u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            4,
        ))
    }
}

impl Decode for u64 {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        ensure_bytes(data, 8)?;
        Ok((
            u64::from_le_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]),
            8,
        ))
    }
}

impl Decode for bool {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        ensure_bytes(data, 1)?;
        match data[0] {
            0 => Ok((false, 1)),
            1 => Ok((true, 1)),
            d => Err(CodecError::InvalidDiscriminator(d)),
        }
    }
}

// --- Fixed-size cryptographic type decoders ---

impl Decode for grey_types::Hash {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        ensure_bytes(data, 32)?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&data[..32]);
        Ok((grey_types::Hash(bytes), 32))
    }
}

impl Decode for grey_types::Ed25519PublicKey {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        ensure_bytes(data, 32)?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&data[..32]);
        Ok((grey_types::Ed25519PublicKey(bytes), 32))
    }
}

impl Decode for grey_types::BandersnatchPublicKey {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        ensure_bytes(data, 32)?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&data[..32]);
        Ok((grey_types::BandersnatchPublicKey(bytes), 32))
    }
}

impl Decode for grey_types::BandersnatchSignature {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        ensure_bytes(data, 96)?;
        let mut bytes = [0u8; 96];
        bytes.copy_from_slice(&data[..96]);
        Ok((grey_types::BandersnatchSignature(bytes), 96))
    }
}

impl Decode for grey_types::Ed25519Signature {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        ensure_bytes(data, 64)?;
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&data[..64]);
        Ok((grey_types::Ed25519Signature(bytes), 64))
    }
}

impl Decode for grey_types::BlsPublicKey {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        ensure_bytes(data, 144)?;
        let mut bytes = [0u8; 144];
        bytes.copy_from_slice(&data[..144]);
        Ok((grey_types::BlsPublicKey(bytes), 144))
    }
}

impl Decode for grey_types::BandersnatchRingRoot {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        ensure_bytes(data, 144)?;
        let mut bytes = [0u8; 144];
        bytes.copy_from_slice(&data[..144]);
        Ok((grey_types::BandersnatchRingRoot(bytes), 144))
    }
}

// --- Generic container decoders ---

/// Decode a variable-length sequence with length prefix (eq C.1-C.4).
impl<T: Decode> Decode for Vec<T> {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        let (len, mut offset) = decode_natural(data)?;
        let mut items = Vec::with_capacity(len);
        for _ in 0..len {
            let (item, consumed) = T::decode(&data[offset..])?;
            items.push(item);
            offset += consumed;
        }
        Ok((items, offset))
    }
}

/// Decode an optional value with a discriminator byte (eq C.5-C.7).
impl<T: Decode> Decode for Option<T> {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        ensure_bytes(data, 1)?;
        match data[0] {
            0 => Ok((None, 1)),
            1 => {
                let (val, consumed) = T::decode(&data[1..])?;
                Ok((Some(val), 1 + consumed))
            }
            d => Err(CodecError::InvalidDiscriminator(d)),
        }
    }
}

/// Decode a tuple of two decodable types (concatenation).
impl<A: Decode, B: Decode> Decode for (A, B) {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        let (a, offset_a) = A::decode(data)?;
        let (b, offset_b) = B::decode(&data[offset_a..])?;
        Ok(((a, b), offset_a + offset_b))
    }
}

/// Decode a BTreeMap as a sorted sequence of key-value pairs (eq C.10).
impl<K: Decode + Ord, V: Decode> Decode for std::collections::BTreeMap<K, V> {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        let (len, mut offset) = decode_natural(data)?;
        let mut map = std::collections::BTreeMap::new();
        for _ in 0..len {
            let (k, kc) = K::decode(&data[offset..])?;
            offset += kc;
            let (v, vc) = V::decode(&data[offset..])?;
            offset += vc;
            map.insert(k, v);
        }
        Ok((map, offset))
    }
}

// --- Protocol type decoders (Appendix C) ---

use grey_types::header::*;
use grey_types::work::*;

impl Decode for RefinementContext {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        let mut off = 0;
        let (anchor, c) = grey_types::Hash::decode(&data[off..])?; off += c;
        let (state_root, c) = grey_types::Hash::decode(&data[off..])?; off += c;
        let (beefy_root, c) = grey_types::Hash::decode(&data[off..])?; off += c;
        let (lookup_anchor, c) = grey_types::Hash::decode(&data[off..])?; off += c;
        let (lookup_anchor_timeslot, c) = u32::decode(&data[off..])?; off += c;
        let (prerequisites, c) = Vec::<grey_types::Hash>::decode(&data[off..])?; off += c;
        Ok((RefinementContext {
            anchor, state_root, beefy_root, lookup_anchor,
            lookup_anchor_timeslot, prerequisites,
        }, off))
    }
}

impl Decode for WorkResult {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        ensure_bytes(data, 1)?;
        match data[0] {
            0 => {
                let (payload, c) = Vec::<u8>::decode(&data[1..])?;
                Ok((WorkResult::Ok(payload), 1 + c))
            }
            1 => Ok((WorkResult::OutOfGas, 1)),
            2 => Ok((WorkResult::Panic, 1)),
            3 => Ok((WorkResult::BadExports, 1)),
            4 => Ok((WorkResult::BadCode, 1)),
            5 => Ok((WorkResult::CodeOversize, 1)),
            d => Err(CodecError::InvalidDiscriminator(d)),
        }
    }
}

impl Decode for WorkDigest {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        let mut off = 0;
        let (service_id, c) = u32::decode(&data[off..])?; off += c;
        let (code_hash, c) = grey_types::Hash::decode(&data[off..])?; off += c;
        let (payload_hash, c) = grey_types::Hash::decode(&data[off..])?; off += c;
        let (accumulate_gas, c) = u64::decode(&data[off..])?; off += c;
        let (result, c) = WorkResult::decode(&data[off..])?; off += c;
        // RefineLoad fields use compact encoding
        let (gas_used, c) = decode_compact(&data[off..])?; off += c;
        let (imports_count, c) = decode_compact(&data[off..])?; off += c;
        let (extrinsics_count, c) = decode_compact(&data[off..])?; off += c;
        let (extrinsics_size, c) = decode_compact(&data[off..])?; off += c;
        let (exports_count, c) = decode_compact(&data[off..])?; off += c;
        Ok((WorkDigest {
            service_id, code_hash, payload_hash, accumulate_gas, result,
            gas_used, imports_count: imports_count as u16,
            extrinsics_count: extrinsics_count as u16,
            extrinsics_size: extrinsics_size as u32,
            exports_count: exports_count as u16,
        }, off))
    }
}

impl Decode for ImportSegment {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        let (hash, c1) = grey_types::Hash::decode(data)?;
        let (index, c2) = u16::decode(&data[c1..])?;
        Ok((ImportSegment { hash, index }, c1 + c2))
    }
}

impl Decode for WorkItem {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        let mut off = 0;
        let (service_id, c) = u32::decode(&data[off..])?; off += c;
        let (code_hash, c) = grey_types::Hash::decode(&data[off..])?; off += c;
        let (gas_limit, c) = u64::decode(&data[off..])?; off += c;
        let (accumulate_gas_limit, c) = u64::decode(&data[off..])?; off += c;
        let (exports_count, c) = u16::decode(&data[off..])?; off += c;
        let (payload, c) = Vec::<u8>::decode(&data[off..])?; off += c;
        let (imports, c) = Vec::<ImportSegment>::decode(&data[off..])?; off += c;
        let (extrinsics, c) = Vec::<(grey_types::Hash, u32)>::decode(&data[off..])?; off += c;
        Ok((WorkItem {
            service_id, code_hash, gas_limit, accumulate_gas_limit,
            exports_count, payload, imports, extrinsics,
        }, off))
    }
}

impl Decode for AvailabilitySpec {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        let mut off = 0;
        let (package_hash, c) = grey_types::Hash::decode(&data[off..])?; off += c;
        let (bundle_length, c) = u32::decode(&data[off..])?; off += c;
        let (erasure_root, c) = grey_types::Hash::decode(&data[off..])?; off += c;
        let (exports_root, c) = grey_types::Hash::decode(&data[off..])?; off += c;
        let (exports_count, c) = u16::decode(&data[off..])?; off += c;
        Ok((AvailabilitySpec {
            package_hash, bundle_length, erasure_root, exports_root, exports_count,
        }, off))
    }
}

impl Decode for WorkReport {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        let mut off = 0;
        let (package_spec, c) = AvailabilitySpec::decode(&data[off..])?; off += c;
        let (context, c) = RefinementContext::decode(&data[off..])?; off += c;
        // core_index uses compact encoding
        let (core_index_val, c) = decode_compact(&data[off..])?; off += c;
        let (authorizer_hash, c) = grey_types::Hash::decode(&data[off..])?; off += c;
        // auth_gas_used uses compact encoding
        let (auth_gas_used, c) = decode_compact(&data[off..])?; off += c;
        let (auth_output, c) = Vec::<u8>::decode(&data[off..])?; off += c;
        let (segment_root_lookup, c) = std::collections::BTreeMap::<grey_types::Hash, grey_types::Hash>::decode(&data[off..])?; off += c;
        let (results, c) = Vec::<WorkDigest>::decode(&data[off..])?; off += c;
        Ok((WorkReport {
            package_spec, context,
            core_index: core_index_val as u16,
            authorizer_hash, auth_gas_used, auth_output,
            segment_root_lookup, results,
        }, off))
    }
}

impl Decode for WorkPackage {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        let mut off = 0;
        let (auth_code_host, c) = u32::decode(&data[off..])?; off += c;
        let (auth_code_hash, c) = grey_types::Hash::decode(&data[off..])?; off += c;
        let (context, c) = RefinementContext::decode(&data[off..])?; off += c;
        let (authorization, c) = Vec::<u8>::decode(&data[off..])?; off += c;
        let (authorizer_config, c) = Vec::<u8>::decode(&data[off..])?; off += c;
        let (items, c) = Vec::<WorkItem>::decode(&data[off..])?; off += c;
        Ok((WorkPackage {
            auth_code_host, auth_code_hash, context,
            authorization, authorizer_config, items,
        }, off))
    }
}

impl Decode for Ticket {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        let (id, c1) = grey_types::Hash::decode(data)?;
        let (attempt, c2) = u8::decode(&data[c1..])?;
        Ok((Ticket { id, attempt }, c1 + c2))
    }
}

/// TicketProof: attempt (u8) + fixed-size 784-byte Ring VRF proof.
impl Decode for TicketProof {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        let (attempt, c1) = u8::decode(data)?;
        ensure_bytes(&data[c1..], 784)?;
        let proof = data[c1..c1 + 784].to_vec();
        Ok((TicketProof { attempt, proof }, c1 + 784))
    }
}

impl Decode for Judgment {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        let mut off = 0;
        let (is_valid, c) = bool::decode(&data[off..])?; off += c;
        let (validator_index, c) = u16::decode(&data[off..])?; off += c;
        let (signature, c) = grey_types::Ed25519Signature::decode(&data[off..])?; off += c;
        Ok((Judgment { is_valid, validator_index, signature }, off))
    }
}

impl Decode for Culprit {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        let mut off = 0;
        let (report_hash, c) = grey_types::Hash::decode(&data[off..])?; off += c;
        let (validator_key, c) = grey_types::Ed25519PublicKey::decode(&data[off..])?; off += c;
        let (signature, c) = grey_types::Ed25519Signature::decode(&data[off..])?; off += c;
        Ok((Culprit { report_hash, validator_key, signature }, off))
    }
}

impl Decode for Fault {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        let mut off = 0;
        let (report_hash, c) = grey_types::Hash::decode(&data[off..])?; off += c;
        let (is_valid, c) = bool::decode(&data[off..])?; off += c;
        let (validator_key, c) = grey_types::Ed25519PublicKey::decode(&data[off..])?; off += c;
        let (signature, c) = grey_types::Ed25519Signature::decode(&data[off..])?; off += c;
        Ok((Fault { report_hash, is_valid, validator_key, signature }, off))
    }
}

// --- Config-dependent decoders ---

/// Verdict: report_hash + age + fixed-size judgments (super_majority count, no length prefix).
impl DecodeWithConfig for Verdict {
    fn decode_with_config(data: &[u8], config: &Config) -> Result<(Self, usize), CodecError> {
        let mut off = 0;
        let (report_hash, c) = grey_types::Hash::decode(&data[off..])?; off += c;
        let (age, c) = u32::decode(&data[off..])?; off += c;
        // Fixed-size: super_majority judgments, no length prefix
        let count = config.super_majority() as usize;
        let mut judgments = Vec::with_capacity(count);
        for _ in 0..count {
            let (j, c) = Judgment::decode(&data[off..])?;
            off += c;
            judgments.push(j);
        }
        Ok((Verdict { report_hash, age, judgments }, off))
    }
}

/// DisputesExtrinsic: verdicts (Vec) + culprits (Vec) + faults (Vec).
/// Verdicts need config-aware decoding.
impl DecodeWithConfig for DisputesExtrinsic {
    fn decode_with_config(data: &[u8], config: &Config) -> Result<(Self, usize), CodecError> {
        let mut off = 0;
        // Verdicts: length-prefixed, each verdict needs config
        let (verdict_count, c) = decode_natural(&data[off..])?; off += c;
        let mut verdicts = Vec::with_capacity(verdict_count);
        for _ in 0..verdict_count {
            let (v, c) = Verdict::decode_with_config(&data[off..], config)?;
            off += c;
            verdicts.push(v);
        }
        let (culprits, c) = Vec::<Culprit>::decode(&data[off..])?; off += c;
        let (faults, c) = Vec::<Fault>::decode(&data[off..])?; off += c;
        Ok((DisputesExtrinsic { verdicts, culprits, faults }, off))
    }
}

/// Assurance: anchor + fixed-size bitfield (ceil(C/8) bytes) + validator_index + signature.
impl DecodeWithConfig for Assurance {
    fn decode_with_config(data: &[u8], config: &Config) -> Result<(Self, usize), CodecError> {
        let mut off = 0;
        let (anchor, c) = grey_types::Hash::decode(&data[off..])?; off += c;
        // Bitfield: fixed-size, ceil(C/8) bytes, no length prefix
        let bf_len = config.avail_bitfield_bytes();
        ensure_bytes(&data[off..], bf_len)?;
        let bitfield = data[off..off + bf_len].to_vec();
        off += bf_len;
        let (validator_index, c) = u16::decode(&data[off..])?; off += c;
        let (signature, c) = grey_types::Ed25519Signature::decode(&data[off..])?; off += c;
        Ok((Assurance { anchor, bitfield, validator_index, signature }, off))
    }
}

/// Guarantee: report + timeslot + credentials (length-prefixed).
impl Decode for Guarantee {
    fn decode(data: &[u8]) -> Result<(Self, usize), CodecError> {
        let mut off = 0;
        let (report, c) = WorkReport::decode(&data[off..])?; off += c;
        let (timeslot, c) = u32::decode(&data[off..])?; off += c;
        let (credentials, c) = Vec::<(u16, grey_types::Ed25519Signature)>::decode(&data[off..])?; off += c;
        Ok((Guarantee { report, timeslot, credentials }, off))
    }
}

/// EpochMarker: entropy + entropy_previous + fixed-size validator list (V entries, no length prefix).
impl DecodeWithConfig for EpochMarker {
    fn decode_with_config(data: &[u8], config: &Config) -> Result<(Self, usize), CodecError> {
        let mut off = 0;
        let (entropy, c) = grey_types::Hash::decode(&data[off..])?; off += c;
        let (entropy_previous, c) = grey_types::Hash::decode(&data[off..])?; off += c;
        // Fixed-size: V validator (bandersnatch, ed25519) pairs, no length prefix
        let count = config.validators_count as usize;
        let mut validators = Vec::with_capacity(count);
        for _ in 0..count {
            let (bk, c) = grey_types::BandersnatchPublicKey::decode(&data[off..])?; off += c;
            let (ek, c) = grey_types::Ed25519PublicKey::decode(&data[off..])?; off += c;
            validators.push((bk, ek));
        }
        Ok((EpochMarker { entropy, entropy_previous, validators }, off))
    }
}

/// Extrinsic: tickets + preimages + guarantees + assurances + disputes.
/// Assurances and disputes need config-aware decoding.
impl DecodeWithConfig for Extrinsic {
    fn decode_with_config(data: &[u8], config: &Config) -> Result<(Self, usize), CodecError> {
        let mut off = 0;
        let (tickets, c) = Vec::<TicketProof>::decode(&data[off..])?; off += c;
        // Preimages: Vec<(ServiceId, Vec<u8>)>
        let (preimages, c) = Vec::<(u32, Vec<u8>)>::decode(&data[off..])?; off += c;
        let (guarantees, c) = Vec::<Guarantee>::decode(&data[off..])?; off += c;
        // Assurances: length-prefixed, each needs config
        let (assurance_count, c) = decode_natural(&data[off..])?; off += c;
        let mut assurances = Vec::with_capacity(assurance_count);
        for _ in 0..assurance_count {
            let (a, c) = Assurance::decode_with_config(&data[off..], config)?;
            off += c;
            assurances.push(a);
        }
        // Disputes need config
        let (disputes, c) = DisputesExtrinsic::decode_with_config(&data[off..], config)?; off += c;
        Ok((Extrinsic { tickets, preimages, guarantees, assurances, disputes }, off))
    }
}

/// Header: all fields including config-dependent optional markers.
impl DecodeWithConfig for Header {
    fn decode_with_config(data: &[u8], config: &Config) -> Result<(Self, usize), CodecError> {
        let mut off = 0;
        let (parent_hash, c) = grey_types::Hash::decode(&data[off..])?; off += c;
        let (state_root, c) = grey_types::Hash::decode(&data[off..])?; off += c;
        let (extrinsic_hash, c) = grey_types::Hash::decode(&data[off..])?; off += c;
        let (timeslot, c) = u32::decode(&data[off..])?; off += c;

        // epoch_marker: Optional, config-dependent inner
        ensure_bytes(&data[off..], 1)?;
        let epoch_marker = match data[off] {
            0 => { off += 1; None }
            1 => {
                off += 1;
                let (em, c) = EpochMarker::decode_with_config(&data[off..], config)?;
                off += c;
                Some(em)
            }
            d => return Err(CodecError::InvalidDiscriminator(d)),
        };

        // tickets_marker: Optional, fixed-size E entries (no length prefix)
        ensure_bytes(&data[off..], 1)?;
        let tickets_marker = match data[off] {
            0 => { off += 1; None }
            1 => {
                off += 1;
                let count = config.epoch_length as usize;
                let mut tickets = Vec::with_capacity(count);
                for _ in 0..count {
                    let (t, c) = Ticket::decode(&data[off..])?;
                    off += c;
                    tickets.push(t);
                }
                Some(tickets)
            }
            d => return Err(CodecError::InvalidDiscriminator(d)),
        };

        let (author_index, c) = u16::decode(&data[off..])?; off += c;
        let (vrf_signature, c) = grey_types::BandersnatchSignature::decode(&data[off..])?; off += c;
        let (offenders_marker, c) = Vec::<grey_types::Ed25519PublicKey>::decode(&data[off..])?; off += c;
        let (seal, c) = grey_types::BandersnatchSignature::decode(&data[off..])?; off += c;

        Ok((Header {
            parent_hash, state_root, extrinsic_hash, timeslot,
            epoch_marker, tickets_marker, author_index,
            vrf_signature, offenders_marker, seal,
        }, off))
    }
}

/// Block: header + extrinsic, both config-dependent.
impl DecodeWithConfig for Block {
    fn decode_with_config(data: &[u8], config: &Config) -> Result<(Self, usize), CodecError> {
        let (header, off1) = Header::decode_with_config(data, config)?;
        let (extrinsic, off2) = Extrinsic::decode_with_config(&data[off1..], config)?;
        Ok((Block { header, extrinsic }, off1 + off2))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::{encode_natural, Encode};

    #[test]
    fn test_decode_natural_roundtrip() {
        for value in [0, 1, 127, 128, 255, 300, 16384, 1_000_000] {
            let mut buf = Vec::new();
            encode_natural(value, &mut buf);
            let (decoded, consumed) = decode_natural(&buf).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn test_decode_u32_roundtrip() {
        let value: u32 = 0x12345678;
        let encoded = value.encode();
        let (decoded, consumed) = u32::decode(&encoded).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn test_decode_hash_roundtrip() {
        let hash = grey_types::Hash([0xAB; 32]);
        let encoded = Encode::encode(&hash);
        let (decoded, consumed) = grey_types::Hash::decode(&encoded).unwrap();
        assert_eq!(decoded, hash);
        assert_eq!(consumed, 32);
    }

    #[test]
    fn test_decode_bool_roundtrip() {
        let (f, c) = bool::decode(&[0]).unwrap();
        assert!(!f);
        assert_eq!(c, 1);
        let (t, c) = bool::decode(&[1]).unwrap();
        assert!(t);
        assert_eq!(c, 1);
        assert!(bool::decode(&[2]).is_err());
    }

    #[test]
    fn test_decode_vec_roundtrip() {
        let original: Vec<u32> = vec![1, 2, 3, 100, 999];
        let encoded = original.encode();
        let (decoded, consumed) = Vec::<u32>::decode(&encoded).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_decode_option_roundtrip() {
        let some: Option<u32> = Some(42);
        let none: Option<u32> = None;
        let enc_some = some.encode();
        let enc_none = none.encode();
        let (d_some, c) = Option::<u32>::decode(&enc_some).unwrap();
        assert_eq!(d_some, Some(42));
        assert_eq!(c, enc_some.len());
        let (d_none, c) = Option::<u32>::decode(&enc_none).unwrap();
        assert_eq!(d_none, None);
        assert_eq!(c, enc_none.len());
    }

    #[test]
    fn test_decode_btreemap_roundtrip() {
        let mut original = std::collections::BTreeMap::new();
        original.insert(grey_types::Hash([1; 32]), grey_types::Hash([2; 32]));
        original.insert(grey_types::Hash([3; 32]), grey_types::Hash([4; 32]));
        let encoded = original.encode();
        let (decoded, consumed) = std::collections::BTreeMap::<grey_types::Hash, grey_types::Hash>::decode(&encoded).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_decode_ticket_roundtrip() {
        let ticket = Ticket {
            id: grey_types::Hash([0xAA; 32]),
            attempt: 2,
        };
        let encoded = ticket.encode();
        let (decoded, consumed) = Ticket::decode(&encoded).unwrap();
        assert_eq!(decoded.id, ticket.id);
        assert_eq!(decoded.attempt, ticket.attempt);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_decode_refine_context_roundtrip() {
        let bin = include_bytes!("../../../res/testvectors/codec/tiny/refine_context.bin");
        let (ctx, consumed) = RefinementContext::decode(bin).unwrap();
        assert_eq!(consumed, bin.len());
        let re_encoded = ctx.encode();
        assert_eq!(&re_encoded[..], &bin[..], "re-encoded bytes mismatch");
    }

    #[test]
    fn test_decode_work_report_roundtrip() {
        let bin = include_bytes!("../../../res/testvectors/codec/tiny/work_report.bin");
        let (report, consumed) = WorkReport::decode(bin).unwrap();
        assert_eq!(consumed, bin.len());
        let re_encoded = report.encode();
        assert_eq!(&re_encoded[..], &bin[..], "re-encoded bytes mismatch");
    }

    #[test]
    fn test_decode_header_tiny_roundtrip() {
        let config = Config::tiny();
        for (name, bin) in [
            ("header_0", include_bytes!("../../../res/testvectors/codec/tiny/header_0.bin").as_slice()),
            ("header_1", include_bytes!("../../../res/testvectors/codec/tiny/header_1.bin").as_slice()),
        ] {
            let (header, consumed) = Header::decode_with_config(bin, &config).unwrap();
            assert_eq!(consumed, bin.len(), "{name}: consumed mismatch");
            let re_encoded = header.encode();
            assert_eq!(&re_encoded[..], &bin[..], "{name}: re-encoded bytes mismatch");
        }
    }

    #[test]
    fn test_decode_extrinsic_tiny_roundtrip() {
        let config = Config::tiny();
        let bin = include_bytes!("../../../res/testvectors/codec/tiny/extrinsic.bin");
        let (ext, consumed) = Extrinsic::decode_with_config(bin, &config).unwrap();
        assert_eq!(consumed, bin.len());
        let re_encoded = ext.encode();
        assert_eq!(&re_encoded[..], &bin[..], "re-encoded bytes mismatch");
    }

    #[test]
    fn test_decode_block_tiny_roundtrip() {
        let config = Config::tiny();
        let block_bin = include_bytes!("../../../res/testvectors/codec/tiny/block.bin");
        let (block, consumed) = Block::decode_with_config(block_bin, &config).unwrap();
        assert_eq!(consumed, block_bin.len());
        let re_encoded = block.encode();
        assert_eq!(re_encoded.len(), block_bin.len(), "re-encoded length mismatch");
        assert_eq!(&re_encoded[..], &block_bin[..], "re-encoded bytes mismatch");
    }
}
