//! Header encoding functions E(H) and EU(H) (eq C.22-C.23).
//!
//! Shared between grey-state (for computing header hashes during transitions)
//! and grey (for the conformance binary).

use crate::encode::encode_compact;
use grey_types::header::Header;

/// Encode the full header E(H) = EU(H) ++ HS.
pub fn encode_header(header: &Header) -> Vec<u8> {
    let mut buf = encode_header_unsigned(header);
    // HS: seal (96 bytes)
    buf.extend_from_slice(&header.seal.0);
    buf
}

/// Encode the unsigned portion of a header EU(H) (eq C.23).
///
/// Field order: HP, HR, HX, E4(HT), ¿HE, ¿HW, E2(HI), HV, ↕HO
pub fn encode_header_unsigned(header: &Header) -> Vec<u8> {
    let mut buf = Vec::new();

    // HP: parent_hash (32 bytes)
    buf.extend_from_slice(&header.parent_hash.0);
    // HR: state_root (32 bytes)
    buf.extend_from_slice(&header.state_root.0);
    // HX: extrinsic_hash (32 bytes)
    buf.extend_from_slice(&header.extrinsic_hash.0);
    // E4(HT): timeslot (4 bytes LE)
    buf.extend_from_slice(&header.timeslot.to_le_bytes());

    // ¿HE: epoch_marker (optional/discriminated)
    match &header.epoch_marker {
        None => buf.push(0),
        Some(em) => {
            buf.push(1);
            // entropy: Hash (η₀)
            buf.extend_from_slice(&em.entropy.0);
            // entropy_previous: Hash (η₁)
            buf.extend_from_slice(&em.entropy_previous.0);
            // keys: V × (Bandersnatch(32) + Ed25519(32))
            for (bk, ek) in &em.validators {
                buf.extend_from_slice(&bk.0);
                buf.extend_from_slice(&ek.0);
            }
        }
    }

    // ¿HW: tickets_marker (optional/discriminated)
    match &header.tickets_marker {
        None => buf.push(0),
        Some(tickets) => {
            buf.push(1);
            // E tickets, each = Hash(32) + u8(1) = 33 bytes
            for ticket in tickets {
                buf.extend_from_slice(&ticket.id.0);
                buf.push(ticket.attempt);
            }
        }
    }

    // E2(HI): author_index (2 bytes LE)
    buf.extend_from_slice(&header.author_index.to_le_bytes());

    // HV: vrf_signature (96 bytes)
    buf.extend_from_slice(&header.vrf_signature.0);

    // ↕HO: offenders_marker (compact length + Ed25519 keys)
    encode_compact(header.offenders_marker.len() as u64, &mut buf);
    for key in &header.offenders_marker {
        buf.extend_from_slice(&key.0);
    }

    buf
}

/// Decode a full header from E(H) bytes.
#[allow(unused_assignments)]
pub fn decode_header(data: &[u8]) -> Option<Header> {
    use crate::decode::decode_compact_at;
    use grey_types::*;

    let mut pos = 0;
    let len = data.len();

    // Helper to read fixed bytes
    macro_rules! read_bytes {
        ($n:expr) => {{
            if pos + $n > len {
                return None;
            }
            let slice = &data[pos..pos + $n];
            pos += $n;
            slice
        }};
    }

    // HP: parent_hash (32 bytes)
    let mut parent_hash = [0u8; 32];
    parent_hash.copy_from_slice(read_bytes!(32));

    // HR: state_root (32 bytes)
    let mut state_root = [0u8; 32];
    state_root.copy_from_slice(read_bytes!(32));

    // HX: extrinsic_hash (32 bytes)
    let mut extrinsic_hash = [0u8; 32];
    extrinsic_hash.copy_from_slice(read_bytes!(32));

    // E4(HT): timeslot (4 bytes LE)
    let timeslot = u32::from_le_bytes(read_bytes!(4).try_into().ok()?);

    // ¿HE: epoch_marker (discriminated)
    let disc = *read_bytes!(1).first()?;
    let epoch_marker = if disc == 0 {
        None
    } else {
        let mut entropy = [0u8; 32];
        entropy.copy_from_slice(read_bytes!(32));
        let mut entropy_previous = [0u8; 32];
        entropy_previous.copy_from_slice(read_bytes!(32));
        // Read V validator key pairs until we hit the next discriminator.
        // Since we don't know V here, we read based on the tickets_marker
        // discriminator byte position. Epoch marker contains exactly E validator pairs
        // where E = epoch_length. Actually, per GP this is V validators.
        // We need to know the count. Since the encoding doesn't embed a length,
        // we need to know V from config. For a self-contained decode, we scan
        // ahead to find where the next section starts.
        //
        // Actually per GP eq C.23, the epoch marker validators is a fixed-size
        // array of V elements. Since we don't embed the count, the decoder
        // must know V. We'll accept a variable-length approach: read pairs
        // until we have consumed what's needed. For now, we try all known
        // validator counts (tiny=6, full=1023).
        //
        // Better approach: since everything after validators is deterministic
        // in size, we can compute V from remaining data.
        // After epoch_marker: ¿HW(1 byte disc + ...) + HI(2) + HV(96) + ↕HO(...) + HS(96)
        // Minimum remaining after validators = 1 + 2 + 96 + 1 + 96 = 196
        // Each validator pair = 64 bytes
        // So: validators_bytes = len - pos - (remaining_for: tickets_marker + rest)
        // But tickets_marker is variable too. Let's just compute:
        // remaining = len - pos
        // remaining = v_count * 64 + rest_of_header
        // rest_of_header >= 1(¿HW disc) + 2(HI) + 96(HV) + 1(↕HO min) + 96(HS) = 196
        // We try: v_count = (remaining - 196) / 64, but tickets_marker could be present.
        // Simplest: try common V values.
        let remaining = len - pos;
        // Try to figure out V: remaining includes validators + ¿HW + HI + HV + ↕HO + HS
        // Minimum without tickets and offenders: 1 + 2 + 96 + 1 + 96 = 196
        // With tickets (E entries of 33 bytes): 1 + E*33 + ...
        // Just try candidates
        let mut validators = Vec::new();
        let v_candidates = [6u32, 1023]; // tiny, full
        let mut found_v = false;
        let saved_pos = pos;
        for &v in &v_candidates {
            let need = v as usize * 64;
            if remaining >= need + 196 {
                pos = saved_pos;
                let mut vals = Vec::with_capacity(v as usize);
                let mut ok = true;
                for _ in 0..v {
                    if pos + 64 > len {
                        ok = false;
                        break;
                    }
                    let mut bk = [0u8; 32];
                    bk.copy_from_slice(&data[pos..pos + 32]);
                    pos += 32;
                    let mut ek = [0u8; 32];
                    ek.copy_from_slice(&data[pos..pos + 32]);
                    pos += 32;
                    vals.push((BandersnatchPublicKey(bk), Ed25519PublicKey(ek)));
                }
                if ok {
                    // Verify next byte is a valid discriminator (0 or 1)
                    if pos < len && (data[pos] == 0 || data[pos] == 1) {
                        validators = vals;
                        found_v = true;
                        break;
                    }
                }
            }
        }
        if !found_v {
            return None;
        }
        Some(header::EpochMarker {
            entropy: Hash(entropy),
            entropy_previous: Hash(entropy_previous),
            validators,
        })
    };

    // ¿HW: tickets_marker (discriminated)
    let disc = *read_bytes!(1).first()?;
    let tickets_marker = if disc == 0 {
        None
    } else {
        // E tickets, each = Hash(32) + u8(1) = 33 bytes
        // Same problem: we don't know E. Use same approach.
        let remaining = len - pos;
        // After tickets: HI(2) + HV(96) + ↕HO(1+) + HS(96) = min 195
        let e_candidates = [12u32, 600]; // tiny, full
        let mut tickets = Vec::new();
        let mut found_e = false;
        let saved_pos = pos;
        for &e in &e_candidates {
            let need = e as usize * 33;
            if remaining >= need + 195 {
                pos = saved_pos;
                let mut tix = Vec::with_capacity(e as usize);
                for _ in 0..e {
                    if pos + 33 > len {
                        break;
                    }
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&data[pos..pos + 32]);
                    pos += 32;
                    let attempt = data[pos];
                    pos += 1;
                    tix.push(header::Ticket {
                        id: Hash(id),
                        attempt,
                    });
                }
                if tix.len() == e as usize {
                    tickets = tix;
                    found_e = true;
                    break;
                }
            }
        }
        if !found_e {
            return None;
        }
        Some(tickets)
    };

    // E2(HI): author_index (2 bytes LE)
    let author_index = u16::from_le_bytes(read_bytes!(2).try_into().ok()?);

    // HV: vrf_signature (96 bytes)
    let mut vrf_sig = [0u8; 96];
    vrf_sig.copy_from_slice(read_bytes!(96));

    // ↕HO: offenders_marker (compact length + Ed25519 keys)
    let offenders_count = decode_compact_at(data, &mut pos).ok()? as usize;
    let mut offenders = Vec::with_capacity(offenders_count);
    for _ in 0..offenders_count {
        let mut key = [0u8; 32];
        key.copy_from_slice(read_bytes!(32));
        offenders.push(Ed25519PublicKey(key));
    }

    // HS: seal (96 bytes)
    let mut seal = [0u8; 96];
    seal.copy_from_slice(read_bytes!(96));

    Some(Header {
        parent_hash: Hash(parent_hash),
        state_root: Hash(state_root),
        extrinsic_hash: Hash(extrinsic_hash),
        timeslot,
        epoch_marker,
        tickets_marker,
        author_index,
        vrf_signature: BandersnatchSignature(vrf_sig),
        offenders_marker: offenders,
        seal: BandersnatchSignature(seal),
    })
}

/// Compute header hash H(E(H)) — blake2b-256 of the full header encoding.
///
/// Per GP eq 5.1: HP ≡ H(E(P(H)))
pub fn compute_header_hash(header: &Header) -> grey_types::Hash {
    let encoded = encode_header(header);
    grey_crypto::blake2b_256(&encoded)
}

/// Compute unsigned header hash H(EU(H)) — blake2b-256 of the unsigned header encoding.
///
/// Used by the fuzz-proto GetState lookup.
pub fn compute_unsigned_header_hash(header: &Header) -> grey_types::Hash {
    let encoded = encode_header_unsigned(header);
    grey_crypto::blake2b_256(&encoded)
}
