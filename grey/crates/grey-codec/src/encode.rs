//! Encoding functions (Appendix C of the Gray Paper).

/// Trait for types that can be encoded to the JAM wire format.
pub trait Encode {
    /// Encode this value, appending bytes to the given buffer.
    fn encode_to(&self, buf: &mut Vec<u8>);

    /// Encode this value and return the bytes.
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_to(&mut buf);
        buf
    }
}

/// Encode a variable-length natural number (eq C.1-C.4).
///
/// JAM prefix-length encoding: the leading bits of the first byte indicate
/// the number of additional bytes. The first byte also carries the most
/// significant bits of the value, remaining bytes are little-endian.
///
/// - `0xxxxxxx` (1 byte):  values 0..127
/// - `10xxxxxx + 1 byte`:  values 128..16383
/// - `110xxxxx + 2 bytes`: values 16384..2097151
/// - `1110xxxx + 3 bytes`: values up to 2^28-1
/// - ... up to `11111110 + 7 bytes`, and `11111111 + 8 bytes LE`
pub fn encode_natural(value: usize, buf: &mut Vec<u8>) {
    encode_compact(value as u64, buf);
}

/// Encode a value using JAM compact/variable-length encoding.
///
/// Same encoding as `encode_natural` but takes u64 directly.
/// Used for sequence length prefixes and for fields marked as Compact in the ASN schema.
pub fn encode_compact(value: u64, buf: &mut Vec<u8>) {
    if value == 0 {
        buf.push(0);
        return;
    }
    let x = value;
    // Find len: smallest L in 0..=7 such that x < 2^(7*(L+1))
    let len = (0u32..8).find(|&l| x < (1u64 << (7 * (l + 1)))).unwrap_or(8);
    if len <= 7 {
        // Header byte: top `len` bits set + high bits of value
        let threshold = 256u16 - (1u16 << (8 - len));
        let header = threshold as u8 + (x >> (8 * len)) as u8;
        buf.push(header);
        if len > 0 {
            let mask = (1u64 << (8 * len)) - 1;
            let remainder = x & mask;
            buf.extend_from_slice(&remainder.to_le_bytes()[..len as usize]);
        }
    } else {
        // len >= 8: header = 0xFF, followed by 8 LE bytes
        buf.push(0xFF);
        buf.extend_from_slice(&x.to_le_bytes());
    }
}

// Fixed-width little-endian integer encodings (eq C.12).

impl Encode for u8 {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.push(*self);
    }
}

impl Encode for u16 {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_le_bytes());
    }
}

impl Encode for u32 {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_le_bytes());
    }
}

impl Encode for u64 {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_le_bytes());
    }
}

impl Encode for bool {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.push(if *self { 1 } else { 0 });
    }
}

impl Encode for [u8; 32] {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self);
    }
}

impl Encode for [u8; 64] {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self);
    }
}

impl Encode for [u8; 96] {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self);
    }
}

impl Encode for grey_types::Hash {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}

impl Encode for grey_types::Ed25519PublicKey {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}

impl Encode for grey_types::BandersnatchPublicKey {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}

impl Encode for grey_types::BandersnatchSignature {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}

impl Encode for grey_types::Ed25519Signature {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}

/// Encode a variable-length sequence with length prefix.
impl<T: Encode> Encode for Vec<T> {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        encode_natural(self.len(), buf);
        for item in self {
            item.encode_to(buf);
        }
    }
}

/// Encode an optional value with a discriminator byte (eq C.5-C.7).
impl<T: Encode> Encode for Option<T> {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        match self {
            None => buf.push(0),
            Some(val) => {
                buf.push(1);
                val.encode_to(buf);
            }
        }
    }
}

// --- Encode impls for tuples ---

impl<A: Encode, B: Encode> Encode for (A, B) {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.0.encode_to(buf);
        self.1.encode_to(buf);
    }
}

// --- Encode impls for protocol types (Appendix C) ---

use grey_types::header::*;
use grey_types::work::*;

impl Encode for RefinementContext {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.anchor.encode_to(buf);
        self.state_root.encode_to(buf);
        self.beefy_root.encode_to(buf);
        self.lookup_anchor.encode_to(buf);
        self.lookup_anchor_timeslot.encode_to(buf);
        self.prerequisites.encode_to(buf);
    }
}

impl Encode for WorkResult {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        match self {
            WorkResult::Ok(data) => {
                buf.push(0);
                data.encode_to(buf);
            }
            WorkResult::OutOfGas => buf.push(1),
            WorkResult::Panic => buf.push(2),
            WorkResult::BadExports => buf.push(3),
            WorkResult::BadCode => buf.push(4),
            WorkResult::CodeOversize => buf.push(5),
        }
    }
}

impl Encode for WorkDigest {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        // WorkResult fields (ASN)
        self.service_id.encode_to(buf);
        self.code_hash.encode_to(buf);
        self.payload_hash.encode_to(buf);
        self.accumulate_gas.encode_to(buf);
        self.result.encode_to(buf);
        // RefineLoad fields use SCALE Compact encoding
        encode_compact(self.gas_used, buf);
        encode_compact(self.imports_count as u64, buf);
        encode_compact(self.extrinsics_count as u64, buf);
        encode_compact(self.extrinsics_size as u64, buf);
        encode_compact(self.exports_count as u64, buf);
    }
}

impl Encode for ImportSegment {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.hash.encode_to(buf);
        self.index.encode_to(buf);
    }
}

impl Encode for WorkItem {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.service_id.encode_to(buf);
        self.code_hash.encode_to(buf);
        self.gas_limit.encode_to(buf);
        self.accumulate_gas_limit.encode_to(buf);
        self.exports_count.encode_to(buf);
        self.payload.encode_to(buf);
        self.imports.encode_to(buf);
        self.extrinsics.encode_to(buf);
    }
}

impl Encode for AvailabilitySpec {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.package_hash.encode_to(buf);
        self.bundle_length.encode_to(buf);
        self.erasure_root.encode_to(buf);
        self.exports_root.encode_to(buf);
        self.exports_count.encode_to(buf);
    }
}

impl Encode for WorkReport {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.package_spec.encode_to(buf);
        self.context.encode_to(buf);
        // core_index uses Compact encoding
        encode_compact(self.core_index as u64, buf);
        self.authorizer_hash.encode_to(buf);
        // auth_gas_used uses Compact encoding
        encode_compact(self.auth_gas_used, buf);
        self.auth_output.encode_to(buf);
        self.segment_root_lookup.encode_to(buf);
        self.results.encode_to(buf);
    }
}

/// Encode a BTreeMap as a sorted sequence of key-value pairs (eq C.10).
impl<K: Encode, V: Encode> Encode for std::collections::BTreeMap<K, V> {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        encode_natural(self.len(), buf);
        for (k, v) in self.iter() {
            k.encode_to(buf);
            v.encode_to(buf);
        }
    }
}

impl Encode for WorkPackage {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.auth_code_host.encode_to(buf);
        self.auth_code_hash.encode_to(buf);
        self.context.encode_to(buf);
        self.authorization.encode_to(buf);
        self.authorizer_config.encode_to(buf);
        self.items.encode_to(buf);
    }
}

impl Encode for Ticket {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.id.encode_to(buf);
        self.attempt.encode_to(buf);
    }
}

impl Encode for TicketProof {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.attempt.encode_to(buf);
        // Ring VRF signature is fixed-size 784 bytes (no length prefix)
        buf.extend_from_slice(&self.proof);
    }
}

impl Encode for Verdict {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.report_hash.encode_to(buf);
        self.age.encode_to(buf);
        // votes is SEQUENCE (SIZE(validators-super-majority)) — fixed-size, no length prefix
        for judgment in &self.judgments {
            judgment.encode_to(buf);
        }
    }
}

impl Encode for Judgment {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.is_valid.encode_to(buf);
        self.validator_index.encode_to(buf);
        self.signature.encode_to(buf);
    }
}

impl Encode for Culprit {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.report_hash.encode_to(buf);
        self.validator_key.encode_to(buf);
        self.signature.encode_to(buf);
    }
}

impl Encode for Fault {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.report_hash.encode_to(buf);
        self.is_valid.encode_to(buf);
        self.validator_key.encode_to(buf);
        self.signature.encode_to(buf);
    }
}

impl Encode for DisputesExtrinsic {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.verdicts.encode_to(buf);
        self.culprits.encode_to(buf);
        self.faults.encode_to(buf);
    }
}

impl Encode for Assurance {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.anchor.encode_to(buf);
        // Bitfield is a fixed-size OCTET STRING (not length-prefixed)
        buf.extend_from_slice(&self.bitfield);
        self.validator_index.encode_to(buf);
        self.signature.encode_to(buf);
    }
}

impl Encode for Guarantee {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.report.encode_to(buf);
        self.timeslot.encode_to(buf);
        self.credentials.encode_to(buf);
    }
}

impl Encode for Extrinsic {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.tickets.encode_to(buf);
        self.preimages.encode_to(buf);
        self.guarantees.encode_to(buf);
        self.assurances.encode_to(buf);
        self.disputes.encode_to(buf);
    }
}

impl Encode for EpochMarker {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.entropy.encode_to(buf);
        self.entropy_previous.encode_to(buf);
        // validators is SEQUENCE (SIZE(validators-count)) — fixed-size, no length prefix
        for (bk, ek) in &self.validators {
            bk.encode_to(buf);
            ek.encode_to(buf);
        }
    }
}

impl Encode for Header {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.parent_hash.encode_to(buf);
        self.state_root.encode_to(buf);
        self.extrinsic_hash.encode_to(buf);
        self.timeslot.encode_to(buf);
        self.epoch_marker.encode_to(buf);
        // tickets_marker: TicketsMark OPTIONAL
        // TicketsMark is SEQUENCE (SIZE(epoch-length)) — fixed-size, no length prefix
        match &self.tickets_marker {
            None => buf.push(0),
            Some(tickets) => {
                buf.push(1);
                for ticket in tickets {
                    ticket.encode_to(buf);
                }
            }
        }
        self.author_index.encode_to(buf);
        self.vrf_signature.encode_to(buf);
        self.offenders_marker.encode_to(buf);
        self.seal.encode_to(buf);
    }
}

impl Encode for Block {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        self.header.encode_to(buf);
        self.extrinsic.encode_to(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_natural_small() {
        let mut buf = Vec::new();
        encode_natural(0, &mut buf);
        assert_eq!(buf, vec![0]);

        let mut buf = Vec::new();
        encode_natural(127, &mut buf);
        assert_eq!(buf, vec![127]);
    }

    #[test]
    fn test_encode_natural_large() {
        let mut buf = Vec::new();
        encode_natural(128, &mut buf);
        assert_eq!(buf, vec![0x80, 0x80]); // JAM prefix-length: 2 bytes

        let mut buf = Vec::new();
        encode_natural(300, &mut buf);
        assert_eq!(buf, vec![0x81, 0x2c]); // JAM prefix-length: 300 = 1*256 + 44

        let mut buf = Vec::new();
        encode_natural(16384, &mut buf);
        assert_eq!(buf, vec![0xc0, 0x00, 0x40]); // JAM prefix-length: 3 bytes
    }

    #[test]
    fn test_encode_u32_le() {
        let val: u32 = 0x12345678;
        let encoded = val.encode();
        assert_eq!(encoded, vec![0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_encode_hash() {
        let hash = grey_types::Hash([0xAB; 32]);
        let encoded = hash.encode();
        assert_eq!(encoded.len(), 32);
        assert!(encoded.iter().all(|&b| b == 0xAB));
    }

    /// Helper: decode a 0x-prefixed hex string to bytes.
    fn decode_hex(s: &str) -> Vec<u8> {
        hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("bad hex")
    }

    /// Helper: decode hex string to a Hash.
    fn hash_from_hex(s: &str) -> grey_types::Hash {
        let bytes = decode_hex(s);
        let mut h = [0u8; 32];
        h.copy_from_slice(&bytes);
        grey_types::Hash(h)
    }

    #[test]
    fn test_codec_refine_context() {
        let json: serde_json::Value = serde_json::from_str(
            include_str!("../../../res/spec/tests/vectors/codec/refine_context.gp072_tiny.json"),
        )
        .unwrap();
        let expected = include_bytes!("../../../res/spec/tests/vectors/codec/refine_context.gp072_tiny.bin");

        let ctx = RefinementContext {
            anchor: hash_from_hex(json["anchor"].as_str().unwrap()),
            state_root: hash_from_hex(json["state_root"].as_str().unwrap()),
            beefy_root: hash_from_hex(json["beefy_root"].as_str().unwrap()),
            lookup_anchor: hash_from_hex(json["lookup_anchor"].as_str().unwrap()),
            lookup_anchor_timeslot: json["lookup_anchor_slot"].as_u64().unwrap() as u32,
            prerequisites: json["prerequisites"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| hash_from_hex(v.as_str().unwrap()))
                .collect(),
        };

        let encoded = ctx.encode();
        assert_eq!(
            encoded,
            expected.as_slice(),
            "refine_context encoding mismatch"
        );
    }

    /// Helper: parse a WorkDigest from a JSON value (test vector format).
    fn work_digest_from_json(json: &serde_json::Value) -> WorkDigest {
        let result = &json["result"];
        let work_result = if let Some(data) = result.get("ok") {
            WorkResult::Ok(decode_hex(data.as_str().unwrap()))
        } else if result.get("out_of_gas").is_some() {
            WorkResult::OutOfGas
        } else if result.get("panic").is_some() {
            WorkResult::Panic
        } else if result.get("bad_exports").is_some() {
            WorkResult::BadExports
        } else if result.get("bad_code").is_some() {
            WorkResult::BadCode
        } else if result.get("code_oversize").is_some() {
            WorkResult::CodeOversize
        } else {
            panic!("unknown work result variant");
        };

        let rl = &json["refine_load"];
        WorkDigest {
            service_id: json["service_id"].as_u64().unwrap() as u32,
            code_hash: hash_from_hex(json["code_hash"].as_str().unwrap()),
            payload_hash: hash_from_hex(json["payload_hash"].as_str().unwrap()),
            accumulate_gas: json["accumulate_gas"].as_u64().unwrap(),
            result: work_result,
            gas_used: rl["gas_used"].as_u64().unwrap(),
            imports_count: rl["imports"].as_u64().unwrap() as u16,
            extrinsics_count: rl["extrinsic_count"].as_u64().unwrap() as u16,
            extrinsics_size: rl["extrinsic_size"].as_u64().unwrap() as u32,
            exports_count: rl["exports"].as_u64().unwrap() as u16,
        }
    }

    #[test]
    fn test_codec_work_result_0() {
        let json: serde_json::Value = serde_json::from_str(
            include_str!("../../../res/spec/tests/vectors/codec/work_result_0.gp072_tiny.json"),
        )
        .unwrap();
        let expected = include_bytes!("../../../res/spec/tests/vectors/codec/work_result_0.gp072_tiny.bin");
        let digest = work_digest_from_json(&json);
        let encoded = digest.encode();
        assert_eq!(encoded, expected.as_slice(), "work_result_0 encoding mismatch");
    }

    #[test]
    fn test_codec_work_item() {
        let json: serde_json::Value = serde_json::from_str(
            include_str!("../../../res/spec/tests/vectors/codec/work_item.gp072_tiny.json"),
        )
        .unwrap();
        let expected = include_bytes!("../../../res/spec/tests/vectors/codec/work_item.gp072_tiny.bin");

        let item = WorkItem {
            service_id: json["service"].as_u64().unwrap() as u32,
            code_hash: hash_from_hex(json["code_hash"].as_str().unwrap()),
            gas_limit: json["refine_gas_limit"].as_u64().unwrap(),
            accumulate_gas_limit: json["accumulate_gas_limit"].as_u64().unwrap(),
            exports_count: json["export_count"].as_u64().unwrap() as u16,
            payload: decode_hex(json["payload"].as_str().unwrap()),
            imports: json["import_segments"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| ImportSegment {
                    hash: hash_from_hex(s["tree_root"].as_str().unwrap()),
                    index: s["index"].as_u64().unwrap() as u16,
                })
                .collect(),
            extrinsics: json["extrinsic"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| {
                    (
                        hash_from_hex(e["hash"].as_str().unwrap()),
                        e["len"].as_u64().unwrap() as u32,
                    )
                })
                .collect(),
        };

        let encoded = item.encode();
        assert_eq!(encoded, expected.as_slice(), "work_item encoding mismatch");
    }

    #[test]
    fn test_codec_work_result_1() {
        let json: serde_json::Value = serde_json::from_str(
            include_str!("../../../res/spec/tests/vectors/codec/work_result_1.gp072_tiny.json"),
        )
        .unwrap();
        let expected = include_bytes!("../../../res/spec/tests/vectors/codec/work_result_1.gp072_tiny.bin");
        let digest = work_digest_from_json(&json);
        let encoded = digest.encode();
        assert_eq!(encoded, expected.as_slice(), "work_result_1 encoding mismatch");
    }

    fn refine_context_from_json(json: &serde_json::Value) -> RefinementContext {
        RefinementContext {
            anchor: hash_from_hex(json["anchor"].as_str().unwrap()),
            state_root: hash_from_hex(json["state_root"].as_str().unwrap()),
            beefy_root: hash_from_hex(json["beefy_root"].as_str().unwrap()),
            lookup_anchor: hash_from_hex(json["lookup_anchor"].as_str().unwrap()),
            lookup_anchor_timeslot: json["lookup_anchor_slot"].as_u64().unwrap() as u32,
            prerequisites: json["prerequisites"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| hash_from_hex(v.as_str().unwrap()))
                .collect(),
        }
    }

    fn availability_spec_from_json(json: &serde_json::Value) -> AvailabilitySpec {
        AvailabilitySpec {
            package_hash: hash_from_hex(json["hash"].as_str().unwrap()),
            bundle_length: json["length"].as_u64().unwrap() as u32,
            erasure_root: hash_from_hex(json["erasure_root"].as_str().unwrap()),
            exports_root: hash_from_hex(json["exports_root"].as_str().unwrap()),
            exports_count: json["exports_count"].as_u64().unwrap() as u16,
        }
    }

    fn work_item_from_json(json: &serde_json::Value) -> WorkItem {
        WorkItem {
            service_id: json["service"].as_u64().unwrap() as u32,
            code_hash: hash_from_hex(json["code_hash"].as_str().unwrap()),
            gas_limit: json["refine_gas_limit"].as_u64().unwrap(),
            accumulate_gas_limit: json["accumulate_gas_limit"].as_u64().unwrap(),
            exports_count: json["export_count"].as_u64().unwrap() as u16,
            payload: decode_hex(json["payload"].as_str().unwrap()),
            imports: json["import_segments"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| ImportSegment {
                    hash: hash_from_hex(s["tree_root"].as_str().unwrap()),
                    index: s["index"].as_u64().unwrap() as u16,
                })
                .collect(),
            extrinsics: json["extrinsic"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| (hash_from_hex(e["hash"].as_str().unwrap()), e["len"].as_u64().unwrap() as u32))
                .collect(),
        }
    }

    fn work_report_from_json(json: &serde_json::Value) -> WorkReport {
        WorkReport {
            package_spec: availability_spec_from_json(&json["package_spec"]),
            context: refine_context_from_json(&json["context"]),
            core_index: json["core_index"].as_u64().unwrap() as u16,
            authorizer_hash: hash_from_hex(json["authorizer_hash"].as_str().unwrap()),
            auth_gas_used: json["auth_gas_used"].as_u64().unwrap(),
            auth_output: decode_hex(json["auth_output"].as_str().unwrap()),
            segment_root_lookup: json["segment_root_lookup"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| {
                    (
                        hash_from_hex(item["work_package_hash"].as_str().unwrap()),
                        hash_from_hex(item["segment_tree_root"].as_str().unwrap()),
                    )
                })
                .collect(),
            results: json["results"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| work_digest_from_json(r))
                .collect(),
        }
    }

    fn sig64_from_hex(s: &str) -> grey_types::Ed25519Signature {
        let bytes = decode_hex(s);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&bytes);
        grey_types::Ed25519Signature(sig)
    }

    fn ed25519_key_from_hex(s: &str) -> grey_types::Ed25519PublicKey {
        let bytes = decode_hex(s);
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        grey_types::Ed25519PublicKey(key)
    }

    #[test]
    fn test_codec_work_package() {
        let json: serde_json::Value = serde_json::from_str(
            include_str!("../../../res/spec/tests/vectors/codec/work_package.gp072_tiny.json"),
        )
        .unwrap();
        let expected = include_bytes!("../../../res/spec/tests/vectors/codec/work_package.gp072_tiny.bin");

        let pkg = WorkPackage {
            auth_code_host: json["auth_code_host"].as_u64().unwrap() as u32,
            auth_code_hash: hash_from_hex(json["auth_code_hash"].as_str().unwrap()),
            context: refine_context_from_json(&json["context"]),
            authorization: decode_hex(json["authorization"].as_str().unwrap()),
            authorizer_config: decode_hex(json["authorizer_config"].as_str().unwrap()),
            items: json["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| work_item_from_json(i))
                .collect(),
        };

        let encoded = pkg.encode();
        assert_eq!(encoded, expected.as_slice(), "work_package encoding mismatch");
    }

    #[test]
    fn test_codec_work_report() {
        let json: serde_json::Value = serde_json::from_str(
            include_str!("../../../res/spec/tests/vectors/codec/work_report.gp072_tiny.json"),
        )
        .unwrap();
        let expected = include_bytes!("../../../res/spec/tests/vectors/codec/work_report.gp072_tiny.bin");

        let report = work_report_from_json(&json);
        let encoded = report.encode();
        assert_eq!(encoded, expected.as_slice(), "work_report encoding mismatch");
    }

    #[test]
    fn test_codec_tickets_extrinsic() {
        let json: serde_json::Value = serde_json::from_str(
            include_str!("../../../res/spec/tests/vectors/codec/tickets_extrinsic.gp072_tiny.json"),
        )
        .unwrap();
        let expected = include_bytes!("../../../res/spec/tests/vectors/codec/tickets_extrinsic.gp072_tiny.bin");

        let tickets: Vec<TicketProof> = json
            .as_array()
            .unwrap()
            .iter()
            .map(|t| TicketProof {
                attempt: t["attempt"].as_u64().unwrap() as u8,
                proof: decode_hex(t["signature"].as_str().unwrap()),
            })
            .collect();

        let encoded = tickets.encode();
        assert_eq!(encoded, expected.as_slice(), "tickets_extrinsic encoding mismatch");
    }

    #[test]
    fn test_codec_disputes_extrinsic() {
        let json: serde_json::Value = serde_json::from_str(
            include_str!("../../../res/spec/tests/vectors/codec/disputes_extrinsic.gp072_tiny.json"),
        )
        .unwrap();
        let expected = include_bytes!("../../../res/spec/tests/vectors/codec/disputes_extrinsic.gp072_tiny.bin");

        let disputes = DisputesExtrinsic {
            verdicts: json["verdicts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| Verdict {
                    report_hash: hash_from_hex(v["target"].as_str().unwrap()),
                    age: v["age"].as_u64().unwrap() as u32,
                    judgments: v["votes"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|j| Judgment {
                            is_valid: j["vote"].as_bool().unwrap(),
                            validator_index: j["index"].as_u64().unwrap() as u16,
                            signature: sig64_from_hex(j["signature"].as_str().unwrap()),
                        })
                        .collect(),
                })
                .collect(),
            culprits: json["culprits"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| Culprit {
                    report_hash: hash_from_hex(c["target"].as_str().unwrap()),
                    validator_key: ed25519_key_from_hex(c["key"].as_str().unwrap()),
                    signature: sig64_from_hex(c["signature"].as_str().unwrap()),
                })
                .collect(),
            faults: json["faults"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| Fault {
                    report_hash: hash_from_hex(f["target"].as_str().unwrap()),
                    is_valid: f["vote"].as_bool().unwrap(),
                    validator_key: ed25519_key_from_hex(f["key"].as_str().unwrap()),
                    signature: sig64_from_hex(f["signature"].as_str().unwrap()),
                })
                .collect(),
        };

        let encoded = disputes.encode();
        assert_eq!(encoded, expected.as_slice(), "disputes_extrinsic encoding mismatch");
    }

    #[test]
    fn test_codec_preimages_extrinsic() {
        let json: serde_json::Value = serde_json::from_str(
            include_str!("../../../res/spec/tests/vectors/codec/preimages_extrinsic.gp072_tiny.json"),
        )
        .unwrap();
        let expected = include_bytes!("../../../res/spec/tests/vectors/codec/preimages_extrinsic.gp072_tiny.bin");

        let preimages: Vec<(u32, Vec<u8>)> = json
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                (
                    p["requester"].as_u64().unwrap() as u32,
                    decode_hex(p["blob"].as_str().unwrap()),
                )
            })
            .collect();

        let encoded = preimages.encode();
        assert_eq!(encoded, expected.as_slice(), "preimages_extrinsic encoding mismatch");
    }

    #[test]
    fn test_codec_assurances_extrinsic() {
        let json: serde_json::Value = serde_json::from_str(
            include_str!("../../../res/spec/tests/vectors/codec/assurances_extrinsic.gp072_tiny.json"),
        )
        .unwrap();
        let expected = include_bytes!("../../../res/spec/tests/vectors/codec/assurances_extrinsic.gp072_tiny.bin");

        let assurances: Vec<Assurance> = json
            .as_array()
            .unwrap()
            .iter()
            .map(|a| Assurance {
                anchor: hash_from_hex(a["anchor"].as_str().unwrap()),
                bitfield: decode_hex(a["bitfield"].as_str().unwrap()),
                validator_index: a["validator_index"].as_u64().unwrap() as u16,
                signature: sig64_from_hex(a["signature"].as_str().unwrap()),
            })
            .collect();

        let encoded = assurances.encode();
        assert_eq!(encoded, expected.as_slice(), "assurances_extrinsic encoding mismatch");
    }

    #[test]
    fn test_codec_guarantees_extrinsic() {
        let json: serde_json::Value = serde_json::from_str(
            include_str!("../../../res/spec/tests/vectors/codec/guarantees_extrinsic.gp072_tiny.json"),
        )
        .unwrap();
        let expected = include_bytes!("../../../res/spec/tests/vectors/codec/guarantees_extrinsic.gp072_tiny.bin");

        let guarantees: Vec<Guarantee> = json
            .as_array()
            .unwrap()
            .iter()
            .map(|g| Guarantee {
                report: work_report_from_json(&g["report"]),
                timeslot: g["slot"].as_u64().unwrap() as u32,
                credentials: g["signatures"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| {
                        (
                            s["validator_index"].as_u64().unwrap() as u16,
                            sig64_from_hex(s["signature"].as_str().unwrap()),
                        )
                    })
                    .collect(),
            })
            .collect();

        let encoded = guarantees.encode();
        assert_eq!(encoded, expected.as_slice(), "guarantees_extrinsic encoding mismatch");
    }

    fn bandersnatch_key_from_hex(s: &str) -> grey_types::BandersnatchPublicKey {
        let bytes = decode_hex(s);
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        grey_types::BandersnatchPublicKey(key)
    }

    fn bandersnatch_sig_from_hex(s: &str) -> grey_types::BandersnatchSignature {
        let bytes = decode_hex(s);
        let mut sig = [0u8; 96];
        sig.copy_from_slice(&bytes);
        grey_types::BandersnatchSignature(sig)
    }

    fn epoch_marker_from_json(json: &serde_json::Value) -> EpochMarker {
        EpochMarker {
            entropy: hash_from_hex(json["entropy"].as_str().unwrap()),
            entropy_previous: hash_from_hex(json["tickets_entropy"].as_str().unwrap()),
            validators: json["validators"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| {
                    (
                        bandersnatch_key_from_hex(v["bandersnatch"].as_str().unwrap()),
                        ed25519_key_from_hex(v["ed25519"].as_str().unwrap()),
                    )
                })
                .collect(),
        }
    }

    fn ticket_from_json(json: &serde_json::Value) -> Ticket {
        Ticket {
            id: hash_from_hex(json["id"].as_str().unwrap()),
            attempt: json["attempt"].as_u64().unwrap() as u8,
        }
    }

    fn header_from_json(json: &serde_json::Value) -> Header {
        Header {
            parent_hash: hash_from_hex(json["parent"].as_str().unwrap()),
            state_root: hash_from_hex(json["parent_state_root"].as_str().unwrap()),
            extrinsic_hash: hash_from_hex(json["extrinsic_hash"].as_str().unwrap()),
            timeslot: json["slot"].as_u64().unwrap() as u32,
            epoch_marker: if json["epoch_mark"].is_null() {
                None
            } else {
                Some(epoch_marker_from_json(&json["epoch_mark"]))
            },
            tickets_marker: if json["tickets_mark"].is_null() {
                None
            } else {
                Some(
                    json["tickets_mark"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|t| ticket_from_json(t))
                        .collect(),
                )
            },
            author_index: json["author_index"].as_u64().unwrap() as u16,
            vrf_signature: bandersnatch_sig_from_hex(json["entropy_source"].as_str().unwrap()),
            offenders_marker: json["offenders_mark"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| ed25519_key_from_hex(o.as_str().unwrap()))
                .collect(),
            seal: bandersnatch_sig_from_hex(json["seal"].as_str().unwrap()),
        }
    }

    fn disputes_from_json(json: &serde_json::Value) -> DisputesExtrinsic {
        DisputesExtrinsic {
            verdicts: json["verdicts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| Verdict {
                    report_hash: hash_from_hex(v["target"].as_str().unwrap()),
                    age: v["age"].as_u64().unwrap() as u32,
                    judgments: v["votes"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|j| Judgment {
                            is_valid: j["vote"].as_bool().unwrap(),
                            validator_index: j["index"].as_u64().unwrap() as u16,
                            signature: sig64_from_hex(j["signature"].as_str().unwrap()),
                        })
                        .collect(),
                })
                .collect(),
            culprits: json["culprits"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| Culprit {
                    report_hash: hash_from_hex(c["target"].as_str().unwrap()),
                    validator_key: ed25519_key_from_hex(c["key"].as_str().unwrap()),
                    signature: sig64_from_hex(c["signature"].as_str().unwrap()),
                })
                .collect(),
            faults: json["faults"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| Fault {
                    report_hash: hash_from_hex(f["target"].as_str().unwrap()),
                    is_valid: f["vote"].as_bool().unwrap(),
                    validator_key: ed25519_key_from_hex(f["key"].as_str().unwrap()),
                    signature: sig64_from_hex(f["signature"].as_str().unwrap()),
                })
                .collect(),
        }
    }

    #[test]
    fn test_codec_header_0() {
        let json: serde_json::Value = serde_json::from_str(
            include_str!("../../../res/spec/tests/vectors/codec/header_0.gp072_tiny.json"),
        )
        .unwrap();
        let expected = include_bytes!("../../../res/spec/tests/vectors/codec/header_0.gp072_tiny.bin");

        let header = header_from_json(&json);
        let encoded = header.encode();
        assert_eq!(encoded, expected.as_slice(), "header_0 encoding mismatch");
    }

    #[test]
    fn test_codec_header_1() {
        let json: serde_json::Value = serde_json::from_str(
            include_str!("../../../res/spec/tests/vectors/codec/header_1.gp072_tiny.json"),
        )
        .unwrap();
        let expected = include_bytes!("../../../res/spec/tests/vectors/codec/header_1.gp072_tiny.bin");

        let header = header_from_json(&json);
        let encoded = header.encode();
        assert_eq!(encoded, expected.as_slice(), "header_1 encoding mismatch");
    }

    #[test]
    fn test_codec_extrinsic() {
        let json: serde_json::Value = serde_json::from_str(
            include_str!("../../../res/spec/tests/vectors/codec/extrinsic.gp072_tiny.json"),
        )
        .unwrap();
        let expected = include_bytes!("../../../res/spec/tests/vectors/codec/extrinsic.gp072_tiny.bin");

        let extrinsic = Extrinsic {
            tickets: json["tickets"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| TicketProof {
                    attempt: t["attempt"].as_u64().unwrap() as u8,
                    proof: decode_hex(t["signature"].as_str().unwrap()),
                })
                .collect(),
            preimages: json["preimages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| {
                    (
                        p["requester"].as_u64().unwrap() as u32,
                        decode_hex(p["blob"].as_str().unwrap()),
                    )
                })
                .collect(),
            guarantees: json["guarantees"]
                .as_array()
                .unwrap()
                .iter()
                .map(|g| Guarantee {
                    report: work_report_from_json(&g["report"]),
                    timeslot: g["slot"].as_u64().unwrap() as u32,
                    credentials: g["signatures"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|s| {
                            (
                                s["validator_index"].as_u64().unwrap() as u16,
                                sig64_from_hex(s["signature"].as_str().unwrap()),
                            )
                        })
                        .collect(),
                })
                .collect(),
            assurances: json["assurances"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| Assurance {
                    anchor: hash_from_hex(a["anchor"].as_str().unwrap()),
                    bitfield: decode_hex(a["bitfield"].as_str().unwrap()),
                    validator_index: a["validator_index"].as_u64().unwrap() as u16,
                    signature: sig64_from_hex(a["signature"].as_str().unwrap()),
                })
                .collect(),
            disputes: disputes_from_json(&json["disputes"]),
        };

        let encoded = extrinsic.encode();
        assert_eq!(encoded, expected.as_slice(), "extrinsic encoding mismatch");
    }

    #[test]
    fn test_codec_block() {
        let json: serde_json::Value = serde_json::from_str(
            include_str!("../../../res/spec/tests/vectors/codec/block.gp072_tiny.json"),
        )
        .unwrap();
        let expected = include_bytes!("../../../res/spec/tests/vectors/codec/block.gp072_tiny.bin");

        let block = Block {
            header: header_from_json(&json["header"]),
            extrinsic: {
                let ext = &json["extrinsic"];
                Extrinsic {
                    tickets: ext["tickets"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|t| TicketProof {
                            attempt: t["attempt"].as_u64().unwrap() as u8,
                            proof: decode_hex(t["signature"].as_str().unwrap()),
                        })
                        .collect(),
                    preimages: ext["preimages"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|p| {
                            (
                                p["requester"].as_u64().unwrap() as u32,
                                decode_hex(p["blob"].as_str().unwrap()),
                            )
                        })
                        .collect(),
                    guarantees: ext["guarantees"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|g| Guarantee {
                            report: work_report_from_json(&g["report"]),
                            timeslot: g["slot"].as_u64().unwrap() as u32,
                            credentials: g["signatures"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|s| {
                                    (
                                        s["validator_index"].as_u64().unwrap() as u16,
                                        sig64_from_hex(s["signature"].as_str().unwrap()),
                                    )
                                })
                                .collect(),
                        })
                        .collect(),
                    assurances: ext["assurances"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|a| Assurance {
                            anchor: hash_from_hex(a["anchor"].as_str().unwrap()),
                            bitfield: decode_hex(a["bitfield"].as_str().unwrap()),
                            validator_index: a["validator_index"].as_u64().unwrap() as u16,
                            signature: sig64_from_hex(a["signature"].as_str().unwrap()),
                        })
                        .collect(),
                    disputes: disputes_from_json(&ext["disputes"]),
                }
            },
        };

        let encoded = block.encode();
        assert_eq!(encoded, expected.as_slice(), "block encoding mismatch");
    }
}
