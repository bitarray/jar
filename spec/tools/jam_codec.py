"""
Minimal JAM codec encoder for work report hashing.
Used by gen_reports_tests.py to compute report hashes for signature verification.
"""

import hashlib
from typing import Optional


def blake2b_256(data: bytes) -> bytes:
    """Blake2b-256 hash."""
    return hashlib.blake2b(data, digest_size=32).digest()


def encode_compact(value: int) -> bytes:
    """JAM compact/variable-length encoding (eq C.1-C.4)."""
    if value == 0:
        return b'\x00'
    x = value
    # Find len: smallest L in 0..=7 such that x < 2^(7*(L+1))
    ll = 0
    for l in range(8):
        if x < (1 << (7 * (l + 1))):
            ll = l
            break
    else:
        ll = 8

    if ll <= 7:
        threshold = 256 - (1 << (8 - ll))
        header = (threshold & 0xFF) + ((x >> (8 * ll)) & 0xFF)
        buf = bytes([header & 0xFF])
        if ll > 0:
            mask = (1 << (8 * ll)) - 1
            remainder = x & mask
            buf += remainder.to_bytes(ll, 'little')
        return buf
    else:
        # ll == 8: header = 0xFF, 8 bytes LE
        return b'\xff' + x.to_bytes(8, 'little')


def encode_natural(value: int) -> bytes:
    return encode_compact(value)


def encode_u32_le(value: int) -> bytes:
    return value.to_bytes(4, 'little')


def encode_u64_le(value: int) -> bytes:
    return value.to_bytes(8, 'little')


def encode_u16_le(value: int) -> bytes:
    return value.to_bytes(2, 'little')


def encode_hash(h: str) -> bytes:
    """Encode a 32-byte hash from hex string."""
    return bytes.fromhex(h.removeprefix("0x"))


def encode_bytes(data: bytes) -> bytes:
    """Encode a variable-length byte sequence (length-prefixed)."""
    return encode_natural(len(data)) + data


def encode_sequence(items: list, encode_fn) -> bytes:
    """Encode a sequence with length prefix."""
    buf = encode_natural(len(items))
    for item in items:
        buf += encode_fn(item)
    return buf


def encode_availability_spec(spec: dict) -> bytes:
    """Encode AvailabilitySpec (package_spec in JSON)."""
    buf = encode_hash(spec["hash"])          # package_hash: H
    buf += encode_u32_le(spec["length"])     # bundle_length: u32
    buf += encode_hash(spec["erasure_root"]) # erasure_root: H
    buf += encode_hash(spec["exports_root"]) # exports_root: H
    buf += encode_u16_le(spec["exports_count"])  # exports_count: u16
    return buf


def encode_refinement_context(ctx: dict) -> bytes:
    """Encode RefinementContext."""
    buf = encode_hash(ctx["anchor"])         # anchor: H
    buf += encode_hash(ctx["state_root"])    # state_root: H
    buf += encode_hash(ctx["beefy_root"])    # beefy_root: H
    buf += encode_hash(ctx["lookup_anchor"]) # lookup_anchor: H
    buf += encode_u32_le(ctx["lookup_anchor_slot"])  # lookup_anchor_timeslot: u32
    # prerequisites: sequence of hashes
    buf += encode_sequence(ctx["prerequisites"], encode_hash)
    return buf


def encode_work_result(result: dict) -> bytes:
    """Encode WorkResult (discriminated union)."""
    r = result.get("result", result)
    if isinstance(r, dict):
        if "ok" in r:
            data = bytes.fromhex(r["ok"].removeprefix("0x"))
            return b'\x00' + encode_bytes(data)
        elif "err" in r:
            # Error variants
            err = r["err"]
            if err == "out_of_gas":
                return b'\x01'
            elif err == "panic":
                return b'\x02'
            elif err == "bad_exports":
                return b'\x03'
            elif err == "bad_code":
                return b'\x04'
            elif err == "code_oversize":
                return b'\x05'
    # Fallback
    return b'\x00' + encode_bytes(b'')


def encode_work_digest(digest: dict) -> bytes:
    """Encode WorkDigest (WorkResult with RefineLoad)."""
    buf = encode_u32_le(digest["service_id"])        # service_id: u32
    buf += encode_hash(digest["code_hash"])           # code_hash: H
    buf += encode_hash(digest["payload_hash"])        # payload_hash: H
    buf += encode_u64_le(digest["accumulate_gas"])    # accumulate_gas: u64
    buf += encode_work_result(digest)                 # result: WorkResult
    # RefineLoad fields use compact encoding
    rl = digest.get("refine_load", {})
    buf += encode_compact(rl.get("gas_used", 0))
    buf += encode_compact(rl.get("imports", 0))
    buf += encode_compact(rl.get("extrinsic_count", 0))
    buf += encode_compact(rl.get("extrinsic_size", 0))
    buf += encode_compact(rl.get("exports", 0))
    return buf


def encode_segment_root_lookup(lookup: list) -> bytes:
    """Encode segment_root_lookup as sequence of (Hash, Hash) pairs."""
    buf = encode_natural(len(lookup))
    for entry in lookup:
        buf += encode_hash(entry[0])
        buf += encode_hash(entry[1])
    return buf


def encode_work_report(report: dict) -> bytes:
    """Encode a WorkReport per JAM codec."""
    buf = encode_availability_spec(report["package_spec"])
    buf += encode_refinement_context(report["context"])
    buf += encode_compact(report["core_index"])
    buf += encode_hash(report["authorizer_hash"])
    buf += encode_compact(report["auth_gas_used"])
    # auth_output as bytes
    auth_out = bytes.fromhex(report["auth_output"].removeprefix("0x"))
    buf += encode_bytes(auth_out)
    # segment_root_lookup
    srl = report.get("segment_root_lookup", [])
    buf += encode_natural(len(srl))
    for entry in srl:
        if isinstance(entry, dict):
            buf += encode_hash(entry["work_package_hash"])
            buf += encode_hash(entry["segment_tree_root"])
        elif isinstance(entry, (list, tuple)):
            buf += encode_hash(entry[0])
            buf += encode_hash(entry[1])
    # results: sequence of WorkDigest
    buf += encode_sequence(report["results"], encode_work_digest)
    return buf


def work_report_hash(report: dict) -> bytes:
    """Compute blake2b-256 hash of the JAM-encoded work report."""
    encoded = encode_work_report(report)
    return blake2b_256(encoded)
