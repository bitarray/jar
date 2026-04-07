//! Fuzz target: random bytes into codec Decode implementations.
//!
//! Verifies that no input causes a panic during decoding.
//! Expected results: Ok(value) or Err — never a panic or UB.

#![no_main]

use grey_codec::Decode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try decoding as various fixed-size types
    let _ = u8::decode(data);
    let _ = u16::decode(data);
    let _ = u32::decode(data);
    let _ = u64::decode(data);

    // Try decoding as Hash (32 bytes)
    let _ = grey_types::Hash::decode(data);

    // Try decoding as Ed25519Signature (64 bytes)
    let _ = grey_types::Ed25519Signature::decode(data);

    // Try decoding as BandersnatchSignature (96 bytes)
    let _ = grey_types::BandersnatchSignature::decode(data);
});
