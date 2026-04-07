//! Fuzz target: random bytes into Block decode.
//!
//! Verifies that decoding arbitrary bytes as a Block never panics.

#![no_main]

use grey_codec::Decode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = grey_types::header::Block::decode(data);
    let _ = grey_types::header::Header::decode(data);
    let _ = grey_types::header::Extrinsic::decode(data);
});
