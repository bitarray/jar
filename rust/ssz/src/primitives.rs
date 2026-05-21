//! SSZ blanket impls for built-in scalar and array types.

use allocator_api2::alloc::Allocator;
use allocator_api2::vec::Vec;
use core::num::NonZeroU32;
use digest::Digest;
use digest::typenum::U32;

use crate::merkle::merkleize;
use crate::merkle::pack_bytes;
use crate::union::option_selector_hash;
use crate::{BYTES_PER_LENGTH_OFFSET, Decode, DecodeError, Encode, HashTreeRoot, read_slice};

// --------------------------------------------------------------------------
// Unsigned integers
// --------------------------------------------------------------------------

macro_rules! impl_uint {
    ($t:ty, $size:expr) => {
        impl Encode for $t {
            fn is_ssz_fixed_len() -> bool {
                true
            }
            fn ssz_fixed_len() -> usize {
                $size
            }
            fn is_basic_type() -> bool {
                true
            }
            fn ssz_bytes_len(&self) -> usize {
                $size
            }
            fn ssz_append<A: Allocator + Clone>(&self, buf: &mut Vec<u8, A>) {
                buf.extend_from_slice(&self.to_le_bytes());
            }
        }

        impl Decode for $t {
            fn is_ssz_fixed_len() -> bool {
                true
            }
            fn ssz_fixed_len() -> usize {
                $size
            }
            fn from_ssz_bytes_in<A: Allocator + Clone>(
                bytes: &[u8],
                _alloc: A,
            ) -> Result<Self, DecodeError> {
                if bytes.len() != $size {
                    return Err(DecodeError::UnexpectedEof {
                        expected: $size,
                        actual: bytes.len(),
                    });
                }
                let mut arr = [0u8; $size];
                arr.copy_from_slice(bytes);
                Ok(<$t>::from_le_bytes(arr))
            }
        }

        impl HashTreeRoot for $t {
            fn hash_tree_root<D: Digest<OutputSize = U32>>(&self) -> [u8; 32] {
                let mut chunk = [0u8; 32];
                chunk[..$size].copy_from_slice(&self.to_le_bytes());
                chunk
            }
        }
    };
}

impl_uint!(u8, 1);
impl_uint!(u16, 2);
impl_uint!(u32, 4);
impl_uint!(u64, 8);
impl_uint!(u128, 16);

// --------------------------------------------------------------------------
// bool
// --------------------------------------------------------------------------

impl Encode for bool {
    fn is_ssz_fixed_len() -> bool {
        true
    }
    fn ssz_fixed_len() -> usize {
        1
    }
    fn is_basic_type() -> bool {
        true
    }
    fn ssz_bytes_len(&self) -> usize {
        1
    }
    fn ssz_append<A: Allocator + Clone>(&self, buf: &mut Vec<u8, A>) {
        buf.push(if *self { 1 } else { 0 });
    }
}

impl Decode for bool {
    fn is_ssz_fixed_len() -> bool {
        true
    }
    fn ssz_fixed_len() -> usize {
        1
    }
    fn from_ssz_bytes_in<A: Allocator + Clone>(
        bytes: &[u8],
        _alloc: A,
    ) -> Result<Self, DecodeError> {
        if bytes.len() != 1 {
            return Err(DecodeError::UnexpectedEof {
                expected: 1,
                actual: bytes.len(),
            });
        }
        match bytes[0] {
            0 => Ok(false),
            1 => Ok(true),
            v => Err(DecodeError::InvalidBool(v)),
        }
    }
}

impl HashTreeRoot for bool {
    fn hash_tree_root<D: Digest<OutputSize = U32>>(&self) -> [u8; 32] {
        let mut chunk = [0u8; 32];
        chunk[0] = if *self { 1 } else { 0 };
        chunk
    }
}

// --------------------------------------------------------------------------
// NonZeroU32
// --------------------------------------------------------------------------

impl Encode for NonZeroU32 {
    fn is_ssz_fixed_len() -> bool {
        true
    }
    fn ssz_fixed_len() -> usize {
        4
    }
    fn ssz_bytes_len(&self) -> usize {
        4
    }
    fn ssz_append<A: Allocator + Clone>(&self, buf: &mut Vec<u8, A>) {
        buf.extend_from_slice(&self.get().to_le_bytes());
    }
}

impl Decode for NonZeroU32 {
    fn is_ssz_fixed_len() -> bool {
        true
    }
    fn ssz_fixed_len() -> usize {
        4
    }
    fn from_ssz_bytes_in<A: Allocator + Clone>(
        bytes: &[u8],
        _alloc: A,
    ) -> Result<Self, DecodeError> {
        let raw = u32::from_ssz_bytes_in(bytes, _alloc)?;
        NonZeroU32::new(raw).ok_or(DecodeError::ZeroNonZero)
    }
}

impl HashTreeRoot for NonZeroU32 {
    fn hash_tree_root<D: Digest<OutputSize = U32>>(&self) -> [u8; 32] {
        let mut chunk = [0u8; 32];
        chunk[..4].copy_from_slice(&self.get().to_le_bytes());
        chunk
    }
}

// --------------------------------------------------------------------------
// U256 — 32-byte little-endian unsigned integer wrapper.
// --------------------------------------------------------------------------

/// A 256-bit unsigned integer represented as 32 little-endian bytes.
///
/// SSZ encodes `uint256` as 32 raw LE bytes; the hash tree root is the
/// 32-byte representation itself (single chunk).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct U256(pub [u8; 32]);

impl Encode for U256 {
    fn is_ssz_fixed_len() -> bool {
        true
    }
    fn ssz_fixed_len() -> usize {
        32
    }
    fn ssz_bytes_len(&self) -> usize {
        32
    }
    fn ssz_append<A: Allocator + Clone>(&self, buf: &mut Vec<u8, A>) {
        buf.extend_from_slice(&self.0);
    }
}

impl Decode for U256 {
    fn is_ssz_fixed_len() -> bool {
        true
    }
    fn ssz_fixed_len() -> usize {
        32
    }
    fn from_ssz_bytes_in<A: Allocator + Clone>(
        bytes: &[u8],
        _alloc: A,
    ) -> Result<Self, DecodeError> {
        if bytes.len() != 32 {
            return Err(DecodeError::UnexpectedEof {
                expected: 32,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(U256(arr))
    }
}

impl HashTreeRoot for U256 {
    fn hash_tree_root<D: Digest<OutputSize = U32>>(&self) -> [u8; 32] {
        self.0
    }
}

// --------------------------------------------------------------------------
// Fixed-size byte arrays [u8; N] — SSZ-spec equivalent of a `ByteVector[N]`.
// --------------------------------------------------------------------------

impl<const N: usize> Encode for [u8; N] {
    fn is_ssz_fixed_len() -> bool {
        true
    }
    fn ssz_fixed_len() -> usize {
        N
    }
    fn ssz_bytes_len(&self) -> usize {
        N
    }
    fn ssz_append<A: Allocator + Clone>(&self, buf: &mut Vec<u8, A>) {
        buf.extend_from_slice(self);
    }
}

impl<const N: usize> Decode for [u8; N] {
    fn is_ssz_fixed_len() -> bool {
        true
    }
    fn ssz_fixed_len() -> usize {
        N
    }
    fn from_ssz_bytes_in<A: Allocator + Clone>(
        bytes: &[u8],
        _alloc: A,
    ) -> Result<Self, DecodeError> {
        if bytes.len() != N {
            return Err(DecodeError::UnexpectedEof {
                expected: N,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(bytes);
        Ok(arr)
    }
}

impl<const N: usize> HashTreeRoot for [u8; N] {
    fn hash_tree_root<D: Digest<OutputSize = U32>>(&self) -> [u8; 32] {
        let chunks = pack_bytes(self);
        let limit = N.div_ceil(32).max(1);
        merkleize::<D>(&chunks, limit)
    }
}

// Note: `[T; N]` impls for non-byte T are deferred. Use `FixedVector<T,
// N>` for typed fixed-length arrays. The blanket `[u8; N]` impls above
// cover byte arrays; jar's only non-byte fixed-array usages today
// (e.g. `[Reg; 8]`) live behind newtypes that can use `FixedVector`
// during the Stage-2+ migration.

// --------------------------------------------------------------------------
// Option<T> — SSZ Union form (selector 0 = None, 1 = Some).
// --------------------------------------------------------------------------

impl<T: Encode> Encode for Option<T> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }
    fn ssz_bytes_len(&self) -> usize {
        match self {
            None => 1,
            Some(t) => 1 + t.ssz_bytes_len(),
        }
    }
    fn ssz_append<A: Allocator + Clone>(&self, buf: &mut Vec<u8, A>) {
        match self {
            None => buf.push(0),
            Some(t) => {
                buf.push(1);
                t.ssz_append(buf);
            }
        }
    }
}

impl<T: Decode> Decode for Option<T> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }
    fn from_ssz_bytes_in<A: Allocator + Clone>(
        bytes: &[u8],
        alloc: A,
    ) -> Result<Self, DecodeError> {
        let selector_byte = read_slice(bytes, 0, 1)?[0];
        match selector_byte {
            0 => {
                if bytes.len() != 1 {
                    return Err(DecodeError::TrailingBytes {
                        expected: 1,
                        actual: bytes.len(),
                    });
                }
                Ok(None)
            }
            1 => {
                let inner = T::from_ssz_bytes_in(&bytes[1..], alloc)?;
                Ok(Some(inner))
            }
            v => Err(DecodeError::InvalidSelector(v)),
        }
    }
}

impl<T: HashTreeRoot> HashTreeRoot for Option<T> {
    fn hash_tree_root<D: Digest<OutputSize = U32>>(&self) -> [u8; 32] {
        match self {
            None => option_selector_hash::<D>([0u8; 32], 0),
            Some(t) => option_selector_hash::<D>(t.hash_tree_root::<D>(), 1),
        }
    }
}
