//! Binary encoding for [`ProgramBlob`].
//!
//! A deliberately dumb little-endian format with no dependencies — not
//! SSZ, not serde. This artifact is a build product consumed by a
//! runtime in the same tree, so it needs neither content-addressing nor
//! a stable cross-ecosystem schema; a personality that wants those
//! wraps the blob in its own encoding.
//!
//! ```text
//!   magic     "NUBP"                                     4
//!   version   u16                                        2
//!   flags     u16 (reserved, must be 0)                   2
//!   stack_pages ro_pages rw_pages heap_pages   u32 x4    16
//!   code_len ro_len rw_len endpoint_count      u32 x4    16
//!   endpoints[endpoint_count]:
//!       key u8 | arg_registers u8 | arg_meta u8 | reg_count u8
//!       entry_pc u64
//!       reg_count x (idx u8 | pad u8 x7 | value u64)
//!   code[code_len] ro[ro_len] rw[rw_len]
//! ```
//!
//! `ro_len`/`rw_len` are the *trailing-zero-trimmed* lengths; decode
//! zero-extends each back to `pages * PAGE_SIZE`. That keeps `.bss`-
//! heavy programs (the 64 KiB guest bump arenas) from paying for their
//! zeros on disk, and is why [`ProgramBlob::new`] normalizes the
//! buffers to whole pages: trim-then-extend then round-trips exactly.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::abi::PAGE_SIZE;
use crate::blob::{Endpoint, InvalidProgram, ProgramBlob, Regions};

/// Format magic: `b"NUBP"`.
pub const MAGIC: [u8; 4] = *b"NUBP";
/// Current format version.
pub const VERSION: u16 = 1;

const HEADER_LEN: usize = 4 + 2 + 2 + 16 + 16;
const ENDPOINT_HEAD_LEN: usize = 4 + 8;
const REG_ENTRY_LEN: usize = 8 + 8;

/// Why a byte slice does not decode to a [`ProgramBlob`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The leading 4 bytes are not [`MAGIC`].
    BadMagic,
    /// Encoded by a newer (or older, incompatible) writer.
    UnsupportedVersion(u16),
    /// A reserved header field was non-zero.
    ReservedFlags(u16),
    /// The input ended mid-field.
    Truncated { need: usize, have: usize },
    /// Two endpoint records claim the same index.
    DuplicateEndpoint(u8),
    /// A trimmed region length exceeds its page count.
    RegionOverflow { len: u32, capacity: usize },
    /// Trailing bytes after the last declared field.
    TrailingBytes(usize),
    /// Decoded successfully but violates a [`ProgramBlob`] invariant.
    Invalid(InvalidProgram),
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodeError::BadMagic => f.write_str("not a nub program blob (bad magic)"),
            DecodeError::UnsupportedVersion(v) => {
                write!(
                    f,
                    "unsupported blob version {v} (this build reads {VERSION})"
                )
            }
            DecodeError::ReservedFlags(v) => {
                write!(f, "reserved flags field is {v:#x}, expected 0")
            }
            DecodeError::Truncated { need, have } => {
                write!(f, "truncated: need {need} bytes, have {have}")
            }
            DecodeError::DuplicateEndpoint(k) => write!(f, "duplicate endpoint index {k}"),
            DecodeError::RegionOverflow { len, capacity } => write!(
                f,
                "region payload {len} bytes exceeds its {capacity}-byte page capacity"
            ),
            DecodeError::TrailingBytes(n) => write!(f, "{n} trailing bytes after the blob"),
            DecodeError::Invalid(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for DecodeError {}

impl From<InvalidProgram> for DecodeError {
    fn from(e: InvalidProgram) -> Self {
        DecodeError::Invalid(e)
    }
}

/// Length of `data` with trailing zero bytes removed.
fn trimmed_len(data: &[u8]) -> usize {
    match data.iter().rposition(|&b| b != 0) {
        Some(i) => i + 1,
        None => 0,
    }
}

/// Cursor over the input that reports how far it got when it runs out.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::Truncated {
            need: usize::MAX,
            have: self.buf.len(),
        })?;
        if end > self.buf.len() {
            return Err(DecodeError::Truncated {
                need: end,
                have: self.buf.len(),
            });
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
}

impl ProgramBlob {
    /// Serialize to the format documented on this module.
    pub fn to_bytes(&self) -> Vec<u8> {
        let ro_len = trimmed_len(&self.ro_data);
        let rw_len = trimmed_len(&self.rw_data);

        let endpoints_len: usize = self
            .endpoints
            .values()
            .map(|e| ENDPOINT_HEAD_LEN + e.initial_regs.len() * REG_ENTRY_LEN)
            .sum();
        let mut out =
            Vec::with_capacity(HEADER_LEN + endpoints_len + self.code.len() + ro_len + rw_len);

        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        for v in [
            self.regions.stack_pages,
            self.regions.ro_pages,
            self.regions.rw_pages,
            self.regions.heap_pages,
        ] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in [
            self.code.len() as u32,
            ro_len as u32,
            rw_len as u32,
            self.endpoints.len() as u32,
        ] {
            out.extend_from_slice(&v.to_le_bytes());
        }

        for (&key, ep) in &self.endpoints {
            out.push(key);
            out.push(ep.arg_registers);
            out.push(ep.arg_meta);
            out.push(ep.initial_regs.len() as u8);
            out.extend_from_slice(&ep.entry_pc.to_le_bytes());
            for (&idx, &value) in &ep.initial_regs {
                out.push(idx);
                out.extend_from_slice(&[0u8; 7]);
                out.extend_from_slice(&value.to_le_bytes());
            }
        }

        out.extend_from_slice(&self.code);
        out.extend_from_slice(&self.ro_data[..ro_len]);
        out.extend_from_slice(&self.rw_data[..rw_len]);
        out
    }

    /// Parse bytes produced by [`ProgramBlob::to_bytes`].
    ///
    /// Rejects trailing bytes: a blob is a whole file, and silently
    /// ignoring a suffix would hide a truncated or concatenated write.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader { buf: bytes, pos: 0 };

        if r.take(4)? != MAGIC {
            return Err(DecodeError::BadMagic);
        }
        let version = r.u16()?;
        if version != VERSION {
            return Err(DecodeError::UnsupportedVersion(version));
        }
        let flags = r.u16()?;
        if flags != 0 {
            return Err(DecodeError::ReservedFlags(flags));
        }

        let regions = Regions {
            stack_pages: r.u32()?,
            ro_pages: r.u32()?,
            rw_pages: r.u32()?,
            heap_pages: r.u32()?,
        };
        let code_len = r.u32()? as usize;
        let ro_len = r.u32()?;
        let rw_len = r.u32()?;
        let endpoint_count = r.u32()?;

        let mut endpoints: BTreeMap<u8, Endpoint> = BTreeMap::new();
        for _ in 0..endpoint_count {
            let key = r.u8()?;
            let arg_registers = r.u8()?;
            let arg_meta = r.u8()?;
            let reg_count = r.u8()?;
            let entry_pc = r.u64()?;
            let mut initial_regs = BTreeMap::new();
            for _ in 0..reg_count {
                let idx = r.u8()?;
                let _pad = r.take(7)?;
                initial_regs.insert(idx, r.u64()?);
            }
            if endpoints
                .insert(
                    key,
                    Endpoint {
                        entry_pc,
                        arg_registers,
                        arg_meta,
                        initial_regs,
                    },
                )
                .is_some()
            {
                return Err(DecodeError::DuplicateEndpoint(key));
            }
        }

        let code = r.take(code_len)?.to_vec();
        let ro_data = read_region(&mut r, ro_len, regions.ro_pages)?;
        let rw_data = read_region(&mut r, rw_len, regions.rw_pages)?;

        if r.pos != bytes.len() {
            return Err(DecodeError::TrailingBytes(bytes.len() - r.pos));
        }

        let blob = ProgramBlob {
            code,
            regions,
            ro_data,
            rw_data,
            endpoints,
        };
        blob.validate()?;
        Ok(blob)
    }
}

/// Read `len` payload bytes and zero-extend to `pages * PAGE_SIZE`.
fn read_region(r: &mut Reader<'_>, len: u32, pages: u32) -> Result<Vec<u8>, DecodeError> {
    let capacity = pages as usize * PAGE_SIZE as usize;
    if len as usize > capacity {
        return Err(DecodeError::RegionOverflow { len, capacity });
    }
    let mut data = r.take(len as usize)?.to_vec();
    data.resize(capacity, 0);
    Ok(data)
}
