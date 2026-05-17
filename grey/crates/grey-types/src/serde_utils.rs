//! Serde helpers for hex-encoded byte types used in test vectors.

/// Deserialize a 0x-prefixed hex string as `Vec<u8>`.
pub fn hex_bytes<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s: String = serde::Deserialize::deserialize(d)?;
    crate::decode_hex(&s).map_err(serde::de::Error::custom)
}

/// Deserialize a 0x-prefixed hex string as [u8; 128] (metadata field).
pub fn hex_metadata<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 128], D::Error> {
    let s: String = serde::Deserialize::deserialize(d)?;
    crate::decode_hex_fixed(&s).map_err(serde::de::Error::custom)
}
