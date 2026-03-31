//! File-based keystore for validator keys.
//!
//! Stores validator key seeds as hex-encoded JSON files in a configurable
//! directory (default: `./grey-keys/`). Keys can be regenerated from seeds.
//!
//! Current version stores keys unencrypted. Future PRs will add
//! password-based encryption (Argon2 + AES-GCM).

use std::path::{Path, PathBuf};

/// A file-based keystore that persists validator key seeds to disk.
pub struct Keystore {
    /// Directory containing key files.
    path: PathBuf,
}

/// Serialized key file format (JSON).
#[derive(serde::Serialize, serde::Deserialize)]
struct KeyFile {
    /// Version of the key file format.
    version: u32,
    /// Validator index this key belongs to.
    validator_index: u16,
    /// Ed25519 seed (hex-encoded 32 bytes). Used to regenerate the keypair.
    ed25519_seed: String,
    /// Bandersnatch seed (hex-encoded 32 bytes).
    bandersnatch_seed: String,
    /// Ed25519 public key (hex-encoded 32 bytes, for verification).
    ed25519_public: String,
}

impl Keystore {
    /// Open or create a keystore at the given directory.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, KeystoreError> {
        let path = path.as_ref().to_path_buf();
        std::fs::create_dir_all(&path).map_err(|e| KeystoreError::Io(e.to_string()))?;
        Ok(Self { path })
    }

    /// Save validator key seeds to the keystore.
    pub fn save_seeds(
        &self,
        validator_index: u16,
        ed25519_seed: &[u8; 32],
        bandersnatch_seed: &[u8; 32],
        ed25519_public: &[u8; 32],
    ) -> Result<PathBuf, KeystoreError> {
        let key_file = KeyFile {
            version: 1,
            validator_index,
            ed25519_seed: hex::encode(ed25519_seed),
            bandersnatch_seed: hex::encode(bandersnatch_seed),
            ed25519_public: hex::encode(ed25519_public),
        };

        let filename = format!("validator-{}.json", validator_index);
        let filepath = self.path.join(&filename);
        let json = serde_json::to_string_pretty(&key_file)
            .map_err(|e| KeystoreError::Io(e.to_string()))?;
        std::fs::write(&filepath, json).map_err(|e| KeystoreError::Io(e.to_string()))?;

        tracing::info!(
            "Saved keys for validator {} to {}",
            validator_index,
            filepath.display()
        );
        Ok(filepath)
    }

    /// Load key seeds for a validator.
    pub fn load_seeds(&self, validator_index: u16) -> Result<([u8; 32], [u8; 32]), KeystoreError> {
        let filename = format!("validator-{}.json", validator_index);
        let filepath = self.path.join(filename);
        let json = std::fs::read_to_string(&filepath)
            .map_err(|_| KeystoreError::NotFound(validator_index))?;
        let key_file: KeyFile =
            serde_json::from_str(&json).map_err(|e| KeystoreError::Io(e.to_string()))?;

        let ed25519_seed: [u8; 32] = hex::decode(&key_file.ed25519_seed)
            .map_err(|e| KeystoreError::Io(e.to_string()))?
            .try_into()
            .map_err(|_| KeystoreError::Io("invalid ed25519 seed length".into()))?;

        let bandersnatch_seed: [u8; 32] = hex::decode(&key_file.bandersnatch_seed)
            .map_err(|e| KeystoreError::Io(e.to_string()))?
            .try_into()
            .map_err(|_| KeystoreError::Io("invalid bandersnatch seed length".into()))?;

        Ok((ed25519_seed, bandersnatch_seed))
    }

    /// Check if keys exist for a validator index.
    pub fn has_keys(&self, validator_index: u16) -> bool {
        let filename = format!("validator-{}.json", validator_index);
        self.path.join(filename).exists()
    }

    /// List all validator indices with stored keys.
    pub fn list_validators(&self) -> Result<Vec<u16>, KeystoreError> {
        let mut indices = Vec::new();
        let entries =
            std::fs::read_dir(&self.path).map_err(|e| KeystoreError::Io(e.to_string()))?;
        for entry in entries {
            let entry = entry.map_err(|e| KeystoreError::Io(e.to_string()))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(rest) = name.strip_prefix("validator-")
                && let Some(idx_str) = rest.strip_suffix(".json")
                && let Ok(idx) = idx_str.parse::<u16>()
            {
                indices.push(idx);
            }
        }
        indices.sort();
        Ok(indices)
    }

    /// Return the keystore directory path.
    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Import a key from raw hex-encoded seeds.
    ///
    /// `ed25519_hex` and `bandersnatch_hex` should be 64-character hex strings
    /// (32 bytes each). The Ed25519 public key is derived from the seed.
    pub fn import_raw_hex(
        &self,
        validator_index: u16,
        ed25519_hex: &str,
        bandersnatch_hex: &str,
    ) -> Result<PathBuf, KeystoreError> {
        let ed25519_seed: [u8; 32] = hex::decode(ed25519_hex.trim_start_matches("0x"))
            .map_err(|e| KeystoreError::Io(format!("invalid ed25519 hex: {e}")))?
            .try_into()
            .map_err(|_| KeystoreError::Io("ed25519 seed must be 32 bytes".into()))?;

        let bandersnatch_seed: [u8; 32] = hex::decode(bandersnatch_hex.trim_start_matches("0x"))
            .map_err(|e| KeystoreError::Io(format!("invalid bandersnatch hex: {e}")))?
            .try_into()
            .map_err(|_| KeystoreError::Io("bandersnatch seed must be 32 bytes".into()))?;

        // Derive Ed25519 public key from seed
        let ed25519_keypair = grey_crypto::ed25519::Ed25519Keypair::from_seed(&ed25519_seed);
        let ed25519_public = ed25519_keypair.public_key().0;

        self.save_seeds(
            validator_index,
            &ed25519_seed,
            &bandersnatch_seed,
            &ed25519_public,
        )
    }
}

/// Errors from the keystore.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("key not found for validator {0}")]
    NotFound(u16),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seeds(index: u16) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let mut ed_seed = [0u8; 32];
        ed_seed[0] = index as u8;
        ed_seed[31] = 0xED;
        let mut band_seed = [0u8; 32];
        band_seed[0] = index as u8;
        band_seed[31] = 0xBA;
        let ed_public = [index as u8; 32]; // fake public key for test
        (ed_seed, band_seed, ed_public)
    }

    #[test]
    fn test_keystore_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::open(dir.path().join("keys")).unwrap();

        let (ed_seed, band_seed, ed_pub) = test_seeds(0);
        ks.save_seeds(0, &ed_seed, &band_seed, &ed_pub).unwrap();

        assert!(ks.has_keys(0));
        assert!(!ks.has_keys(1));

        let (loaded_ed, loaded_band) = ks.load_seeds(0).unwrap();
        assert_eq!(loaded_ed, ed_seed);
        assert_eq!(loaded_band, band_seed);
    }

    #[test]
    fn test_keystore_list_validators() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::open(dir.path().join("keys")).unwrap();

        let (ed, band, pub_k) = test_seeds(0);
        ks.save_seeds(0, &ed, &band, &pub_k).unwrap();
        let (ed, band, pub_k) = test_seeds(5);
        ks.save_seeds(5, &ed, &band, &pub_k).unwrap();
        let (ed, band, pub_k) = test_seeds(2);
        ks.save_seeds(2, &ed, &band, &pub_k).unwrap();

        let validators = ks.list_validators().unwrap();
        assert_eq!(validators, vec![0, 2, 5]);
    }

    #[test]
    fn test_keystore_load_nonexistent() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::open(dir.path().join("keys")).unwrap();
        assert!(ks.load_seeds(99).is_err());
    }

    #[test]
    fn test_keystore_file_format() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::open(dir.path().join("keys")).unwrap();

        let (ed_seed, band_seed, ed_pub) = test_seeds(3);
        let path = ks.save_seeds(3, &ed_seed, &band_seed, &ed_pub).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let key_file: KeyFile = serde_json::from_str(&content).unwrap();
        assert_eq!(key_file.version, 1);
        assert_eq!(key_file.validator_index, 3);
        assert_eq!(key_file.ed25519_seed.len(), 64);
        assert_eq!(key_file.bandersnatch_seed.len(), 64);
        assert_eq!(key_file.ed25519_public.len(), 64);
    }

    #[test]
    fn test_import_raw_hex() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::open(dir.path().join("keys")).unwrap();

        let ed_hex = "aa".repeat(32); // 64 hex chars = 32 bytes
        let band_hex = "bb".repeat(32);

        let path = ks.import_raw_hex(7, &ed_hex, &band_hex).unwrap();
        assert!(path.exists());

        // Load and verify seeds match
        let (loaded_ed, loaded_band) = ks.load_seeds(7).unwrap();
        assert_eq!(loaded_ed, [0xAA; 32]);
        assert_eq!(loaded_band, [0xBB; 32]);

        // Verify public key was derived (not zero)
        let json = std::fs::read_to_string(&path).unwrap();
        let key_file: KeyFile = serde_json::from_str(&json).unwrap();
        assert_ne!(key_file.ed25519_public, "00".repeat(32));
    }

    #[test]
    fn test_import_raw_hex_with_0x_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::open(dir.path().join("keys")).unwrap();

        let ed_hex = format!("0x{}", "cc".repeat(32));
        let band_hex = format!("0x{}", "dd".repeat(32));

        ks.import_raw_hex(8, &ed_hex, &band_hex).unwrap();
        let (loaded_ed, loaded_band) = ks.load_seeds(8).unwrap();
        assert_eq!(loaded_ed, [0xCC; 32]);
        assert_eq!(loaded_band, [0xDD; 32]);
    }

    #[test]
    fn test_import_raw_hex_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::open(dir.path().join("keys")).unwrap();

        // Too short
        assert!(ks.import_raw_hex(0, "aabb", "ccdd").is_err());
        // Invalid hex
        assert!(
            ks.import_raw_hex(0, "zz".repeat(32).as_str(), "aa".repeat(32).as_str())
                .is_err()
        );
    }
}
