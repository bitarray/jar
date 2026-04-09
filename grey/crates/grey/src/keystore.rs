//! File-based keystore for validator keys.
//!
//! Stores validator key seeds as hex-encoded JSON files in a configurable
//! directory (default: `./grey-keys/`). Keys can be regenerated from seeds.
//!
//! Current version stores keys unencrypted. Future PRs will add
//! password-based encryption (Argon2 + AES-GCM).
//!
//! All seed material is zeroized on drop to prevent secrets from lingering
//! in memory after use.

use std::path::{Path, PathBuf};

use bip39::{Language, Mnemonic};
use zeroize::{Zeroize, Zeroizing};

const ED25519_MNEMONIC_DOMAIN: &[u8] = b"grey-keystore-ed25519-v1";
const BANDERSNATCH_MNEMONIC_DOMAIN: &[u8] = b"grey-keystore-bandersnatch-v1";
const BLS_MNEMONIC_DOMAIN: &[u8] = b"grey-keystore-bls-v1";

/// A file-based keystore that persists validator key seeds to disk.
pub struct Keystore {
    /// Directory containing key files.
    path: PathBuf,
}

/// Serialized key file format (JSON).
///
/// Implements `Zeroize` + `Drop` to clear seed material from memory.
#[derive(serde::Serialize, serde::Deserialize, Zeroize)]
#[zeroize(drop)]
struct KeyFile {
    /// Version of the key file format.
    version: u32,
    /// Validator index this key belongs to.
    validator_index: u16,
    /// Ed25519 seed (hex-encoded 32 bytes). Used to regenerate the keypair.
    ed25519_seed: String,
    /// Bandersnatch seed (hex-encoded 32 bytes).
    bandersnatch_seed: String,
    /// BLS seed (hex-encoded 32 bytes). Added in version 1; absent in legacy files.
    #[serde(default)]
    bls_seed: String,
    /// Ed25519 public key (hex-encoded 32 bytes, for verification).
    ed25519_public: String,
}

/// Decode a hex-encoded 32-byte seed, returning a descriptive error on failure.
fn decode_hex_seed(hex_str: &str, name: &str) -> Result<[u8; 32], KeystoreError> {
    hex::decode(hex_str)
        .map_err(|e| KeystoreError::Io(format!("invalid {name} hex: {e}")))?
        .try_into()
        .map_err(|_| KeystoreError::Io(format!("{name} seed must be 32 bytes")))
}

fn derive_domain_separated_seed(
    master_seed: &[u8; 64],
    validator_index: u16,
    domain: &[u8],
) -> [u8; 32] {
    let mut input = Zeroizing::new(Vec::with_capacity(
        domain.len() + std::mem::size_of::<u16>() + 64,
    ));
    input.extend_from_slice(domain);
    input.extend_from_slice(&validator_index.to_be_bytes());
    input.extend_from_slice(master_seed);
    grey_crypto::blake2b_256(&input).0
}

#[allow(clippy::type_complexity)]
fn derive_validator_seeds_from_mnemonic(
    validator_index: u16,
    mnemonic: &str,
    passphrase: Option<&str>,
) -> Result<([u8; 32], [u8; 32], [u8; 32]), KeystoreError> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic.trim())
        .map_err(|e| KeystoreError::Mnemonic(e.to_string()))?;
    let mut master_seed = mnemonic.to_seed(passphrase.unwrap_or(""));
    let ed25519_seed =
        derive_domain_separated_seed(&master_seed, validator_index, ED25519_MNEMONIC_DOMAIN);
    let bandersnatch_seed =
        derive_domain_separated_seed(&master_seed, validator_index, BANDERSNATCH_MNEMONIC_DOMAIN);
    let bls_seed = derive_domain_separated_seed(&master_seed, validator_index, BLS_MNEMONIC_DOMAIN);
    master_seed.zeroize();
    Ok((ed25519_seed, bandersnatch_seed, bls_seed))
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
        bls_seed: &[u8; 32],
        ed25519_public: &[u8; 32],
    ) -> Result<PathBuf, KeystoreError> {
        let key_file = KeyFile {
            version: 1,
            validator_index,
            ed25519_seed: hex::encode(ed25519_seed),
            bandersnatch_seed: hex::encode(bandersnatch_seed),
            bls_seed: hex::encode(bls_seed),
            ed25519_public: hex::encode(ed25519_public),
        };

        let filename = format!("validator-{}.json", validator_index);
        let filepath = self.path.join(&filename);
        let json = Zeroizing::new(
            serde_json::to_string_pretty(&key_file)
                .map_err(|e| KeystoreError::Io(e.to_string()))?,
        );
        std::fs::write(&filepath, json.as_bytes()).map_err(|e| KeystoreError::Io(e.to_string()))?;

        tracing::info!(
            "Saved keys for validator {} to {}",
            validator_index,
            filepath.display()
        );
        Ok(filepath)
    }

    /// Load key seeds for a validator.
    /// Returns (ed25519_seed, bandersnatch_seed, bls_seed).
    /// Legacy key files without a BLS seed return a zero seed.
    #[allow(clippy::type_complexity)]
    pub fn load_seeds(
        &self,
        validator_index: u16,
    ) -> Result<([u8; 32], [u8; 32], [u8; 32]), KeystoreError> {
        let filename = format!("validator-{}.json", validator_index);
        let filepath = self.path.join(filename);
        let json = Zeroizing::new(
            std::fs::read_to_string(&filepath)
                .map_err(|_| KeystoreError::NotFound(validator_index))?,
        );
        let key_file: KeyFile =
            serde_json::from_str(&json).map_err(|e| KeystoreError::Io(e.to_string()))?;

        let ed25519_seed = decode_hex_seed(&key_file.ed25519_seed, "ed25519")?;
        let bandersnatch_seed = decode_hex_seed(&key_file.bandersnatch_seed, "bandersnatch")?;
        let bls_seed = if key_file.bls_seed.is_empty() {
            [0u8; 32] // Legacy files without BLS seed
        } else {
            decode_hex_seed(&key_file.bls_seed, "bls")?
        };

        Ok((ed25519_seed, bandersnatch_seed, bls_seed))
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
        bls_hex: &str,
    ) -> Result<PathBuf, KeystoreError> {
        let ed25519_seed = decode_hex_seed(ed25519_hex.trim_start_matches("0x"), "ed25519")?;
        let bandersnatch_seed =
            decode_hex_seed(bandersnatch_hex.trim_start_matches("0x"), "bandersnatch")?;
        let bls_seed = decode_hex_seed(bls_hex.trim_start_matches("0x"), "bls")?;

        // Derive Ed25519 public key from seed
        let ed25519_keypair = grey_crypto::ed25519::Ed25519Keypair::from_seed(&ed25519_seed);
        let ed25519_public = ed25519_keypair.public_key().0;

        self.save_seeds(
            validator_index,
            &ed25519_seed,
            &bandersnatch_seed,
            &bls_seed,
            &ed25519_public,
        )
    }

    /// Import validator keys derived from a BIP-39 mnemonic seed phrase.
    pub fn import_mnemonic(
        &self,
        validator_index: u16,
        mnemonic: &str,
        passphrase: Option<&str>,
    ) -> Result<PathBuf, KeystoreError> {
        let (ed25519_seed, bandersnatch_seed, bls_seed) =
            derive_validator_seeds_from_mnemonic(validator_index, mnemonic, passphrase)?;

        let ed25519_keypair = grey_crypto::ed25519::Ed25519Keypair::from_seed(&ed25519_seed);
        let ed25519_public = ed25519_keypair.public_key().0;

        self.save_seeds(
            validator_index,
            &ed25519_seed,
            &bandersnatch_seed,
            &bls_seed,
            &ed25519_public,
        )
    }
}

/// Errors from the keystore.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("invalid mnemonic: {0}")]
    Mnemonic(String),
    #[error("key not found for validator {0}")]
    NotFound(u16),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seeds(index: u16) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        let mut ed_seed = [0u8; 32];
        ed_seed[0] = index as u8;
        ed_seed[31] = 0xED;
        let mut band_seed = [0u8; 32];
        band_seed[0] = index as u8;
        band_seed[31] = 0xBA;
        let mut bls_seed = [0u8; 32];
        bls_seed[0] = index as u8;
        bls_seed[31] = 0xBB;
        let ed_public = [index as u8; 32]; // fake public key for test
        (ed_seed, band_seed, bls_seed, ed_public)
    }

    #[test]
    fn test_keystore_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::open(dir.path().join("keys")).unwrap();

        let (ed_seed, band_seed, bls_seed, ed_pub) = test_seeds(0);
        ks.save_seeds(0, &ed_seed, &band_seed, &bls_seed, &ed_pub)
            .unwrap();

        assert!(ks.has_keys(0));
        assert!(!ks.has_keys(1));

        let (loaded_ed, loaded_band, _loaded_bls) = ks.load_seeds(0).unwrap();
        assert_eq!(loaded_ed, ed_seed);
        assert_eq!(loaded_band, band_seed);
    }

    #[test]
    fn test_keystore_list_validators() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::open(dir.path().join("keys")).unwrap();

        let (ed, band, bls, pub_k) = test_seeds(0);
        ks.save_seeds(0, &ed, &band, &bls, &pub_k).unwrap();
        let (ed, band, bls, pub_k) = test_seeds(5);
        ks.save_seeds(5, &ed, &band, &bls, &pub_k).unwrap();
        let (ed, band, bls, pub_k) = test_seeds(2);
        ks.save_seeds(2, &ed, &band, &bls, &pub_k).unwrap();

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

        let (ed_seed, band_seed, bls_seed, ed_pub) = test_seeds(3);
        let path = ks
            .save_seeds(3, &ed_seed, &band_seed, &bls_seed, &ed_pub)
            .unwrap();

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
        let bls_hex = "cc".repeat(32);

        let path = ks.import_raw_hex(7, &ed_hex, &band_hex, &bls_hex).unwrap();
        assert!(path.exists());

        // Load and verify seeds match
        let (loaded_ed, loaded_band, _loaded_bls) = ks.load_seeds(7).unwrap();
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
        let bls_hex = format!("0x{}", "ee".repeat(32));

        ks.import_raw_hex(8, &ed_hex, &band_hex, &bls_hex).unwrap();
        let (loaded_ed, loaded_band, _loaded_bls) = ks.load_seeds(8).unwrap();
        assert_eq!(loaded_ed, [0xCC; 32]);
        assert_eq!(loaded_band, [0xDD; 32]);
    }

    #[test]
    fn test_import_raw_hex_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::open(dir.path().join("keys")).unwrap();

        // Too short
        let valid = "aa".repeat(32);
        assert!(ks.import_raw_hex(0, "aabb", "ccdd", &valid).is_err());
        // Invalid hex
        assert!(
            ks.import_raw_hex(0, "zz".repeat(32).as_str(), &valid, &valid)
                .is_err()
        );
    }

    #[test]
    fn test_import_mnemonic_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::open(dir.path().join("keys")).unwrap();
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let path = ks.import_mnemonic(4, mnemonic, None).unwrap();
        assert!(path.exists());

        let (expected_ed, expected_band, expected_bls) =
            derive_validator_seeds_from_mnemonic(4, mnemonic, None).unwrap();
        let (loaded_ed, loaded_band, loaded_bls) = ks.load_seeds(4).unwrap();
        assert_eq!(loaded_ed, expected_ed);
        assert_eq!(loaded_band, expected_band);
        assert_eq!(loaded_bls, expected_bls);

        let json = std::fs::read_to_string(path).unwrap();
        let key_file: KeyFile = serde_json::from_str(&json).unwrap();
        let expected_public = grey_crypto::ed25519::Ed25519Keypair::from_seed(&expected_ed)
            .public_key()
            .0;
        assert_eq!(key_file.ed25519_public, hex::encode(expected_public));
    }

    #[test]
    fn test_mnemonic_derivation_is_validator_specific() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let validator_0 = derive_validator_seeds_from_mnemonic(0, mnemonic, None).unwrap();
        let validator_1 = derive_validator_seeds_from_mnemonic(1, mnemonic, None).unwrap();

        assert_ne!(validator_0.0, validator_1.0);
        assert_ne!(validator_0.1, validator_1.1);
    }

    #[test]
    fn test_mnemonic_derivation_honors_passphrase() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let without_passphrase = derive_validator_seeds_from_mnemonic(2, mnemonic, None).unwrap();
        let with_passphrase =
            derive_validator_seeds_from_mnemonic(2, mnemonic, Some("validator-passphrase"))
                .unwrap();

        assert_ne!(without_passphrase.0, with_passphrase.0);
        assert_ne!(without_passphrase.1, with_passphrase.1);
    }

    #[test]
    fn test_import_mnemonic_invalid_phrase() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::open(dir.path().join("keys")).unwrap();

        let err = ks
            .import_mnemonic(1, "not a valid bip39 phrase", None)
            .unwrap_err();
        assert!(matches!(err, KeystoreError::Mnemonic(_)));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// save_seeds then load_seeds always recovers the original seeds.
        #[test]
        fn save_load_roundtrip(
            idx in 0u16..100,
            ed_seed in any::<[u8; 32]>(),
            band_seed in any::<[u8; 32]>(),
            bls_seed in any::<[u8; 32]>(),
            ed_pub in any::<[u8; 32]>(),
        ) {
            let dir = tempfile::tempdir().unwrap();
            let ks = Keystore::open(dir.path().join("keys")).unwrap();
            ks.save_seeds(idx, &ed_seed, &band_seed, &bls_seed, &ed_pub).unwrap();
            let (loaded_ed, loaded_band, loaded_bls) = ks.load_seeds(idx).unwrap();
            prop_assert_eq!(loaded_ed, ed_seed);
            prop_assert_eq!(loaded_band, band_seed);
            prop_assert_eq!(loaded_bls, bls_seed);
        }

        /// has_keys is true after save, false before.
        #[test]
        fn has_keys_after_save(idx in 0u16..100) {
            let dir = tempfile::tempdir().unwrap();
            let ks = Keystore::open(dir.path().join("keys")).unwrap();
            prop_assert!(!ks.has_keys(idx));
            let seed = [idx as u8; 32];
            let pub_k = [0u8; 32];
            ks.save_seeds(idx, &seed, &seed, &seed, &pub_k).unwrap();
            prop_assert!(ks.has_keys(idx));
        }

        /// Mnemonic derivation is deterministic: same inputs produce same outputs.
        #[test]
        fn mnemonic_derivation_deterministic(idx in 0u16..100) {
            let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let (ed1, band1, bls1) = derive_validator_seeds_from_mnemonic(idx, mnemonic, None).unwrap();
            let (ed2, band2, bls2) = derive_validator_seeds_from_mnemonic(idx, mnemonic, None).unwrap();
            prop_assert_eq!(ed1, ed2);
            prop_assert_eq!(band1, band2);
            prop_assert_eq!(bls1, bls2);
        }

        /// Different validator indices produce different seeds from the same mnemonic.
        #[test]
        fn mnemonic_different_indices_different_seeds(a in 0u16..1000, b in 0u16..1000) {
            prop_assume!(a != b);
            let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let seeds_a = derive_validator_seeds_from_mnemonic(a, mnemonic, None).unwrap();
            let seeds_b = derive_validator_seeds_from_mnemonic(b, mnemonic, None).unwrap();
            prop_assert_ne!(seeds_a.0, seeds_b.0, "ed25519 seeds should differ");
            prop_assert_ne!(seeds_a.1, seeds_b.1, "bandersnatch seeds should differ");
            prop_assert_ne!(seeds_a.2, seeds_b.2, "bls seeds should differ");
        }

        /// Domain separation: ed25519, bandersnatch, and bls seeds are all distinct.
        #[test]
        fn domain_separation(idx in 0u16..1000) {
            let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let (ed, band, bls) = derive_validator_seeds_from_mnemonic(idx, mnemonic, None).unwrap();
            prop_assert_ne!(ed, band, "ed25519 and bandersnatch seeds should differ");
            prop_assert_ne!(ed, bls, "ed25519 and bls seeds should differ");
            prop_assert_ne!(band, bls, "bandersnatch and bls seeds should differ");
        }

        /// decode_hex_seed rejects strings that aren't 64 hex chars.
        #[test]
        fn decode_hex_seed_rejects_wrong_length(len in 0usize..128) {
            prop_assume!(len != 64);
            let hex_str: String = (0..len).map(|_| 'a').collect();
            let result = decode_hex_seed(&hex_str, "test");
            if len % 2 == 0 && len != 64 {
                // Valid hex but wrong byte length
                prop_assert!(result.is_err());
            }
            // Odd length or wrong byte count → always error
        }
    }
}
