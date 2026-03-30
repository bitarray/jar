//! Persistent storage for Grey node.
//!
//! Uses `redb` as the embedded database backend. Stores:
//! - Blocks keyed by header hash
//! - Block hash index by timeslot
//! - Chain state (as state_serial KV pairs) keyed by block hash
//! - Metadata (head block, finalized block)
//! - DA chunks keyed by (report_hash, chunk_index)

use grey_codec::header_codec;
use grey_types::Hash;
use grey_types::config::Config;
use grey_types::header::Block;
use grey_types::state::State;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::path::Path;

/// Current schema version. Bump this when table layouts change.
/// The store refuses to open a database with a different version.
pub const SCHEMA_VERSION: u32 = 1;

/// Errors from the store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Db(#[from] redb::DatabaseError),
    #[error("storage error: {0}")]
    Storage(#[from] redb::StorageError),
    #[error("table error: {0}")]
    Table(#[from] redb::TableError),
    #[error("transaction error: {0}")]
    Transaction(#[from] redb::TransactionError),
    #[error("commit error: {0}")]
    Commit(#[from] redb::CommitError),
    #[error("codec error: {0}")]
    Codec(String),
    #[error("not found")]
    NotFound,
    #[error("incompatible schema version: database has v{found}, expected v{expected}")]
    IncompatibleSchema { found: u32, expected: u32 },
    #[error("state integrity check failed for block 0x{}: stored checksum {stored}, computed {computed}", hex::encode(.block_hash))]
    IntegrityError {
        block_hash: [u8; 32],
        stored: String,
        computed: String,
    },
}

// Table definitions
// Blocks: block_hash (32 bytes) -> encoded block bytes
const BLOCKS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("blocks");
// Slot index: timeslot (u32 as 4 LE bytes) -> block_hash (32 bytes)
const SLOT_INDEX: TableDefinition<u32, &[u8; 32]> = TableDefinition::new("slot_index");
// State: block_hash (32 bytes) -> state KV pairs (serialized)
const STATE: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("state");
// Metadata: key string -> value bytes
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
// DA chunks: (report_hash ++ chunk_index as u16 LE) = 34 bytes -> chunk data
const CHUNKS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("chunks");
// State checksums: block_hash (32 bytes) -> blake2b_256 hash of the encoded state blob (32 bytes)
const STATE_CHECKSUMS: TableDefinition<&[u8; 32], &[u8; 32]> =
    TableDefinition::new("state_checksums");

const META_SCHEMA_VERSION: &str = "schema_version";
const META_HEAD_HASH: &str = "head_hash";
const META_HEAD_SLOT: &str = "head_slot";
const META_FINALIZED_HASH: &str = "finalized_hash";
const META_FINALIZED_SLOT: &str = "finalized_slot";

/// Service account metadata (fixed-size header fields from the C(255, service_id) KV).
/// Does not include storage, preimage_lookup, or preimage_info dictionaries.
#[derive(Debug, Clone)]
pub struct ServiceMetadata {
    pub code_hash: Hash,
    pub balance: u64,
    pub min_accumulate_gas: u64,
    pub min_on_transfer_gas: u64,
    pub total_footprint: u64,
    pub free_storage_offset: u64,
    pub accumulation_counter: u32,
    pub last_accumulation: u32,
    pub last_activity: u32,
    pub preimage_count: u32,
}

/// Persistent store backed by redb.
pub struct Store {
    db: Database,
}

impl Store {
    /// Open or create a store at the given path.
    ///
    /// On first open (no schema version in META), writes the current
    /// [`SCHEMA_VERSION`]. On subsequent opens, verifies the stored version
    /// matches and returns [`StoreError::IncompatibleSchema`] if not.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let db = Database::create(path.as_ref())?;

        // Create tables if they don't exist
        let txn = db.begin_write()?;
        {
            let _ = txn.open_table(BLOCKS)?;
            let _ = txn.open_table(SLOT_INDEX)?;
            let _ = txn.open_table(STATE)?;
            let mut meta = txn.open_table(META)?;
            let _ = txn.open_table(CHUNKS)?;
            let _ = txn.open_table(STATE_CHECKSUMS)?;

            // Check or initialize schema version.
            // Read first, drop the guard, then write if needed.
            let stored_version = meta.get(META_SCHEMA_VERSION)?.and_then(|val| {
                let bytes = val.value();
                if bytes.len() == 4 {
                    Some(u32::from_le_bytes(bytes.try_into().unwrap()))
                } else {
                    None
                }
            });

            match stored_version {
                Some(v) if v != SCHEMA_VERSION => {
                    return Err(StoreError::IncompatibleSchema {
                        found: v,
                        expected: SCHEMA_VERSION,
                    });
                }
                None => {
                    meta.insert(META_SCHEMA_VERSION, SCHEMA_VERSION.to_le_bytes().as_slice())?;
                }
                Some(_) => {} // version matches, proceed
            }
        }
        txn.commit()?;

        Ok(Self { db })
    }

    /// Return the schema version stored in the database.
    pub fn schema_version(&self) -> Result<u32, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(META)?;
        match table.get(META_SCHEMA_VERSION)? {
            Some(val) => {
                let bytes = val.value();
                if bytes.len() == 4 {
                    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
                } else {
                    Err(StoreError::Codec("invalid schema version bytes".into()))
                }
            }
            None => Err(StoreError::NotFound),
        }
    }

    // ── Blocks ──────────────────────────────────────────────────────────

    /// Store a block. Returns the header hash.
    pub fn put_block(&self, block: &Block) -> Result<Hash, StoreError> {
        let encoded = encode_block(block);
        let hash = header_codec::compute_header_hash(&block.header);

        let txn = self.db.begin_write()?;
        {
            let mut blocks = txn.open_table(BLOCKS)?;
            blocks.insert(&hash.0, encoded.as_slice())?;

            let mut idx = txn.open_table(SLOT_INDEX)?;
            idx.insert(block.header.timeslot, &hash.0)?;
        }
        txn.commit()?;
        Ok(hash)
    }

    /// Get a block by its header hash.
    pub fn get_block(&self, hash: &Hash) -> Result<Block, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BLOCKS)?;
        let val = table.get(&hash.0)?.ok_or(StoreError::NotFound)?;
        decode_block(val.value()).ok_or_else(|| StoreError::Codec("invalid block".into()))
    }

    /// Get a block hash by timeslot.
    pub fn get_block_hash_by_slot(&self, slot: u32) -> Result<Hash, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(SLOT_INDEX)?;
        let val = table.get(slot)?.ok_or(StoreError::NotFound)?;
        Ok(Hash(*val.value()))
    }

    /// Check if a block exists.
    pub fn has_block(&self, hash: &Hash) -> Result<bool, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BLOCKS)?;
        Ok(table.get(&hash.0)?.is_some())
    }

    // ── State ───────────────────────────────────────────────────────────

    /// Store chain state for a given block hash.
    pub fn put_state(
        &self,
        block_hash: &Hash,
        state: &State,
        config: &Config,
    ) -> Result<(), StoreError> {
        let kvs = grey_merkle::state_serial::serialize_state(state, config);
        let encoded = encode_state_kvs(&kvs);
        let checksum = grey_crypto::blake2b_256(&encoded);

        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(STATE)?;
            table.insert(&block_hash.0, encoded.as_slice())?;
            let mut checksums = txn.open_table(STATE_CHECKSUMS)?;
            checksums.insert(&block_hash.0, &checksum.0)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Load chain state for a given block hash.
    pub fn get_state(&self, block_hash: &Hash, config: &Config) -> Result<State, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(STATE)?;
        let val = table.get(&block_hash.0)?.ok_or(StoreError::NotFound)?;
        let kvs = decode_state_kvs(val.value())
            .ok_or_else(|| StoreError::Codec("invalid state KVs".into()))?;
        let (state, _opaque) = grey_merkle::state_serial::deserialize_state(&kvs, config)
            .map_err(StoreError::Codec)?;
        Ok(state)
    }

    /// Verify the integrity of stored state data for a block.
    ///
    /// Recomputes the blake2b_256 hash of the state blob and compares it against
    /// the stored checksum. Returns `Ok(true)` if the checksum matches,
    /// `Ok(false)` if no checksum was stored (pre-checksum data), and
    /// `Err(IntegrityError)` if the checksum does not match.
    pub fn verify_state_integrity(&self, block_hash: &Hash) -> Result<bool, StoreError> {
        let txn = self.db.begin_read()?;

        // Read the state blob
        let state_table = txn.open_table(STATE)?;
        let state_val = state_table
            .get(&block_hash.0)?
            .ok_or(StoreError::NotFound)?;
        let state_bytes = state_val.value();

        // Read the stored checksum
        let checksum_table = txn.open_table(STATE_CHECKSUMS)?;
        let stored = match checksum_table.get(&block_hash.0)? {
            Some(val) => *val.value(),
            None => return Ok(false), // no checksum stored (legacy data)
        };

        // Recompute and compare
        let computed = grey_crypto::blake2b_256(state_bytes);
        if stored != computed.0 {
            return Err(StoreError::IntegrityError {
                block_hash: block_hash.0,
                stored: hex::encode(stored),
                computed: hex::encode(computed.0),
            });
        }

        Ok(true)
    }

    /// Look up a specific service storage entry by computing the expected state key.
    /// Returns None if the entry doesn't exist.
    pub fn get_service_storage(
        &self,
        block_hash: &Hash,
        service_id: u32,
        storage_key: &[u8],
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(STATE)?;
        let val = table.get(&block_hash.0)?.ok_or(StoreError::NotFound)?;
        let kvs = decode_state_kvs(val.value())
            .ok_or_else(|| StoreError::Codec("invalid state KVs".into()))?;

        let expected_key =
            grey_merkle::state_serial::compute_storage_state_key(service_id, storage_key);
        for (key, value) in &kvs {
            if *key == expected_key {
                return Ok(Some(value.clone()));
            }
        }
        Ok(None)
    }

    /// Look up a service account's code hash directly from state KVs.
    /// The service metadata is at key C(255, service_id), and code_hash is bytes [1..33].
    pub fn get_service_code_hash(
        &self,
        block_hash: &Hash,
        service_id: u32,
    ) -> Result<Option<Hash>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(STATE)?;
        let val = table.get(&block_hash.0)?.ok_or(StoreError::NotFound)?;
        let kvs = decode_state_kvs(val.value())
            .ok_or_else(|| StoreError::Codec("invalid state KVs".into()))?;

        let expected_key = grey_merkle::state_serial::key_for_service_pub(255, service_id);
        for (key, value) in &kvs {
            if *key == expected_key {
                // Service account: version(1) + code_hash(32) + ...
                if value.len() >= 33 {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&value[1..33]);
                    return Ok(Some(Hash(h)));
                }
                return Ok(None);
            }
        }
        Ok(None)
    }

    /// Look up a service account's metadata (all fixed-size header fields).
    /// The service metadata is at key C(255, service_id).
    /// Layout: version(1) + code_hash(32) + balance(8) + min_accumulate_gas(8) +
    ///         min_on_transfer_gas(8) + total_footprint(8) + free_storage_offset(8) +
    ///         accumulation_counter(4) + last_accumulation(4) + last_activity(4) +
    ///         preimage_count(4) = 89 bytes minimum.
    pub fn get_service_metadata(
        &self,
        block_hash: &Hash,
        service_id: u32,
    ) -> Result<Option<ServiceMetadata>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(STATE)?;
        let val = table.get(&block_hash.0)?.ok_or(StoreError::NotFound)?;
        let kvs = decode_state_kvs(val.value())
            .ok_or_else(|| StoreError::Codec("invalid state KVs".into()))?;

        let expected_key = grey_merkle::state_serial::key_for_service_pub(255, service_id);
        for (key, value) in &kvs {
            if *key == expected_key {
                if value.len() < 89 {
                    return Err(StoreError::Codec(format!(
                        "service metadata too short: {} bytes (need 89)",
                        value.len()
                    )));
                }
                let v = value;
                let mut pos = 1; // skip version byte
                let mut code_hash = [0u8; 32];
                code_hash.copy_from_slice(&v[pos..pos + 32]);
                pos += 32;
                let balance = u64::from_le_bytes(v[pos..pos + 8].try_into().unwrap());
                pos += 8;
                let min_accumulate_gas = u64::from_le_bytes(v[pos..pos + 8].try_into().unwrap());
                pos += 8;
                let min_on_transfer_gas = u64::from_le_bytes(v[pos..pos + 8].try_into().unwrap());
                pos += 8;
                let total_footprint = u64::from_le_bytes(v[pos..pos + 8].try_into().unwrap());
                pos += 8;
                let free_storage_offset = u64::from_le_bytes(v[pos..pos + 8].try_into().unwrap());
                pos += 8;
                let accumulation_counter = u32::from_le_bytes(v[pos..pos + 4].try_into().unwrap());
                pos += 4;
                let last_accumulation = u32::from_le_bytes(v[pos..pos + 4].try_into().unwrap());
                pos += 4;
                let last_activity = u32::from_le_bytes(v[pos..pos + 4].try_into().unwrap());
                pos += 4;
                let preimage_count = u32::from_le_bytes(v[pos..pos + 4].try_into().unwrap());

                return Ok(Some(ServiceMetadata {
                    code_hash: Hash(code_hash),
                    balance,
                    min_accumulate_gas,
                    min_on_transfer_gas,
                    total_footprint,
                    free_storage_offset,
                    accumulation_counter,
                    last_accumulation,
                    last_activity,
                    preimage_count,
                }));
            }
        }
        Ok(None)
    }

    /// Look up a raw state KV by key from state KVs.
    pub fn get_state_kv(
        &self,
        block_hash: &Hash,
        state_key: &[u8; 31],
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(STATE)?;
        let val = table.get(&block_hash.0)?.ok_or(StoreError::NotFound)?;
        let kvs = decode_state_kvs(val.value())
            .ok_or_else(|| StoreError::Codec("invalid state KVs".into()))?;

        for (key, value) in &kvs {
            if key == state_key {
                return Ok(Some(value.clone()));
            }
        }
        Ok(None)
    }

    /// Get the accumulation root (beefy_root) for a given anchor block.
    /// Reads only the C(3) state KV (recent_blocks) and scans for the matching
    /// header entry, avoiding full state deserialization.
    pub fn get_accumulation_root(
        &self,
        block_hash: &Hash,
        anchor_hash: &Hash,
    ) -> Result<Option<Hash>, StoreError> {
        let key = grey_merkle::state_serial::key_for_component(3);
        let blob = match self.get_state_kv(block_hash, &key)? {
            Some(blob) => blob,
            None => return Ok(None),
        };
        grey_merkle::state_serial::extract_accumulation_root(&blob, anchor_hash)
            .map_err(StoreError::Codec)
    }

    /// Delete state for a given block hash (for pruning).
    pub fn delete_state(&self, block_hash: &Hash) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(STATE)?;
            table.remove(&block_hash.0)?;
        }
        txn.commit()?;
        Ok(())
    }

    // ── Metadata ────────────────────────────────────────────────────────

    /// Set head block (best/latest block).
    pub fn set_head(&self, hash: &Hash, slot: u32) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut meta = txn.open_table(META)?;
            meta.insert(META_HEAD_HASH, hash.0.as_slice())?;
            meta.insert(META_HEAD_SLOT, &slot.to_le_bytes() as &[u8])?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Get head block hash and timeslot.
    pub fn get_head(&self) -> Result<(Hash, u32), StoreError> {
        let txn = self.db.begin_read()?;
        let meta = txn.open_table(META)?;

        let hash_val = meta.get(META_HEAD_HASH)?.ok_or(StoreError::NotFound)?;
        let slot_val = meta.get(META_HEAD_SLOT)?.ok_or(StoreError::NotFound)?;

        let mut hash = [0u8; 32];
        hash.copy_from_slice(hash_val.value());
        let slot = u32::from_le_bytes(
            slot_val
                .value()
                .try_into()
                .map_err(|_| StoreError::Codec("invalid head slot bytes".into()))?,
        );
        Ok((Hash(hash), slot))
    }

    /// Set finalized block.
    pub fn set_finalized(&self, hash: &Hash, slot: u32) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut meta = txn.open_table(META)?;
            meta.insert(META_FINALIZED_HASH, hash.0.as_slice())?;
            meta.insert(META_FINALIZED_SLOT, &slot.to_le_bytes() as &[u8])?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Get finalized block hash and timeslot.
    pub fn get_finalized(&self) -> Result<(Hash, u32), StoreError> {
        let txn = self.db.begin_read()?;
        let meta = txn.open_table(META)?;

        let hash_val = meta.get(META_FINALIZED_HASH)?.ok_or(StoreError::NotFound)?;
        let slot_val = meta.get(META_FINALIZED_SLOT)?.ok_or(StoreError::NotFound)?;

        let mut hash = [0u8; 32];
        hash.copy_from_slice(hash_val.value());
        let slot = u32::from_le_bytes(
            slot_val
                .value()
                .try_into()
                .map_err(|_| StoreError::Codec("invalid finalized slot bytes".into()))?,
        );
        Ok((Hash(hash), slot))
    }

    // ── DA Chunks ───────────────────────────────────────────────────────

    /// Store an erasure-coded chunk.
    pub fn put_chunk(
        &self,
        report_hash: &Hash,
        chunk_index: u16,
        data: &[u8],
    ) -> Result<(), StoreError> {
        let key = chunk_key(report_hash, chunk_index);

        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(CHUNKS)?;
            table.insert(key.as_slice(), data)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Get an erasure-coded chunk.
    pub fn get_chunk(&self, report_hash: &Hash, chunk_index: u16) -> Result<Vec<u8>, StoreError> {
        let key = chunk_key(report_hash, chunk_index);

        let txn = self.db.begin_read()?;
        let table = txn.open_table(CHUNKS)?;
        let val = table.get(key.as_slice())?.ok_or(StoreError::NotFound)?;
        Ok(val.value().to_vec())
    }

    /// Delete all chunks for a work report (for garbage collection).
    pub fn delete_chunks_for_report(&self, report_hash: &Hash) -> Result<u32, StoreError> {
        let txn = self.db.begin_write()?;
        let mut deleted = 0u32;
        {
            let mut table = txn.open_table(CHUNKS)?;
            // Iterate chunk indices 0..max_validators and delete any that exist.
            // In practice we'd use a range scan, but redb key ranges work on byte order.
            let prefix_start = chunk_key(report_hash, 0);
            let prefix_end = chunk_key(report_hash, u16::MAX);
            // Collect keys to delete
            let keys: Vec<Vec<u8>> = {
                let range = table.range(prefix_start.as_slice()..=prefix_end.as_slice())?;
                range
                    .filter_map(|r| r.ok())
                    .map(|(k, _)| k.value().to_vec())
                    .collect()
            };
            for key in &keys {
                table.remove(key.as_slice())?;
                deleted += 1;
            }
        }
        txn.commit()?;
        Ok(deleted)
    }

    // ── Pruning ─────────────────────────────────────────────────────────

    /// Prune state snapshots older than `keep_after_slot`, except finalized.
    /// Returns number of states pruned.
    pub fn prune_states(&self, keep_after_slot: u32) -> Result<u32, StoreError> {
        // Collect block hashes for slots we want to prune
        let txn = self.db.begin_read()?;
        let slot_idx = txn.open_table(SLOT_INDEX)?;
        let state_table = txn.open_table(STATE)?;

        let mut to_delete = Vec::new();
        let range = slot_idx.range(0u32..keep_after_slot)?;
        for entry in range {
            let entry = entry?;
            let hash = *entry.1.value();
            // Only prune if state exists
            if state_table.get(&hash)?.is_some() {
                to_delete.push(hash);
            }
        }
        drop(state_table);
        drop(slot_idx);
        drop(txn);

        if to_delete.is_empty() {
            return Ok(0);
        }

        let txn = self.db.begin_write()?;
        let count = to_delete.len() as u32;
        {
            let mut table = txn.open_table(STATE)?;
            for hash in &to_delete {
                table.remove(hash)?;
            }
        }
        txn.commit()?;
        Ok(count)
    }
}

// ── Encoding helpers ────────────────────────────────────────────────────

/// Encode a block to bytes for storage using JAM codec (header + extrinsic).
fn encode_block(block: &Block) -> Vec<u8> {
    use grey_codec::Encode;
    block.encode()
}

/// Decode a block from storage bytes using JAM codec.
fn decode_block(data: &[u8]) -> Option<Block> {
    use grey_codec::decode::DecodeWithConfig;
    // Use tiny config for storage decode — matches testnet parameters.
    // For full config, the store would need to know the config.
    let config = grey_types::config::Config::tiny();
    let (block, _consumed) = Block::decode_with_config(data, &config).ok()?;
    Some(block)
}

/// Encode state KV pairs for storage.
/// Format: [count:u32] repeated [key:31 bytes][value_len:u32][value bytes]
fn encode_state_kvs(kvs: &[([u8; 31], Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(kvs.len() as u32).to_le_bytes());
    for (key, value) in kvs {
        out.extend_from_slice(key);
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
    }
    out
}

/// Decode state KV pairs from storage.
fn decode_state_kvs(data: &[u8]) -> Option<Vec<([u8; 31], Vec<u8>)>> {
    if data.len() < 4 {
        return None;
    }
    let count = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
    let mut pos = 4;
    let mut kvs = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 31 + 4 > data.len() {
            return None;
        }
        let mut key = [0u8; 31];
        key.copy_from_slice(&data[pos..pos + 31]);
        pos += 31;
        let vlen = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?) as usize;
        pos += 4;
        if pos + vlen > data.len() {
            return None;
        }
        kvs.push((key, data[pos..pos + vlen].to_vec()));
        pos += vlen;
    }
    Some(kvs)
}

/// Build a DA chunk key: report_hash (32 bytes) ++ chunk_index (2 bytes LE).
fn chunk_key(report_hash: &Hash, chunk_index: u16) -> Vec<u8> {
    let mut key = Vec::with_capacity(34);
    key.extend_from_slice(&report_hash.0);
    key.extend_from_slice(&chunk_index.to_le_bytes());
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("test.redb")).unwrap();
        (store, dir)
    }

    #[test]
    fn test_metadata_round_trip() {
        let (store, _dir) = temp_store();

        let hash = Hash([42u8; 32]);
        store.set_head(&hash, 100).unwrap();
        let (got_hash, got_slot) = store.get_head().unwrap();
        assert_eq!(got_hash.0, hash.0);
        assert_eq!(got_slot, 100);

        store.set_finalized(&hash, 90).unwrap();
        let (got_hash, got_slot) = store.get_finalized().unwrap();
        assert_eq!(got_hash.0, hash.0);
        assert_eq!(got_slot, 90);
    }

    #[test]
    fn test_chunk_round_trip() {
        let (store, _dir) = temp_store();

        let report_hash = Hash([1u8; 32]);
        let chunk_data = vec![0xAB; 4104];

        store.put_chunk(&report_hash, 0, &chunk_data).unwrap();
        store.put_chunk(&report_hash, 1, &chunk_data).unwrap();
        store.put_chunk(&report_hash, 5, &chunk_data).unwrap();

        let got = store.get_chunk(&report_hash, 0).unwrap();
        assert_eq!(got, chunk_data);

        let got = store.get_chunk(&report_hash, 5).unwrap();
        assert_eq!(got, chunk_data);

        // Missing chunk
        assert!(store.get_chunk(&report_hash, 99).is_err());

        // Delete all chunks for report
        let deleted = store.delete_chunks_for_report(&report_hash).unwrap();
        assert_eq!(deleted, 3);
        assert!(store.get_chunk(&report_hash, 0).is_err());
    }

    #[test]
    fn test_state_kvs_encoding() {
        let kvs = vec![([1u8; 31], vec![10, 20, 30]), ([2u8; 31], vec![40, 50])];
        let encoded = encode_state_kvs(&kvs);
        let decoded = decode_state_kvs(&encoded).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].0, [1u8; 31]);
        assert_eq!(decoded[0].1, vec![10, 20, 30]);
        assert_eq!(decoded[1].0, [2u8; 31]);
        assert_eq!(decoded[1].1, vec![40, 50]);
    }

    #[test]
    fn test_head_not_found() {
        let (store, _dir) = temp_store();
        assert!(matches!(store.get_head(), Err(StoreError::NotFound)));
    }

    #[test]
    fn test_header_encode_decode_round_trip() {
        use grey_types::*;

        let header = header::Header {
            parent_hash: Hash([1u8; 32]),
            state_root: Hash([2u8; 32]),
            extrinsic_hash: Hash([3u8; 32]),
            timeslot: 42,
            epoch_marker: None,
            tickets_marker: None,
            author_index: 5,
            vrf_signature: BandersnatchSignature([7u8; 96]),
            offenders_marker: vec![],
            seal: BandersnatchSignature([8u8; 96]),
        };

        let encoded = header_codec::encode_header(&header);
        let decoded = header_codec::decode_header(&encoded).expect("decode should succeed");

        assert_eq!(decoded.parent_hash.0, header.parent_hash.0);
        assert_eq!(decoded.state_root.0, header.state_root.0);
        assert_eq!(decoded.extrinsic_hash.0, header.extrinsic_hash.0);
        assert_eq!(decoded.timeslot, header.timeslot);
        assert_eq!(decoded.author_index, header.author_index);
        assert_eq!(decoded.vrf_signature.0, header.vrf_signature.0);
        assert_eq!(decoded.seal.0, header.seal.0);
        assert!(decoded.epoch_marker.is_none());
        assert!(decoded.tickets_marker.is_none());
        assert!(decoded.offenders_marker.is_empty());
    }

    #[test]
    fn test_block_store_round_trip() {
        use grey_types::*;

        let (store, _dir) = temp_store();

        let block = Block {
            header: header::Header {
                parent_hash: Hash([10u8; 32]),
                state_root: Hash([20u8; 32]),
                extrinsic_hash: Hash([30u8; 32]),
                timeslot: 100,
                epoch_marker: None,
                tickets_marker: None,
                author_index: 3,
                vrf_signature: BandersnatchSignature([50u8; 96]),
                offenders_marker: vec![],
                seal: BandersnatchSignature([60u8; 96]),
            },
            extrinsic: header::Extrinsic::default(),
        };

        let hash = store.put_block(&block).unwrap();

        // Get by hash
        let got = store.get_block(&hash).unwrap();
        assert_eq!(got.header.timeslot, 100);
        assert_eq!(got.header.author_index, 3);
        assert_eq!(got.header.parent_hash.0, [10u8; 32]);

        // Get by slot
        let got_hash = store.get_block_hash_by_slot(100).unwrap();
        assert_eq!(got_hash.0, hash.0);

        // Has block
        assert!(store.has_block(&hash).unwrap());
        assert!(!store.has_block(&Hash([0u8; 32])).unwrap());
    }

    #[test]
    fn test_state_kvs_persist_and_load() {
        let (store, _dir) = temp_store();

        let config = Config::tiny();
        let (genesis_state, _) = grey_consensus::genesis::create_genesis(&config);
        let block_hash = Hash([99u8; 32]);

        // Verify serialize_state produces KV pairs and our binary encoding round-trips
        let kvs = grey_merkle::state_serial::serialize_state(&genesis_state, &config);
        assert!(!kvs.is_empty(), "genesis state should produce KV pairs");

        let encoded = encode_state_kvs(&kvs);
        let decoded_kvs = decode_state_kvs(&encoded).unwrap();
        assert_eq!(kvs.len(), decoded_kvs.len());
        for (i, ((k1, v1), (k2, v2))) in kvs.iter().zip(decoded_kvs.iter()).enumerate() {
            assert_eq!(k1, k2, "key mismatch at index {}", i);
            assert_eq!(v1, v2, "value mismatch at index {}", i);
        }

        // Verify store put/get/delete for raw KV data (bypassing state_serial deserialize)
        {
            let txn = store.db.begin_write().unwrap();
            {
                let mut table = txn.open_table(STATE).unwrap();
                table.insert(&block_hash.0, encoded.as_slice()).unwrap();
            }
            txn.commit().unwrap();
        }
        {
            let txn = store.db.begin_read().unwrap();
            let table = txn.open_table(STATE).unwrap();
            let val = table.get(&block_hash.0).unwrap().unwrap();
            let loaded_kvs = decode_state_kvs(val.value()).unwrap();
            assert_eq!(loaded_kvs.len(), kvs.len());
        }

        // Delete
        store.delete_state(&block_hash).unwrap();
        {
            let txn = store.db.begin_read().unwrap();
            let table = txn.open_table(STATE).unwrap();
            assert!(table.get(&block_hash.0).unwrap().is_none());
        }
    }

    #[test]
    fn test_get_accumulation_root() {
        let (store, _dir) = temp_store();
        let config = Config::tiny();
        let (genesis_state, _) = grey_consensus::genesis::create_genesis(&config);
        let block_hash = Hash([99u8; 32]);

        store
            .put_state(&block_hash, &genesis_state, &config)
            .unwrap();

        // Genesis state has recent_blocks with headers. The genesis block's
        // header_hash should be findable, and its accumulation_root should be
        // the zero hash (genesis has no accumulation history).
        if let Some(first_header) = genesis_state.recent_blocks.headers.first() {
            let result = store
                .get_accumulation_root(&block_hash, &first_header.header_hash)
                .unwrap();
            assert!(result.is_some(), "should find the genesis header");
            assert_eq!(
                result.unwrap().0,
                first_header.accumulation_root.0,
                "accumulation_root should match"
            );
        }

        // Looking up a non-existent anchor should return None.
        let fake_anchor = Hash([0xFF; 32]);
        let result = store
            .get_accumulation_root(&block_hash, &fake_anchor)
            .unwrap();
        assert!(result.is_none(), "non-existent anchor should return None");
    }

    #[test]
    fn test_schema_version_written_on_create() {
        let (store, _dir) = temp_store();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn test_schema_version_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.redb");

        // Create the store
        {
            let store = Store::open(&path).unwrap();
            assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        }

        // Reopen — should succeed with same version
        {
            let store = Store::open(&path).unwrap();
            assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        }
    }

    #[test]
    fn test_schema_version_mismatch_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.redb");

        // Create a DB with a different schema version
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut meta = txn.open_table(META).unwrap();
                // Write a future version
                let future_version: u32 = SCHEMA_VERSION + 1;
                meta.insert(META_SCHEMA_VERSION, future_version.to_le_bytes().as_slice())
                    .unwrap();
            }
            txn.commit().unwrap();
        }

        // Opening with current version should fail
        let result = Store::open(&path);
        let err = result.err().expect("expected IncompatibleSchema error");
        let msg = err.to_string();
        assert!(
            msg.contains("incompatible schema version"),
            "expected IncompatibleSchema error, got: {}",
            msg
        );
    }

    #[test]
    fn test_state_integrity_checksum_passes() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("test.redb")).unwrap();
        let config = grey_types::config::Config::tiny();
        let (genesis_state, _) = grey_consensus::genesis::create_genesis(&config);

        let block_hash = Hash([42u8; 32]);
        store
            .put_state(&block_hash, &genesis_state, &config)
            .unwrap();

        // Integrity check should pass
        assert!(store.verify_state_integrity(&block_hash).unwrap());
    }

    #[test]
    fn test_state_integrity_detects_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.redb");
        let block_hash = Hash([42u8; 32]);

        // Store state with checksum
        {
            let store = Store::open(&path).unwrap();
            let config = grey_types::config::Config::tiny();
            let (genesis_state, _) = grey_consensus::genesis::create_genesis(&config);
            store
                .put_state(&block_hash, &genesis_state, &config)
                .unwrap();

            // Verify it passes first
            assert!(store.verify_state_integrity(&block_hash).unwrap());

            // Corrupt the state data by writing different bytes
            let txn = store.db.begin_write().unwrap();
            {
                let mut table = txn.open_table(STATE).unwrap();
                table
                    .insert(&block_hash.0, b"corrupted data".as_slice())
                    .unwrap();
            }
            txn.commit().unwrap();
        }

        // Reopen and verify corruption is detected
        let store = Store::open(&path).unwrap();
        let result = store.verify_state_integrity(&block_hash);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("integrity check failed"),
            "expected IntegrityError, got: {}",
            msg
        );
    }

    #[test]
    fn test_state_integrity_no_checksum_returns_false() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.redb");
        let block_hash = Hash([42u8; 32]);

        let store = Store::open(&path).unwrap();

        // Manually insert state without checksum (simulates legacy data)
        let txn = store.db.begin_write().unwrap();
        {
            let mut table = txn.open_table(STATE).unwrap();
            table
                .insert(&block_hash.0, b"some state data".as_slice())
                .unwrap();
        }
        txn.commit().unwrap();

        // Should return false (no checksum), not error
        assert!(!store.verify_state_integrity(&block_hash).unwrap());
    }
}
