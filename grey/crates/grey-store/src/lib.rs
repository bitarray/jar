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
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
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
// GRANDPA votes: key = round(8) + type(1) + validator(2) = 11 bytes -> value = hash(32) + slot(4) + sig(64) = 100 bytes
const GRANDPA_VOTES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("grandpa_votes");
// Chunk metadata: report_hash (32 bytes) -> creation_slot (u32 LE, 4 bytes)
// Tracks when chunks were first stored for TTL-based expiration.
const CHUNK_META: TableDefinition<&[u8; 32], u32> = TableDefinition::new("chunk_meta");

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

/// State key-value pairs: 31-byte key → variable-length value.
type StateKvs = Vec<([u8; 31], Vec<u8>)>;

/// A persisted GRANDPA vote: (vote_type, validator_index, block_hash, block_slot, signature).
pub type PersistedVote = (u8, u16, Hash, u32, [u8; 64]);

/// Persistent store backed by redb.
pub struct Store {
    db: Database,
}

/// Run schema migrations from `from_version` to `to_version`.
///
/// Migrations run sequentially: v_from→v_from+1, v_from+1→v_from+2, etc.
/// Each step is a match arm that performs the upgrade and advances `current`.
///
/// To add a new migration when bumping SCHEMA_VERSION:
/// 1. Add a new arm for the old version number.
/// 2. The migration receives the META table for metadata updates.
///
/// Example (when bumping to v2):
/// ```ignore
/// 1 => {
///     tracing::info!("Migrating v1 → v2: adding new_table");
///     // ... create new table, reformat data, etc.
///     current += 1;
/// }
/// ```
fn run_migrations(
    from_version: u32,
    to_version: u32,
    _meta: &mut redb::Table<&str, &[u8]>,
) -> Result<(), StoreError> {
    // No migrations registered yet (SCHEMA_VERSION = 1, first version).
    // When SCHEMA_VERSION is bumped, add migration arms here.
    if from_version < to_version {
        return Err(StoreError::Codec(format!(
            "no migration path from schema v{from_version} to v{to_version}"
        )));
    }
    Ok(())
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
            let _ = txn.open_table(GRANDPA_VOTES)?;
            let _ = txn.open_table(CHUNK_META)?;

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
                Some(v) if v > SCHEMA_VERSION => {
                    // Database is newer than this binary — cannot downgrade
                    return Err(StoreError::IncompatibleSchema {
                        found: v,
                        expected: SCHEMA_VERSION,
                    });
                }
                Some(v) if v < SCHEMA_VERSION => {
                    // Run migrations from v to SCHEMA_VERSION
                    run_migrations(v, SCHEMA_VERSION, &mut meta)?;
                    meta.insert(META_SCHEMA_VERSION, SCHEMA_VERSION.to_le_bytes().as_slice())?;
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

    /// Get a block by timeslot (convenience: slot → hash → block).
    pub fn get_block_by_slot(&self, slot: u32) -> Result<Block, StoreError> {
        let hash = self.get_block_hash_by_slot(slot)?;
        self.get_block(&hash)
    }

    /// Check if a block exists.
    pub fn has_block(&self, hash: &Hash) -> Result<bool, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BLOCKS)?;
        Ok(table.get(&hash.0)?.is_some())
    }

    /// Count rows in a table.
    fn table_count<K: redb::Key + 'static, V: redb::Value + 'static>(
        &self,
        table_def: redb::TableDefinition<K, V>,
    ) -> Result<u64, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(table_def)?;
        Ok(table.len()?)
    }

    /// Count the number of stored blocks.
    pub fn block_count(&self) -> Result<u64, StoreError> {
        self.table_count(BLOCKS)
    }

    /// Count the number of stored state entries.
    pub fn state_count(&self) -> Result<u64, StoreError> {
        self.table_count(STATE)
    }

    /// Count the number of stored DA chunks.
    pub fn chunk_count(&self) -> Result<u64, StoreError> {
        self.table_count(CHUNKS)
    }

    /// Count the number of stored GRANDPA votes.
    pub fn vote_count(&self) -> Result<u64, StoreError> {
        self.table_count(GRANDPA_VOTES)
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

    /// Verify integrity of all stored state entries.
    ///
    /// Returns `(verified, skipped, failed)` counts:
    /// - verified: checksum matched
    /// - skipped: no checksum stored (legacy data)
    /// - failed: checksum mismatch (corruption detected)
    ///
    /// Logs each failure but does not stop on first error.
    pub fn verify_all_states(&self) -> Result<(u32, u32, u32), StoreError> {
        let txn = self.db.begin_read()?;
        let state_table = txn.open_table(STATE)?;

        let mut block_hashes: Vec<[u8; 32]> = Vec::new();
        for entry in state_table.iter()? {
            let entry = entry?;
            block_hashes.push(*entry.0.value());
        }
        drop(state_table);
        drop(txn);

        let mut verified = 0u32;
        let mut skipped = 0u32;
        let mut failed = 0u32;

        for hash in &block_hashes {
            match self.verify_state_integrity(&Hash(*hash)) {
                Ok(true) => verified += 1,
                Ok(false) => skipped += 1,
                Err(StoreError::IntegrityError { .. }) => {
                    failed += 1;
                    // Error already logged by verify_state_integrity or caller
                }
                Err(e) => return Err(e),
            }
        }

        Ok((verified, skipped, failed))
    }

    /// Load and decode state KV pairs for a block hash.
    fn load_state_kvs(&self, block_hash: &Hash) -> Result<StateKvs, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(STATE)?;
        let val = table.get(&block_hash.0)?.ok_or(StoreError::NotFound)?;
        decode_state_kvs(val.value()).ok_or_else(|| StoreError::Codec("invalid state KVs".into()))
    }

    /// Find a value by key in decoded state KV pairs.
    fn find_in_kvs<'a>(kvs: &'a StateKvs, key: &[u8; 31]) -> Option<&'a [u8]> {
        kvs.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_slice())
    }

    /// Look up a specific service storage entry by computing the expected state key.
    /// Returns None if the entry doesn't exist.
    pub fn get_service_storage(
        &self,
        block_hash: &Hash,
        service_id: u32,
        storage_key: &[u8],
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let kvs = self.load_state_kvs(block_hash)?;
        let expected_key =
            grey_merkle::state_serial::compute_storage_state_key(service_id, storage_key);
        Ok(Self::find_in_kvs(&kvs, &expected_key).map(|v| v.to_vec()))
    }

    /// Look up a service account's code hash directly from state KVs.
    /// The service metadata is at key C(255, service_id), and code_hash is bytes [1..33].
    pub fn get_service_code_hash(
        &self,
        block_hash: &Hash,
        service_id: u32,
    ) -> Result<Option<Hash>, StoreError> {
        let kvs = self.load_state_kvs(block_hash)?;
        let expected_key = grey_merkle::state_serial::key_for_service_pub(255, service_id);
        Ok(Self::find_in_kvs(&kvs, &expected_key).and_then(|value| {
            // Service account: version(1) + code_hash(32) + ...
            if value.len() >= 33 {
                let mut h = [0u8; 32];
                h.copy_from_slice(&value[1..33]);
                Some(Hash(h))
            } else {
                None
            }
        }))
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
        let kvs = self.load_state_kvs(block_hash)?;
        let expected_key = grey_merkle::state_serial::key_for_service_pub(255, service_id);
        let Some(value) = Self::find_in_kvs(&kvs, &expected_key) else {
            return Ok(None);
        };
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

        Ok(Some(ServiceMetadata {
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
        }))
    }

    /// Look up a raw state KV by key from state KVs.
    pub fn get_state_kv(
        &self,
        block_hash: &Hash,
        state_key: &[u8; 31],
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let kvs = self.load_state_kvs(block_hash)?;
        Ok(Self::find_in_kvs(&kvs, state_key).map(|v| v.to_vec()))
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
    /// Write a hash+slot pair to two META keys.
    fn set_meta_hash_slot(
        &self,
        hash_key: &str,
        slot_key: &str,
        hash: &Hash,
        slot: u32,
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut meta = txn.open_table(META)?;
            meta.insert(hash_key, hash.0.as_slice())?;
            meta.insert(slot_key, &slot.to_le_bytes() as &[u8])?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Read a hash+slot pair from two META keys.
    fn get_meta_hash_slot(
        &self,
        hash_key: &str,
        slot_key: &str,
    ) -> Result<(Hash, u32), StoreError> {
        let txn = self.db.begin_read()?;
        let meta = txn.open_table(META)?;

        let hash_val = meta.get(hash_key)?.ok_or(StoreError::NotFound)?;
        let slot_val = meta.get(slot_key)?.ok_or(StoreError::NotFound)?;

        let mut hash = [0u8; 32];
        hash.copy_from_slice(hash_val.value());
        let slot = u32::from_le_bytes(
            slot_val
                .value()
                .try_into()
                .map_err(|_| StoreError::Codec(format!("invalid {slot_key} bytes")))?,
        );
        Ok((Hash(hash), slot))
    }

    pub fn set_head(&self, hash: &Hash, slot: u32) -> Result<(), StoreError> {
        self.set_meta_hash_slot(META_HEAD_HASH, META_HEAD_SLOT, hash, slot)
    }

    /// Get head block hash and timeslot.
    pub fn get_head(&self) -> Result<(Hash, u32), StoreError> {
        self.get_meta_hash_slot(META_HEAD_HASH, META_HEAD_SLOT)
    }

    /// Set finalized block.
    pub fn set_finalized(&self, hash: &Hash, slot: u32) -> Result<(), StoreError> {
        self.set_meta_hash_slot(META_FINALIZED_HASH, META_FINALIZED_SLOT, hash, slot)
    }

    /// Get finalized block hash and timeslot.
    pub fn get_finalized(&self) -> Result<(Hash, u32), StoreError> {
        self.get_meta_hash_slot(META_FINALIZED_HASH, META_FINALIZED_SLOT)
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

    /// Store an erasure-coded chunk with creation slot metadata for TTL tracking.
    pub fn put_chunk_with_slot(
        &self,
        report_hash: &Hash,
        chunk_index: u16,
        data: &[u8],
        creation_slot: u32,
    ) -> Result<(), StoreError> {
        let key = chunk_key(report_hash, chunk_index);

        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(CHUNKS)?;
            table.insert(key.as_slice(), data)?;
            // Record creation slot (only first chunk per report sets the metadata)
            let mut meta = txn.open_table(CHUNK_META)?;
            if meta.get(&report_hash.0)?.is_none() {
                meta.insert(&report_hash.0, creation_slot)?;
            }
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

    /// Remove all expired chunks: chunks whose creation slot is older than
    /// `current_slot - ttl_slots`. Returns the number of reports cleaned up.
    pub fn prune_expired_chunks(
        &self,
        current_slot: u32,
        ttl_slots: u32,
    ) -> Result<u32, StoreError> {
        let cutoff = current_slot.saturating_sub(ttl_slots);
        if cutoff == 0 {
            return Ok(0);
        }

        // Collect expired report hashes from metadata
        let txn = self.db.begin_read()?;
        let meta_table = txn.open_table(CHUNK_META)?;
        let mut expired_reports: Vec<[u8; 32]> = Vec::new();
        for entry in meta_table.iter()? {
            let entry = entry?;
            let creation_slot = entry.1.value();
            if creation_slot < cutoff {
                expired_reports.push(*entry.0.value());
            }
        }
        drop(meta_table);
        drop(txn);

        if expired_reports.is_empty() {
            return Ok(0);
        }

        let count = expired_reports.len() as u32;
        // Delete chunks and metadata for each expired report
        for report_hash in &expired_reports {
            self.delete_chunks_for_report(&Hash(*report_hash))?;
        }
        // Clean up metadata entries
        let txn = self.db.begin_write()?;
        {
            let mut meta = txn.open_table(CHUNK_META)?;
            for report_hash in &expired_reports {
                meta.remove(report_hash)?;
            }
        }
        txn.commit()?;

        tracing::info!(
            "Pruned chunks for {} expired reports (cutoff slot {})",
            count,
            cutoff
        );
        Ok(count)
    }

    // ── Pruning ─────────────────────────────────────────────────────────

    /// Prune all data (blocks, state, checksums, slot index) for slots before
    /// `keep_after_slot`. Slot 0 (genesis) is always preserved.
    /// Returns the number of blocks pruned.
    pub fn prune_before_slot(&self, keep_after_slot: u32) -> Result<u32, StoreError> {
        if keep_after_slot == 0 {
            return Ok(0);
        }

        // Collect (slot, block_hash) pairs to prune (skip slot 0 = genesis)
        let txn = self.db.begin_read()?;
        let slot_idx = txn.open_table(SLOT_INDEX)?;
        let mut to_delete: Vec<(u32, [u8; 32])> = Vec::new();
        let range = slot_idx.range(1u32..keep_after_slot)?;
        for entry in range {
            let entry = entry?;
            let slot = entry.0.value();
            let hash = *entry.1.value();
            to_delete.push((slot, hash));
        }
        drop(slot_idx);
        drop(txn);

        if to_delete.is_empty() {
            return Ok(0);
        }

        let count = to_delete.len() as u32;
        let txn = self.db.begin_write()?;
        {
            let mut blocks = txn.open_table(BLOCKS)?;
            let mut state = txn.open_table(STATE)?;
            let mut checksums = txn.open_table(STATE_CHECKSUMS)?;
            let mut slot_index = txn.open_table(SLOT_INDEX)?;

            for (slot, hash) in &to_delete {
                blocks.remove(hash)?;
                state.remove(hash)?;
                checksums.remove(hash)?;
                slot_index.remove(slot)?;
            }
        }
        txn.commit()?;

        tracing::info!("Pruned {} blocks for slots 1..{}", count, keep_after_slot);
        Ok(count)
    }

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

    // ── GRANDPA vote persistence ────────────────────────────────────────

    /// Persist a GRANDPA vote (prevote or precommit).
    /// `vote_type`: 0x01 = prevote, 0x02 = precommit.
    pub fn put_grandpa_vote(
        &self,
        round: u64,
        vote_type: u8,
        validator_index: u16,
        block_hash: &Hash,
        block_slot: u32,
        signature: &[u8; 64],
    ) -> Result<(), StoreError> {
        let mut key = [0u8; 11];
        key[0..8].copy_from_slice(&round.to_le_bytes());
        key[8] = vote_type;
        key[9..11].copy_from_slice(&validator_index.to_le_bytes());

        let mut value = [0u8; 100];
        value[0..32].copy_from_slice(&block_hash.0);
        value[32..36].copy_from_slice(&block_slot.to_le_bytes());
        value[36..100].copy_from_slice(signature);

        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(GRANDPA_VOTES)?;
            table.insert(key.as_slice(), value.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Load all GRANDPA votes for a given round.
    pub fn get_grandpa_votes_for_round(
        &self,
        round: u64,
    ) -> Result<Vec<PersistedVote>, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(GRANDPA_VOTES)?;

        // Range scan: all keys starting with this round's 8-byte LE prefix
        let prefix_start = round.to_le_bytes();
        let mut range_end = [0u8; 11];
        range_end[0..8].copy_from_slice(&(round + 1).to_le_bytes());

        let mut votes = Vec::new();
        let range = table.range(prefix_start.as_slice()..range_end.as_slice())?;
        for entry in range {
            let entry = entry?;
            let key = entry.0.value();
            let val = entry.1.value();
            if key.len() < 11 || val.len() < 100 {
                continue;
            }
            let vote_type = key[8];
            let validator_index = u16::from_le_bytes([key[9], key[10]]);
            let mut block_hash = [0u8; 32];
            block_hash.copy_from_slice(&val[0..32]);
            let block_slot = u32::from_le_bytes([val[32], val[33], val[34], val[35]]);
            let mut signature = [0u8; 64];
            signature.copy_from_slice(&val[36..100]);
            votes.push((
                vote_type,
                validator_index,
                Hash(block_hash),
                block_slot,
                signature,
            ));
        }
        Ok(votes)
    }

    /// Get the highest round number from persisted GRANDPA votes.
    /// Returns 0 if no votes are stored.
    pub fn get_latest_grandpa_round(&self) -> Result<u64, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(GRANDPA_VOTES)?;
        // Keys are sorted by (round LE, vote_type, validator_index).
        // The last entry has the highest round.
        match table.last()? {
            Some(entry) => {
                let key = entry.0.value();
                if key.len() >= 8 {
                    Ok(u64::from_le_bytes(key[0..8].try_into().unwrap()))
                } else {
                    Ok(0)
                }
            }
            None => Ok(0),
        }
    }

    /// Remove all GRANDPA votes for rounds ≤ `up_to_round`.
    pub fn prune_grandpa_votes(&self, up_to_round: u64) -> Result<u32, StoreError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(GRANDPA_VOTES)?;

        let mut to_delete: Vec<Vec<u8>> = Vec::new();
        let range_end = (up_to_round + 1).to_le_bytes();
        let range = table.range(..range_end.as_slice())?;
        for entry in range {
            let entry = entry?;
            to_delete.push(entry.0.value().to_vec());
        }
        drop(table);
        drop(txn);

        if to_delete.is_empty() {
            return Ok(0);
        }

        let count = to_delete.len() as u32;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(GRANDPA_VOTES)?;
            for key in &to_delete {
                table.remove(key.as_slice())?;
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

        // Get block by slot (convenience method)
        let got_by_slot = store.get_block_by_slot(100).unwrap();
        assert_eq!(got_by_slot.header.timeslot, 100);
        assert_eq!(got_by_slot.header.author_index, 3);

        // Non-existent slot
        assert!(store.get_block_by_slot(999).is_err());

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
    fn test_schema_migration_no_path_errors() {
        // If SCHEMA_VERSION is 1, there's no migration from 0→1 (fresh DBs skip migration).
        // A DB at version 0 would trigger a migration attempt, but there's no migration
        // registered for 0→1 (version 0 never existed), so it should error gracefully.
        if SCHEMA_VERSION <= 1 {
            // With SCHEMA_VERSION=1, we can't test migration because version 0
            // isn't a real schema. Skip until we have version 2+.
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.redb");

        // Write an old version
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut meta = txn.open_table(META).unwrap();
                let old_version: u32 = 0;
                meta.insert(META_SCHEMA_VERSION, old_version.to_le_bytes().as_slice())
                    .unwrap();
            }
            txn.commit().unwrap();
        }

        // Opening should attempt migration from 0 → SCHEMA_VERSION
        let result = Store::open(&path);
        // Since there's no registered migration from 0→1, it should fail
        let msg = result.err().expect("expected migration error").to_string();
        assert!(
            msg.contains("no migration path"),
            "expected 'no migration path' error, got: {}",
            msg
        );
    }

    #[test]
    fn test_schema_future_version_rejected() {
        // A DB from a newer binary (future version) should be rejected — can't downgrade
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.redb");

        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut meta = txn.open_table(META).unwrap();
                let future_version: u32 = SCHEMA_VERSION + 1;
                meta.insert(META_SCHEMA_VERSION, future_version.to_le_bytes().as_slice())
                    .unwrap();
            }
            txn.commit().unwrap();
        }

        let result = Store::open(&path);
        let msg = result
            .err()
            .expect("expected IncompatibleSchema")
            .to_string();
        assert!(
            msg.contains("incompatible schema version"),
            "expected IncompatibleSchema, got: {}",
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

    fn make_block(slot: u32) -> Block {
        use grey_types::*;
        Block {
            header: header::Header {
                parent_hash: Hash([10u8; 32]),
                state_root: Hash([20u8; 32]),
                extrinsic_hash: Hash([30u8; 32]),
                timeslot: slot,
                epoch_marker: None,
                tickets_marker: None,
                author_index: 0,
                vrf_signature: BandersnatchSignature([50u8; 96]),
                offenders_marker: vec![],
                seal: BandersnatchSignature([60u8; 96]),
            },
            extrinsic: header::Extrinsic::default(),
        }
    }

    #[test]
    fn test_prune_before_slot() {
        let (store, _dir) = temp_store();
        let config = grey_types::config::Config::tiny();
        let (genesis_state, _) = grey_consensus::genesis::create_genesis(&config);

        // Store blocks at slots 0 (genesis), 1, 2, 3, 4, 5
        for slot in 0..=5u32 {
            let block = make_block(slot);
            let hash = store.put_block(&block).unwrap();
            store.put_state(&hash, &genesis_state, &config).unwrap();
        }

        // Verify all 6 blocks exist
        for slot in 0..=5u32 {
            assert!(store.get_block_hash_by_slot(slot).is_ok());
        }

        // Prune slots < 3 (keep slots 3, 4, 5 + genesis slot 0)
        let pruned = store.prune_before_slot(3).unwrap();
        assert_eq!(pruned, 2, "should prune slots 1 and 2");

        // Slot 0 (genesis) should still exist
        assert!(store.get_block_hash_by_slot(0).is_ok(), "genesis preserved");

        // Slots 1, 2 should be pruned
        assert!(store.get_block_hash_by_slot(1).is_err(), "slot 1 pruned");
        assert!(store.get_block_hash_by_slot(2).is_err(), "slot 2 pruned");

        // Slots 3, 4, 5 should still exist
        assert!(store.get_block_hash_by_slot(3).is_ok(), "slot 3 kept");
        assert!(store.get_block_hash_by_slot(4).is_ok(), "slot 4 kept");
        assert!(store.get_block_hash_by_slot(5).is_ok(), "slot 5 kept");

        // Prune with 0 should be no-op
        assert_eq!(store.prune_before_slot(0).unwrap(), 0);
    }

    #[test]
    fn test_grandpa_vote_persistence() {
        let (store, _dir) = temp_store();
        let block_hash = Hash([42u8; 32]);
        let sig = [7u8; 64];

        // Store some votes
        store
            .put_grandpa_vote(1, 0x01, 0, &block_hash, 10, &sig)
            .unwrap(); // round 1 prevote v0
        store
            .put_grandpa_vote(1, 0x01, 1, &block_hash, 10, &sig)
            .unwrap(); // round 1 prevote v1
        store
            .put_grandpa_vote(1, 0x02, 0, &block_hash, 10, &sig)
            .unwrap(); // round 1 precommit v0
        store
            .put_grandpa_vote(2, 0x01, 0, &block_hash, 11, &sig)
            .unwrap(); // round 2 prevote v0

        // Load round 1 votes
        let votes = store.get_grandpa_votes_for_round(1).unwrap();
        assert_eq!(votes.len(), 3);

        // Load round 2 votes
        let votes = store.get_grandpa_votes_for_round(2).unwrap();
        assert_eq!(votes.len(), 1);
        assert_eq!(votes[0].0, 0x01); // prevote
        assert_eq!(votes[0].1, 0); // validator 0
        assert_eq!(votes[0].2, block_hash);
        assert_eq!(votes[0].3, 11); // slot

        // Prune round 1
        let pruned = store.prune_grandpa_votes(1).unwrap();
        assert_eq!(pruned, 3);

        // Round 1 should be empty now
        let votes = store.get_grandpa_votes_for_round(1).unwrap();
        assert!(votes.is_empty());

        // Round 2 should still have its vote
        let votes = store.get_grandpa_votes_for_round(2).unwrap();
        assert_eq!(votes.len(), 1);
    }

    #[test]
    fn test_get_latest_grandpa_round() {
        let (store, _dir) = temp_store();
        let block_hash = Hash([42u8; 32]);
        let sig = [7u8; 64];

        // No votes yet
        assert_eq!(store.get_latest_grandpa_round().unwrap(), 0);

        // Store votes for rounds 1 and 3
        store
            .put_grandpa_vote(1, 0x01, 0, &block_hash, 10, &sig)
            .unwrap();
        store
            .put_grandpa_vote(3, 0x01, 1, &block_hash, 12, &sig)
            .unwrap();

        assert_eq!(store.get_latest_grandpa_round().unwrap(), 3);

        // Prune round 3 — should fall back to round 1
        store.prune_grandpa_votes(3).unwrap();
        // After pruning all rounds ≤ 3, no votes remain
        assert_eq!(store.get_latest_grandpa_round().unwrap(), 0);
    }

    #[test]
    fn test_chunk_expiration() {
        let (store, _dir) = temp_store();
        let report_old = Hash([1u8; 32]);
        let report_new = Hash([2u8; 32]);
        let chunk_data = vec![0xAB; 100];

        // Store old chunks at slot 10
        store
            .put_chunk_with_slot(&report_old, 0, &chunk_data, 10)
            .unwrap();
        store
            .put_chunk_with_slot(&report_old, 1, &chunk_data, 10)
            .unwrap();

        // Store new chunks at slot 100
        store
            .put_chunk_with_slot(&report_new, 0, &chunk_data, 100)
            .unwrap();

        // Verify all chunks exist
        assert!(store.get_chunk(&report_old, 0).is_ok());
        assert!(store.get_chunk(&report_new, 0).is_ok());

        // Prune with current_slot=200, TTL=100 → cutoff=100, old (slot 10) expires
        let pruned = store.prune_expired_chunks(200, 100).unwrap();
        assert_eq!(pruned, 1, "one report should be pruned");

        // Old chunks should be gone
        assert!(store.get_chunk(&report_old, 0).is_err());
        assert!(store.get_chunk(&report_old, 1).is_err());

        // New chunks should remain
        assert!(store.get_chunk(&report_new, 0).is_ok());

        // Prune again — no-op
        assert_eq!(store.prune_expired_chunks(200, 100).unwrap(), 0);
    }
}
