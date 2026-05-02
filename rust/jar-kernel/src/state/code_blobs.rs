//! Smoke-fixture JAR blob used by genesis.
//!
//! After the CNode-driven `Vault.initialize` refactor, code blobs live
//! as `RegCap::Code(CodeCap)` entries inside Vault CNodes — one
//! Vault holds its own code as a persistent CodeCap whose `blob` field
//! is the **raw code sub-blob** (jump_table + code + bitmask) extracted
//! from the source JAR blob at Vault-creation time. There is no
//! kernel-side "JAR-blob → code-cap-blob" resolver any more: invocation
//! init walks `vault.slots` directly via
//! `crate::state::vault_init::build_init_cap_table`.
//!
//! What remains here is just a single compile-time JAR blob that
//! genesis parses and unpacks into persistent Vaults. The fixture is
//! consumed by `crate::genesis::alloc_vault_with_code`. The
//! `slot_clear` fixture was retired with the event-redesign.

/// Default smoke fixture: a PVM blob that ecallis IPC-slot (REPLY) → halts
/// immediately. Compiled at build time from `rust/jar-test-services/halt`.
pub fn halt_blob() -> &'static [u8] {
    include_bytes!(env!("JAR_HALT_BLOB_PATH"))
}
