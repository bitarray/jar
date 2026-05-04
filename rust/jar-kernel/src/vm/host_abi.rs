//! Host-call ABI: register conventions, BareFrame slot placement,
//! and return-code sentinels.
//!
//! Host calls are `ProtocolCap` variants the kernel injects into
//! the BareFrame at `vault.initialize`. Guests reach them via
//! cap-ref `(slot << 8) | 0` (cross slot 0 → BareFrame, target =
//! slot in BareFrame), using javm's dynamic-CALL ecall path
//! (`csrw 0x800; ecall`, op = 0x00, subject_ref in φ[12]).
//!
//! Alternatively, a guest can MGMT_COPY a kernel cap from BareFrame
//! into MainFrame at startup and then use plain `ecalli imm`.
//!
//! ## BareFrame slot placement
//!
//! javm-reserved: 0 (REPLY), 1 (caller cap), 4 (args DataCap from
//! `set_args`), 9 (per-invocation `UntypedCap`). Jar-kernel injects
//! around them:
//!
//! | Slot | Cap | When |
//! |------|-----|------|
//! | 0    | (javm) REPLY | always |
//! | 1    | (javm) caller cap | per-CALL |
//! | 4    | (javm) args DataCap | when set_args |
//! | 7    | home VaultRef | always |
//! | 8    | `CallerKernel` (role) | always |
//! | 9    | (javm) UntypedCap | always |
//! | 10   | SelfId | always |
//! | 11   | `EmitEvent` | always |
//! | 12   | `MintAttestCap` | verify only |
//! | 13   | `SetScore` | verify only |
//! | 14   | `AttestationScope` | verify only |
//!
//! MainFrame slots 1+ are entirely chain-author-controlled (image-
//! driven). The kernel never touches them.
//!
//! ## Register conventions
//!
//! - φ[7]..φ[14] carry up to 8 inputs.
//! - φ[7] carries the primary return value; φ[8] the secondary.
//! - Pointer/length pairs reference the guest's flat memory window.
//!
//! ## Per-call ABI
//!
//! ### `caller_role()` (BareFrame slot 8)
//! - returns role in φ[7]: 0 = `KernelRole::Verify`,
//!   1 = `KernelRole::Process`.
//!
//! ### `emit_event(target_path, blob)` (BareFrame slot 11)
//! - φ[7] = target_path_ptr, φ[8] = target_path_len
//! - φ[9] = blob_ptr, φ[10] = blob_len
//! - returns RC in φ[7]
//!
//! ### `mint_attest_cap(dst_slot, key, blob, sig)` (BareFrame slot 12)
//! - φ[7] = dst_slot (cap-table slot to place the minted cap into)
//! - φ[8] = key_ptr (0 → IDENTITY_KEY, no read; otherwise 32-byte
//!   ed25519 pubkey)
//! - φ[9] = blob_ptr, φ[10] = blob_len
//! - φ[11] = sig_ptr (0 → no signature; only legal for IDENTITY_KEY.
//!   Otherwise 64-byte ed25519 signature)
//! - returns RC in φ[7]
//!
//! Key and signature lengths are hardcoded (ed25519 widths) to keep
//! the call within the RISC-V `e`-feature 6-register limit.
//!
//! ### `setScore(identifier, score)` (BareFrame slot 13)
//! - φ[7] = identifier_ptr, φ[8] = identifier_len
//! - φ[9] = score (u64)
//! - returns RC in φ[7]
//!
//! ### `open(file_cap_slot, dst_slot)` (BareFrame slot 15)
//! - φ[7] = file_cap_slot — slot in the active VM's MainFrame
//!   holding `Cap::Protocol(ProtocolCap::Reg(RegCap::File(_)))`.
//! - φ[8] = dst_slot — slot in the active VM's MainFrame to place
//!   the resulting `Cap::Data`. Must be empty.
//! - returns RC in φ[7] (RC_OK on success; RC_BAD_CAP if file_cap_slot
//!   doesn't hold a FileCap or destination is occupied; RC_QUOTA if
//!   the active Untyped doesn't cover the file's page count).
//!
//! ### `save(data_cap_slot, quota_cap_slot, dst_slot)` (BareFrame slot 16)
//! - φ[7] = data_cap_slot — slot in the active VM's MainFrame
//!   holding the source `Cap::Data` (post-execution pages).
//! - φ[8] = quota_cap_slot — slot holding the
//!   `Cap::Protocol(ProtocolCap::Reg(RegCap::StorageQuota(_)))` that
//!   pays for the new file.
//! - φ[9] = dst_slot — slot to place the resulting
//!   `Cap::Protocol(ProtocolCap::Reg(RegCap::File(_)))`. Must be empty.
//! - returns RC in φ[7]. Process role only — read-only contexts
//!   (verify) get RC_READONLY.

/// BareFrame slot holding the home VaultRef — handle the guest
/// uses to reach its own `Vault.slots` via foreign-frame ops.
/// Avoids javm's reserved slots (0/1/4/9).
pub const BARE_HOME_VAULT_SLOT: u8 = 7;

/// BareFrame slot the kernel injects the `CallerKernel` cap at —
/// its `role` field tells the guest verify vs process.
pub const BARE_CALLER_KERNEL_SLOT: u8 = 8;

// Per-invocation `UntypedCap` lives at javm's `BARE_FRAME_UNTYPED_SLOT`
// (slot 9), placed by `new_from_artifacts` and pinned. Address it via
// `javm::kernel::BARE_FRAME_UNTYPED_SLOT` directly.

/// BareFrame slot holding the SelfId cap — the running VM's
/// own VaultId.
pub const BARE_SELF_ID_SLOT: u8 = 10;

/// BareFrame slot the kernel injects the `EmitEvent` cap at.
pub const BARE_EMIT_EVENT_SLOT: u8 = 11;

/// BareFrame slot the kernel injects the `MintAttestCap` cap at
/// (verify only).
pub const BARE_MINT_ATTEST_CAP_SLOT: u8 = 12;

/// BareFrame slot the kernel injects the `SetScore` cap at
/// (verify only).
pub const BARE_SET_SCORE_SLOT: u8 = 13;

/// BareFrame slot the kernel injects the `AttestationScope` cap
/// at (verify only).
pub const BARE_ATTESTATION_SCOPE_SLOT: u8 = 14;

/// BareFrame slot the kernel injects the `Open` host-call selector
/// at — `host_open(file_cap_slot, dst_slot)` reads bytes from
/// `state.data_blobs[file_id]`, allocates ephemeral pages from the
/// active Untyped, and places a fresh unmapped `Cap::Data` at
/// `dst_slot` of the active VM's MainFrame. Process role only.
pub const BARE_OPEN_SLOT: u8 = 15;

/// BareFrame slot the kernel injects the `Save` host-call selector
/// at — `host_save(data_cap_slot, quota_cap_slot, dst_slot)` reads
/// post-execution pages from a Frame `Cap::Data`, debits bytes from
/// the named StorageQuota entry, mints a fresh `FileId` in
/// `state.data_blobs`, and places
/// `Cap::Protocol(ProtocolCap::Reg(RegCap::File(_)))` at `dst_slot`.
/// Process role only.
pub const BARE_SAVE_SLOT: u8 = 16;

/// Sentinel returned from host calls signalling success when the call
/// has no natural return value.
pub const RC_OK: u64 = 0;

/// Generic error sentinel.
pub const RC_ERR: u64 = u64::MAX;

/// "None" / "absent" sentinel for read-style host calls.
pub const RC_NONE: u64 = u64::MAX - 1;

/// Read-only context attempted a mutating host call (e.g. process
/// invocation calling `mint_attest_cap` or `setScore`, both of which
/// are verify-only).
pub const RC_READONLY: u64 = u64::MAX - 2;

/// Quota exceeded.
pub const RC_QUOTA: u64 = u64::MAX - 3;

/// Scope violation (mint_attest_cap for a key outside the
/// AttestationScope's restricted seen-set).
pub const RC_AUTHORITY: u64 = u64::MAX - 4;

/// Cap not found / slot empty / malformed input.
pub const RC_BAD_CAP: u64 = u64::MAX - 5;

/// Signature verification failed.
pub const RC_BAD_SIG: u64 = u64::MAX - 6;
