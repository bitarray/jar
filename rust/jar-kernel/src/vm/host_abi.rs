//! Host-call ABI for the event-redesign: register conventions, slot
//! placement, and return-code sentinels.
//!
//! Host calls are dispatched as `ProtocolCap` variants — `EmitEvent`,
//! `MintAttestCap`, `SetScore`. The kernel places each cap into a
//! known frame cap-table slot at invocation init; an `ecalli <slot>`
//! from the guest causes javm to read the cap at that slot and route
//! through `InvocationHost::call`.
//!
//! ## Frame slot placement
//!
//! - Slot 0: javm-reserved bare-Frame FrameRef.
//! - Slot 1: home VaultRef (kernel-injected).
//! - Slot 2: SelfId cap.
//! - Slot 3: kernel-injected `CallerKernel` cap (carries `KernelRole`).
//! - Slot 4: `EmitEvent` cap (verify + process).
//! - Slot 5: `MintAttestCap` cap (verify only).
//! - Slot 6: `SetScore` cap (verify only).
//! - Slot 32: `AttestationScope` cap (verify only). See
//!   [`crate::cap::KERNEL_CAP_SLOT`].
//!
//! ## Register conventions
//!
//! - φ[7]..φ[14] carry up to 8 inputs.
//! - φ[7] carries the primary return value; φ[8] the secondary.
//! - Pointer/length pairs reference the guest's flat memory window.
//!
//! ## Per-call ABI
//!
//! ### `caller_role()` (slot 3)
//! - returns role in φ[7]: 0 = `KernelRole::Verify`,
//!   1 = `KernelRole::Process`.
//!
//! ### `emit_event(target_path, blob)` (slot 4)
//! - φ[7] = target_path_ptr, φ[8] = target_path_len
//! - φ[9] = blob_ptr, φ[10] = blob_len
//! - returns RC in φ[7]
//!
//! ### `mint_attest_cap(dst_slot, key, blob, sig)` (slot 5)
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
//! ### `setScore(identifier, score)` (slot 6)
//! - φ[7] = identifier_ptr, φ[8] = identifier_len
//! - φ[9] = score (u64)
//! - returns RC in φ[7]

/// Frame slot the kernel injects the `CallerKernel` cap at — its
/// `role` field tells the guest whether this is a verify or process
/// invocation.
pub const CALLER_KERNEL_SLOT: u8 = 3;

/// Frame slot the kernel injects the `EmitEvent` cap at.
pub const EMIT_EVENT_SLOT: u8 = 4;

/// Frame slot the kernel injects the `MintAttestCap` cap at (verify only).
pub const MINT_ATTEST_CAP_SLOT: u8 = 5;

/// Frame slot the kernel injects the `SetScore` cap at (verify only).
pub const SET_SCORE_SLOT: u8 = 6;

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
