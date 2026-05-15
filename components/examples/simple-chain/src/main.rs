//! Simple example chain (v3 placeholder).
//!
//! The v2 simple-chain — a Rust→javm guest that implemented
//! ed25519-signed account-model balance transfers — relied on v2
//! ABI constants (Vault.initialize, MintAttestCap, SetScore,
//! BareFrame layout, MGMT_MAP semantics) that don't carry over to
//! v3. With v3 the chain Image construction, the kernel-cap layout,
//! and the host_open/host_save flow all live in the new
//! `jar-kernel` crate; a v3 Rust→javm pipeline that emits chain
//! Image blobs is future work.
//!
//! For the end-to-end demonstration this crate is reduced to a
//! host-only no-op. The runnable v3 chain apply path is exercised
//! by the integration tests in `rust/jar-kernel/src/kernel.rs`
//! and (Stage D.2) the dedicated end-to-end fixture there.

fn main() {}
