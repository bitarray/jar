//! Nub: the JAR v3 microkernel.
//!
//! This crate defines the [`Arch`] substrate trait and the generic
//! [`Kernel`] over it. The kernel is a *general VM* that invokes JAVM
//! programs (see `~/docs/minimum-v3`). It is **not** block-apply
//! specific — block-apply is layered on top in a separate crate.
//!
//! ## Layering
//!
//! ```text
//!     callers (chain runtime / tests / RPC)
//!                  │
//!         jar-apply  (block-apply, gas, quota — separate crate, later)
//!                  │
//!              nub  (uniform Nub handle over backends)
//!                  │
//!     ┌────────────┼────────────────┐
//!     │                             │
//! nub-arch-local        nub-arch-x86
//! (in-process,         (bare-metal guest,
//!  std)                 no_std + no_main)
//!     │                             │
//!     └────────────┬────────────────┘
//!                  │
//!              nub-kernel  ← this crate
//!              (Arch trait, Kernel<A: Arch>, types)
//! ```
//!
//! ## State
//!
//! The kernel "owns the state": the invoking `Cap::Instance` and
//! everything reachable from it. Concretely the [`Arch`] impl holds
//! the storage (in-process structures for `nub-arch-local`,
//! guest-resident structures for `nub-arch-x86`); the
//! [`Kernel`] is a thin generic wrapper that delegates to the Arch.
//!
//! ## `no_std`
//!
//! This crate is `no_std` by default with an optional `std` feature
//! (currently enabled by default for ergonomics on host targets). The
//! Hyperlight Arch impl will pull the no_std build path; in-process
//! consumers use the std build.

#![cfg_attr(not(feature = "std"), no_std)]

/// 32-byte content hash. Same shape as `javm_cap::CapHash`; defined
/// here locally so this crate stays `no_std`. A future unification
/// pass will share the type once `javm-cap` becomes `no_std`-clean.
pub type CapHash = [u8; 32];

/// Opaque, 32-byte handle to an Instance held by an `Arch`.
///
/// The Arch chooses how to interpret it. For the skeleton both
/// backends use the cap content hash directly, so [`InstanceRef`] is
/// effectively a [`CapHash`] wrapper. If a backend later wants a
/// guest-internal handle (e.g. an index into a guest-side table for
/// cheap lookup), the natural follow-up is to make this an associated
/// type on [`Arch`].
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct InstanceRef(pub [u8; 32]);

impl InstanceRef {
    pub const fn from_hash(hash: CapHash) -> Self {
        Self(hash)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Per-invocation knobs. Empty for the skeleton; fields will land as
/// the kernel grows (gas budget overrides, quota budget, tracing,
/// reentrancy depth limits, …).
#[derive(Copy, Clone, Default, Debug)]
pub struct InvokeOptions {}

/// Result of a successful invocation. Extensible — fields land as
/// needed (gas remaining, post-invocation cap hash, host-call trace,
/// …). For the skeleton we expose only the JAVM HALT return value
/// and gas used.
#[derive(Copy, Clone, Debug)]
pub struct InvokeOutcome {
    pub return_value: u64,
    pub gas_used: u64,
}

/// Low-level CPU/MMU substrate trait. An `Arch` impl runs in the same
/// address space as the [`Kernel`] that calls it — it owns the
/// kernel's state and provides the primitives (page mapping, ring
/// transitions, exception handling, …) needed to execute JAVM
/// programs. The skeleton trait only exposes [`invoke`](Arch::invoke)
/// and [`state_root`](Arch::state_root); the substrate-specific
/// primitives that the kernel will eventually drive (map_pages,
/// install_handler, …) are intentionally not part of the public
/// surface yet — they're encapsulated inside [`Arch::invoke`] for
/// now.
pub trait Arch {
    type Error;

    /// Invoke `endpoint` on the `Cap::Instance` identified by
    /// `target`, passing `args` (SCALE-encoded, by convention). The
    /// Arch impl is responsible for executing the underlying JAVM
    /// program to termination (HALT / yield / fault / gas-exhausted)
    /// and reporting the outcome.
    fn invoke(
        &mut self,
        target: InstanceRef,
        endpoint: u16,
        args: &[u8],
        opts: InvokeOptions,
    ) -> Result<InvokeOutcome, Self::Error>;

    /// Content-addressed root of the Arch's current state — the hash
    /// of the invoking `Cap::Instance` after the most recent
    /// invocation (or genesis if none).
    fn state_root(&self) -> CapHash;
}

/// The kernel: a thin wrapper over an [`Arch`] impl that owns the
/// state. `nub` is the microkernel that this represents; callers use
/// it via the uniform `Nub` handle in the `nub` crate, which selects
/// the backend (local interpreter vs hyperlight RPC) at construction
/// time.
pub struct Kernel<A: Arch> {
    arch: A,
}

impl<A: Arch> Kernel<A> {
    pub const fn new(arch: A) -> Self {
        Self { arch }
    }

    pub fn invoke(
        &mut self,
        target: InstanceRef,
        endpoint: u16,
        args: &[u8],
        opts: InvokeOptions,
    ) -> Result<InvokeOutcome, A::Error> {
        self.arch.invoke(target, endpoint, args, opts)
    }

    pub fn state_root(&self) -> CapHash {
        self.arch.state_root()
    }

    pub fn arch(&self) -> &A {
        &self.arch
    }

    pub fn arch_mut(&mut self) -> &mut A {
        &mut self.arch
    }
}
