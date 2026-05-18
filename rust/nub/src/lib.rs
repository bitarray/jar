//! Nub: the JAR v3 microkernel — uniform caller-facing handle.
//!
//! The [`Nub`] handle is the API callers (chain runtime, tests, RPC,
//! `jar-apply`) link against. It hides the choice of substrate behind
//! a single invoke surface, dispatching to one of two backends:
//!
//! - **Local**: runs `Kernel<nub_arch_local::LocalArch>` directly
//!   in-process. Used for tests, deterministic replay, and any host
//!   that doesn't need real ring-0 isolation.
//!
//! - **Hyperlight**: ships the invocation as an RPC into a
//!   `nub-arch-x86` guest binary running inside a Hyperlight
//!   sandbox. The actual `Kernel<HyperlightArch>` lives guest-side;
//!   the host holds only the sandbox + an `InstanceRef` table.
//!
//! Both backends share the [`nub_kernel::Arch`] trait surface
//! ([`invoke`](Nub::invoke) + [`state_root`](Nub::state_root)). The
//! current skeleton implementation returns a fixed value (42) from
//! either backend, just to exercise the wiring.

use anyhow::Result;
use nub_host_kvm::sandbox::{
    GuestBinary, MultiUseSandbox, SandboxConfiguration, UninitializedSandbox,
};
use nub_arch_local::LocalArch;
use nub_kernel::Kernel;

pub use nub_arch_x86_abi::{InvocationResult, InvocationSpec, PvmRegs};
pub use nub_kernel::{CapHash, InstanceRef, InvokeOptions, InvokeOutcome};

use scale::{Decode, Encode};

/// Path to the cross-compiled Hyperlight guest blob. Set by
/// `build.rs` via [`nub_build::build`].
const NUB_ARCH_X86_BLOB_PATH: &str = env!("NUB_ARCH_X86_BLOB");

/// Uniform handle to the nub microkernel.
pub struct Nub {
    backend: Backend,
}

enum Backend {
    Local(Kernel<LocalArch>),
    Hyperlight(Box<HyperlightDriver>),
}

/// Host-side RPC stub for the Hyperlight backend. The real kernel
/// lives guest-side; this wrapper just ships invocations into the
/// sandbox.
struct HyperlightDriver {
    sandbox: MultiUseSandbox,
    state_root_cache: CapHash,
}

impl Nub {
    /// Construct a Nub backed by the in-process [`LocalArch`].
    pub fn new_local() -> Self {
        Self {
            backend: Backend::Local(Kernel::new(LocalArch::new())),
        }
    }

    /// Construct a Nub backed by a fresh Hyperlight sandbox loaded
    /// from the `nub-arch-x86` guest blob.
    pub fn new_hyperlight() -> Result<Self> {
        // Scratch budget covers the per-process pool inside the guest
        // (`nub-arch-x86::pool`): mem + perms + bb + jt + jit +
        // arena + a few page-sized side buffers. Sized to ~144 MiB so
        // the largest bench programs fit with comfortable headroom.
        //
        // Input / output buffers: the host SCALE-encodes an
        // `InvocationSpec` (containing the program's full code +
        // bitmask + jump table + initial data regions) and ships it
        // via Hyperlight's input-data ring. Default 16 KiB is
        // exhausted by guest-tests' multi-endpoint Image.
        let mut cfg = SandboxConfiguration::default();
        // Sized post-Stage-F: forked host (nub-host-kvm) + forked
        // guest-bin still mark writable pages CoW so the host's
        // snapshot machinery has somewhere to roll back from. The
        // leak that motivated the fork is bounded by the heap size —
        // every heap page CoW-resolves once into a fresh scratch
        // frame, then the working set asymptotes. With a 64 MiB heap
        // the worst-case CoW consumption is ~64 MiB; plus the
        // per-process pool (~94 MiB; see `nub-arch-x86::pool`),
        // plus a small stack-growth allowance, comfortably fits in
        // 192 MiB scratch. Without the bench-era 1 GiB heap, the
        // criterion default sample sizes no longer blow the budget.
        cfg.set_scratch_size(512 * 1024 * 1024);
        cfg.set_input_data_size(16 * 1024 * 1024);
        cfg.set_output_data_size(16 * 1024 * 1024);
        cfg.set_heap_size(256 * 1024 * 1024);
        let uninit = UninitializedSandbox::new(
            GuestBinary::FilePath(NUB_ARCH_X86_BLOB_PATH.to_string()),
            Some(cfg),
        )?;
        let sandbox = uninit.evolve()?;
        Ok(Self {
            backend: Backend::Hyperlight(Box::new(HyperlightDriver {
                sandbox,
                state_root_cache: [0; 32],
            })),
        })
    }

    /// Invoke `endpoint` on `target` with `args`.
    pub fn invoke(
        &mut self,
        target: InstanceRef,
        endpoint: u16,
        args: &[u8],
        opts: InvokeOptions,
    ) -> Result<InvokeOutcome> {
        match &mut self.backend {
            Backend::Local(k) => Ok(k
                .invoke(target, endpoint, args, opts)
                .expect("LocalArch::Error is uninhabited")),
            Backend::Hyperlight(h) => h.invoke(target, endpoint, args, opts),
        }
    }

    /// Current state root.
    pub fn state_root(&self) -> CapHash {
        match &self.backend {
            Backend::Local(k) => k.state_root(),
            Backend::Hyperlight(h) => h.state_root_cache,
        }
    }

    /// Direct-spec invocation path (Stage 2.2). Ships a pre-built
    /// `InvocationSpec` straight into the backend, bypassing the
    /// (still-skeletal) `Arch::invoke` trait. The Hyperlight backend
    /// SCALE-encodes the spec and calls the guest's `nub_invoke`
    /// guest_function; the local backend returns a stub for now
    /// (Stage 3 will switch the local arm to the interpreter).
    pub fn invoke_spec(&mut self, spec: &InvocationSpec) -> Result<InvocationResult> {
        match &mut self.backend {
            Backend::Local(_) => Ok(InvocationResult {
                exit_reason: 4,
                exit_arg: 0,
                return_value: 42,
                gas_remaining: spec.initial_gas,
            }),
            Backend::Hyperlight(h) => {
                let bytes = spec.encode();
                let result_bytes: Vec<u8> = h.sandbox.call("nub_invoke", bytes)?;
                let (result, _consumed) = InvocationResult::decode(&result_bytes)
                    .map_err(|e| anyhow::anyhow!("decode InvocationResult: {e:?}"))?;
                Ok(result)
            }
        }
    }
}

impl HyperlightDriver {
    fn invoke(
        &mut self,
        _target: InstanceRef,
        _endpoint: u16,
        _args: &[u8],
        _opts: InvokeOptions,
    ) -> Result<InvokeOutcome> {
        // Skeleton: ship a fixed RPC into the guest. The guest's
        // `nub_smoke` returns 42, matching `LocalArch`'s stub. Real
        // dispatch (target / endpoint / args wired through) lands
        // alongside the guest-side `Kernel<HyperlightArch>`.
        let return_value: u64 = self.sandbox.call("nub_smoke", ())?;
        Ok(InvokeOutcome {
            return_value,
            gas_used: 0,
        })
    }
}
