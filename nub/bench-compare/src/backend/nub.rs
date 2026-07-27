//! The subject: nub's PVM2 interpreter, and its JIT's compile path.
//!
//! Three rows:
//!
//! - `nub_interp` — the byte-code interpreter, end to end.
//! - `nub_jit_compile` — x86-64 JIT *emission* only, measured directly
//!   against the recompiler (a pure bytes producer), with no sandbox.
//! - `nub_jit` — the JIT actually executing, inside the KVM sandbox,
//!   under the flat reference personality. This is the row the whole
//!   `nub-flat` crate exists to make possible: running recompiled code
//!   needs the ring-0 substrate in `nub-arch-x86`, which needs a
//!   `GuestPersonality`.
//!
//! The sandbox is a process-wide singleton — the guest-VA window is a
//! single reservation that is never released, even after drop — so
//! every `nub_jit` measurement shares one, and the harness runs one row
//! per process anyway.
//!
//! Both rows are metered. nub has no way to turn gas off, and adding
//! one would fork the interpreter's hottest loop for a path nothing in
//! production exercises. Read the cost of metering off the
//! `polkavm64_recompiler_{no,sync}_gas` and
//! `wasmtime_cranelift{,_fuel}` pairs instead, which bracket it.

use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use nub_arch_local::{PreparedProgram, ProgramInstance};
use nub_program::ProgramBlob;

use crate::backend::{Caps, Compiled, Compiler as BcCompiler, Engine, Family, Instance};

/// Gas ceiling. `i64::MAX`, not `u64::MAX`: the JIT's counter is an
/// `i64` and detects exhaustion by sign, so `u64::MAX` would present as
/// already-negative. Set to the maximum so metering is *instrumented*
/// but never *fires* — we measure the cost of counting, not of tripping.
const GAS: u64 = i64::MAX as u64;

/// Clean halt: `nub-rt`'s trampoline ends in a bare `ecall`, which the
/// linker rewrites to `custom-0 ecalli imm=0`.
const EXIT_HOST_CALL: u32 = 4;

pub fn engines() -> Vec<Box<dyn Engine>> {
    let mut v: Vec<Box<dyn Engine>> = vec![Box::new(NubInterp)];
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        v.push(Box::new(jit::NubJitCompile));
        // Needs /dev/kvm. Absent it, the row drops out rather than
        // failing every measurement.
        if std::path::Path::new("/dev/kvm").exists() {
            v.push(Box::new(sandbox::NubJit));
        }
    }
    v
}

fn load(path: &Path) -> Result<ProgramBlob> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    ProgramBlob::from_bytes(&bytes).map_err(|e| anyhow::anyhow!("decode {}: {e}", path.display()))
}

// ---- interpreter ------------------------------------------------------

#[derive(Clone, Copy)]
pub struct NubInterp;

impl Engine for NubInterp {
    fn name(&self) -> &'static str {
        "nub_interp"
    }
    fn family(&self) -> Family {
        Family::Pvm2
    }
    fn caps(&self) -> Caps {
        // `compiles: false` — an interpreter has no compilation step.
        // `compile()` here only reads and decodes the blob, and predecode
        // belongs to instantiation (it is per-address-space, and it is
        // what `spawn` builds). Reporting a decode time in a table headed
        // "compilation" next to Cranelift's would be a category error.
        // nub's real compile-side number is `nub_jit_compile`.
        Caps::new().metered().slow().preloaded()
    }
    /// No engine object: the interpreter is a function.
    fn create(&self) -> Result<Box<dyn BcCompiler>> {
        Ok(Box::new(NubInterp))
    }
}

impl BcCompiler for NubInterp {
    fn compile(&self, path: &Path) -> Result<Box<dyn Compiled>> {
        Ok(Box::new(InterpModule {
            blob: Arc::new(load(path)?),
        }))
    }
}

struct InterpModule {
    blob: Arc<ProgramBlob>,
}

impl Compiled for InterpModule {
    fn spawn(&self) -> Result<Box<dyn Instance>> {
        // Address-space construction and predecode happen here, not in
        // `run`: every other engine instantiates before the clock
        // starts, so nub must too or its row would carry setup the
        // others do not.
        let prepared = PreparedProgram::new(&self.blob, 0, [0; 4])
            .map_err(|e| anyhow::anyhow!("prepare: {e}"))?;
        let instance = ProgramInstance::new(&prepared.spec());
        Ok(Box::new(InterpInstance {
            instance,
            gas_used: 0,
        }))
    }
}

struct InterpInstance {
    instance: ProgramInstance,
    gas_used: u64,
}

impl Instance for InterpInstance {
    fn run(&mut self) -> Result<u32> {
        let mut handler = nub_arch_local::ExitingEcallHandler;
        let result = self.instance.invoke(&mut handler, GAS);
        if result.exit_reason != EXIT_HOST_CALL || result.exit_arg != 0 {
            bail!(
                "did not halt cleanly: exit_reason={} exit_arg={}",
                result.exit_reason,
                result.exit_arg
            );
        }
        self.gas_used = GAS - result.gas_remaining;
        Ok(result.return_value as u32)
    }

    fn gas_used(&self) -> Option<u64> {
        Some(self.gas_used)
    }
}

// ---- JIT (compile only) -----------------------------------------------

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod jit {
    use super::*;
    use nub_exec::gas_const;
    use nub_program::abi::{CODE_BASE, DATA_BASE};
    use nub_recompiler_x86::codegen::{Compiler, HelperFns};

    /// A plausible JIT window base. Not zero: emitted RIP-relative
    /// displacements are computed against it, and a zero base would put
    /// the context pointer out of disp32 range.
    const JIT_VA_BASE: u64 = 0x4000_0000;

    /// The emitted code is never executed here, so the helper addresses
    /// only have to be non-null.
    fn dummy_helpers() -> HelperFns {
        HelperFns {
            mem_read_u8: 0x1000,
            mem_read_u16: 0x1000,
            mem_read_u32: 0x1000,
            mem_read_u64: 0x1000,
            mem_write_u8: 0x1000,
            mem_write_u16: 0x1000,
            mem_write_u32: 0x1000,
            mem_write_u64: 0x1000,
        }
    }

    #[derive(Clone, Copy)]
    pub struct NubJitCompile;

    impl Engine for NubJitCompile {
        fn name(&self) -> &'static str {
            "nub_jit_compile"
        }
        fn family(&self) -> Family {
            Family::Pvm2
        }
        fn caps(&self) -> Caps {
            Caps::new().metered()
        }
        fn create(&self) -> Result<Box<dyn BcCompiler>> {
            Ok(Box::new(NubJitCompile))
        }
    }

    impl BcCompiler for NubJitCompile {
        fn compile(&self, path: &Path) -> Result<Box<dyn Compiled>> {
            let blob = super::load(path)?;
            // Same load/store gas tier the interpreter derives, so the
            // emitted gas gates are the ones a real run would use.
            let mem_cycles = gas_const::mem_cycles_for(gas_const::accessible_pages(
                DATA_BASE + blob.regions.data_extent() as u32,
                DATA_BASE,
            ));
            let code = blob.code.clone();
            let compiler = Compiler::new(
                dummy_helpers(),
                code.len(),
                JIT_VA_BASE,
                mem_cycles,
                CODE_BASE,
            );
            // black_box so the emission cannot be optimized away — this
            // call *is* the measurement.
            std::hint::black_box(compiler.compile(&code));
            Ok(Box::new(JitModule))
        }
    }

    pub struct JitModule;

    impl Compiled for JitModule {
        fn spawn(&self) -> Result<Box<dyn Instance>> {
            bail!("nub_jit_compile measures emission only; the executing row is `nub_jit`")
        }
    }
}

// ---- JIT (executing, in the KVM sandbox) ------------------------------

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod sandbox {
    use super::*;
    use std::sync::OnceLock;

    /// Path to the flat personality's guest kernel, built by `build.rs`.
    const GUEST_BLOB: &str = env!("NUB_FLAT_GUEST_BLOB");

    /// One sandbox per process, forever. `create_hyperlight` reserves a
    /// process-wide guest-VA window that is never released, so a second
    /// construction fails even after the first is dropped.
    fn nub() -> Result<&'static nub::Nub<nub_flat::Flat>> {
        static SANDBOX: OnceLock<std::result::Result<nub::Nub<nub_flat::Flat>, String>> =
            OnceLock::new();
        SANDBOX
            .get_or_init(|| {
                nub::Nub::create_hyperlight(GUEST_BLOB, nub::NubOptions::default())
                    .map_err(|e| e.to_string())
            })
            .as_ref()
            .map_err(|e| anyhow::anyhow!("create the flat sandbox: {e}"))
    }

    #[derive(Clone, Copy)]
    pub struct NubJit;

    impl Engine for NubJit {
        fn name(&self) -> &'static str {
            "nub_jit"
        }
        fn family(&self) -> Family {
            Family::Pvm2
        }
        fn caps(&self) -> Caps {
            // Compiling happens lazily inside the guest on first entry,
            // so there is no host-side compile step to time here —
            // `nub_jit_compile` is that measurement. And every invoke
            // builds a fresh frame, so `spawn` cannot hoist setup out
            // of the timed region the way it can for other engines.
            Caps::new().metered().preloaded().rebuilds_per_run()
        }
        fn create(&self) -> Result<Box<dyn BcCompiler>> {
            nub()?;
            Ok(Box::new(NubJit))
        }
    }

    impl BcCompiler for NubJit {
        fn compile(&self, path: &Path) -> Result<Box<dyn Compiled>> {
            let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
            // Publishing is idempotent and content-addressed, so
            // re-publishing the same program across samples is a
            // hash-table hit in the guest.
            let hash = nub()?
                .put_object(&bytes)
                .map_err(|e| anyhow::anyhow!("publish: {e}"))?;
            Ok(Box::new(JitSandboxModule { hash }))
        }
    }

    struct JitSandboxModule {
        hash: nub::ObjHash,
    }

    impl Compiled for JitSandboxModule {
        fn spawn(&self) -> Result<Box<dyn Instance>> {
            // The guest builds its frame per invocation, so there is
            // nothing to instantiate ahead of time. That makes
            // `nub_jit`'s `runtime` and `oneshot` rows identical by
            // construction — the honest reflection of a design where
            // every invocation gets a fresh address space.
            Ok(Box::new(JitSandboxInstance {
                hash: self.hash,
                gas_used: 0,
            }))
        }

        /// Drop every compiled image in the guest, so the next entry
        /// pays a full recompile.
        fn reset_compilation(&self) -> Result<()> {
            nub()?
                .evict_jit_all()
                .map_err(|e| anyhow::anyhow!("evict jit: {e}"))
        }
    }

    struct JitSandboxInstance {
        hash: nub::ObjHash,
        gas_used: u64,
    }

    impl Instance for JitSandboxInstance {
        fn run(&mut self) -> Result<u32> {
            let result = nub()?
                .invoke_cached(self.hash, 0, [0; 4], GAS)
                .map_err(|e| anyhow::anyhow!("invoke: {e}"))?;
            if result.exit_reason != EXIT_HOST_CALL || result.exit_arg != 0 {
                bail!(
                    "did not halt cleanly: exit_reason={} exit_arg={}",
                    result.exit_reason,
                    result.exit_arg
                );
            }
            self.gas_used = GAS - result.gas_remaining;
            Ok(result.return_value as u32)
        }

        fn gas_used(&self) -> Option<u64> {
            Some(self.gas_used)
        }
    }
}
