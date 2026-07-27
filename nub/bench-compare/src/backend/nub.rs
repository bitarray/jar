//! The subject: nub's PVM2 interpreter, and its JIT's compile path.
//!
//! Two rows today:
//!
//! - `nub_interp` — the byte-code interpreter, end to end.
//! - `nub_jit_compile` — x86-64 JIT *emission* only. The recompiler is
//!   a pure bytes producer, so its compile time is measurable with no
//!   sandbox and no guest kernel. Executing that output needs the ring-0
//!   substrate in `nub-arch-x86`, which needs a `GuestPersonality`;
//!   until nub ships its reference personality there is no
//!   `nub_jit` runtime row, and `spawn` here reports that honestly
//!   rather than silently measuring something else.
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

use crate::backend::{Caps, Compiled, Engine, Family, Instance};

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
    v.push(Box::new(jit::NubJitCompile));
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
        Caps::new().metered().slow()
    }
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
            bail!(
                "nub_jit_compile measures emission only; executing JIT output needs the \
                 ring-0 substrate in nub-arch-x86, i.e. a GuestPersonality"
            )
        }
    }
}
