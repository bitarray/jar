//! PolkaVM — the closest comparison there is.
//!
//! Same ISA family (a RISC-V derivative), same problem statement (a
//! metered VM for a blockchain), and a mature interpreter/recompiler
//! pair. If nub is slower than polkavm at the same job, that is the
//! number that matters.
//!
//! Four rows, and the split is deliberate: `no_gas` / `sync_gas` /
//! `async_gas` on the recompiler is the reference measurement of *what
//! metering costs a JIT*. nub cannot produce that pair itself (it has
//! no unmetered mode), so this triple is how the report brackets nub's
//! always-on metering.

use std::path::Path;

use anyhow::{Context, Result};
use polkavm::{
    ArcBytes, Config, Engine as PvmEngine, Gas, GasMeteringKind, Instance as PvmInstance, Linker,
    Module, ModuleConfig, ProgramBlob, ProgramCounter,
};

/// `polkavm::Gas` is `i64`, so the maximum budget is `i64::MAX`, not
/// `u64::MAX` — same reason nub uses `i64::MAX`.
const GAS_MAX: Gas = Gas::MAX;

use crate::backend::{Caps, Compiled, Engine, Family, Instance};

pub fn engines() -> Vec<Box<dyn Engine>> {
    let mut v: Vec<Box<dyn Engine>> = vec![Box::new(PolkaVm {
        name: "polkavm64_interpreter",
        backend: polkavm::BackendKind::Interpreter,
        gas: None,
    })];

    // The recompiler is x86-64/aarch64 only, and needs a usable sandbox.
    if polkavm::BackendKind::Compiler.is_supported() {
        v.push(Box::new(PolkaVm {
            name: "polkavm64_recompiler_no_gas",
            backend: polkavm::BackendKind::Compiler,
            gas: None,
        }));
        v.push(Box::new(PolkaVm {
            name: "polkavm64_recompiler_sync_gas",
            backend: polkavm::BackendKind::Compiler,
            gas: Some(GasMeteringKind::Sync),
        }));
        v.push(Box::new(PolkaVm {
            name: "polkavm64_recompiler_async_gas",
            backend: polkavm::BackendKind::Compiler,
            gas: Some(GasMeteringKind::Async),
        }));
    }
    v
}

#[derive(Clone, Copy)]
pub struct PolkaVm {
    name: &'static str,
    backend: polkavm::BackendKind,
    gas: Option<GasMeteringKind>,
}

impl Engine for PolkaVm {
    fn name(&self) -> &'static str {
        self.name
    }
    fn family(&self) -> Family {
        Family::Polkavm64
    }
    fn caps(&self) -> Caps {
        let caps = Caps::new();
        let caps = if self.gas.is_some() {
            caps.metered()
        } else {
            caps
        };
        if self.backend == polkavm::BackendKind::Interpreter {
            caps.slow()
        } else {
            caps
        }
    }

    fn compile(&self, path: &Path) -> Result<Box<dyn Compiled>> {
        let mut config = Config::from_env().unwrap_or_default();
        config.set_backend(Some(self.backend));
        config.set_allow_experimental(true);
        let engine = PvmEngine::new(&config).context("polkavm engine")?;

        let bytes: ArcBytes = std::fs::read(path)
            .with_context(|| format!("read {}", path.display()))?
            .into();
        let blob = ProgramBlob::parse(bytes).map_err(|e| anyhow::anyhow!("parse blob: {e}"))?;

        let mut module_config = ModuleConfig::default();
        module_config.set_gas_metering(self.gas);
        let module = Module::from_blob(&engine, &module_config, blob)
            .map_err(|e| anyhow::anyhow!("compile: {e}"))?;

        let run = module
            .exports()
            .find(|e| e.symbol() == "run")
            .map(|e| e.program_counter())
            .context("polkavm blob exports no `run`")?;

        Ok(Box::new(PolkaVmModule {
            module,
            run,
            metered: self.gas.is_some(),
        }))
    }
}

struct PolkaVmModule {
    module: Module,
    run: ProgramCounter,
    metered: bool,
}

impl Compiled for PolkaVmModule {
    fn spawn(&self) -> Result<Box<dyn Instance>> {
        let linker = Linker::<(), String>::new();
        let instance = linker
            .instantiate_pre(&self.module)
            .map_err(|e| anyhow::anyhow!("pre-instantiate: {e}"))?
            .instantiate()
            .map_err(|e| anyhow::anyhow!("instantiate: {e}"))?;
        Ok(Box::new(PolkaVmInstance {
            instance,
            run: self.run,
            metered: self.metered,
            gas_used: 0,
        }))
    }
}

struct PolkaVmInstance {
    instance: PvmInstance<(), String>,
    run: ProgramCounter,
    metered: bool,
    gas_used: u64,
}

impl Instance for PolkaVmInstance {
    fn run(&mut self) -> Result<u32> {
        if self.metered {
            // Maximum budget: instrumentation runs, but never fires.
            self.instance.set_gas(GAS_MAX);
        }
        let value: u32 = self
            .instance
            .call_typed_and_get_result::<u32, ()>(&mut (), self.run, ())
            .map_err(|e| anyhow::anyhow!("call: {e:?}"))?;
        if self.metered {
            self.gas_used = GAS_MAX.saturating_sub(self.instance.gas()) as u64;
        }
        Ok(value)
    }

    fn gas_used(&self) -> Option<u64> {
        self.metered.then_some(self.gas_used)
    }
}
