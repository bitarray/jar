//! Wasmi — the interpreter analogue.
//!
//! Opt-in (`--features wasmi-engine`), because the interpreter question
//! is already answered by `polkavm64_interpreter`, which is a much
//! closer comparison: same ISA family, same metered-VM problem. Wasmi
//! is a different bet — a register-machine wasm interpreter — so it is
//! a useful second data point on how fast a well-built interpreter can
//! be, without being the reference nub is measured against.
//!
//! Unmetered, and flagged as such: wasmi has fuel metering, but this
//! row does not enable it.

use anyhow::Result;
use wasmi::{Engine as WiEngine, Instance as WiInstance, Linker, Module, Store, TypedFunc};

use crate::backend::{Artifact, Caps, Compiled, Compiler, Engine, Family, Instance};

pub fn engines() -> Vec<Box<dyn Engine>> {
    vec![Box::new(Wasmi)]
}

#[derive(Clone, Copy)]
pub struct Wasmi;

impl Engine for Wasmi {
    fn name(&self) -> &'static str {
        "wasmi"
    }
    fn family(&self) -> Family {
        Family::Wasm32
    }
    fn caps(&self) -> Caps {
        Caps::new().slow()
    }

    fn create(&self) -> Result<Box<dyn Compiler>> {
        Ok(Box::new(WasmiCompiler {
            engine: WiEngine::default(),
        }))
    }
}

struct WasmiCompiler {
    engine: WiEngine,
}

impl Compiler for WasmiCompiler {
    fn compile(&self, artifact: &Artifact) -> Result<Box<dyn Compiled>> {
        let module = Module::new(&self.engine, &artifact.bytes[..])
            .map_err(|e| anyhow::anyhow!("wasmi compile: {e}"))?;
        Ok(Box::new(WasmiModule {
            engine: self.engine.clone(),
            module,
        }))
    }
}

struct WasmiModule {
    engine: WiEngine,
    module: Module,
}

impl Compiled for WasmiModule {
    fn spawn(&self) -> Result<Box<dyn Instance>> {
        let mut store = Store::new(&self.engine, ());
        let linker = Linker::<()>::new(&self.engine);
        let instance: WiInstance = linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| anyhow::anyhow!("wasmi instantiate: {e}"))?
            .start(&mut store)
            .map_err(|e| anyhow::anyhow!("wasmi start: {e}"))?;
        let run = instance
            .get_typed_func::<(), u32>(&store, "run")
            .map_err(|e| anyhow::anyhow!("wasm module exports no `run: () -> u32`: {e}"))?;
        Ok(Box::new(WasmiInstance { store, run }))
    }
}

struct WasmiInstance {
    store: Store<()>,
    run: TypedFunc<(), u32>,
}

impl Instance for WasmiInstance {
    fn run(&mut self) -> Result<u32> {
        self.run
            .call(&mut self.store, ())
            .map_err(|e| anyhow::anyhow!("wasmi call: {e}"))
    }
}
