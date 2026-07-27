//! Wasmer Singlepass — the design analogue.
//!
//! nub's x86-64 recompiler is a single-pass JIT: one linear walk over
//! the bytecode, no IR, no register allocator, optimizing for compile
//! latency over code quality. Singlepass is a mature implementation of
//! exactly that trade-off, which makes it the row that answers the
//! question nub's JIT actually has to answer — not "are we as fast as
//! Cranelift" (we are not trying to be) but "is our codegen competitive
//! with a good single-pass compiler at a comparable compile cost".
//!
//! Unmetered: Singlepass has no fuel equivalent, so the row is flagged
//! as such rather than pretending to be comparable to a metered one.

use std::path::Path;

use anyhow::{Context, Result};
use wasmer::{imports, sys::EngineBuilder, Instance as WrInstance, Module, Store, TypedFunction};

use crate::backend::{Caps, Compiled, Engine, Family, Instance};

pub fn engines() -> Vec<Box<dyn Engine>> {
    vec![Box::new(WasmerSinglepass)]
}

#[derive(Clone, Copy)]
pub struct WasmerSinglepass;

impl Engine for WasmerSinglepass {
    fn name(&self) -> &'static str {
        "wasmer_singlepass"
    }
    fn family(&self) -> Family {
        Family::Wasm32
    }
    fn caps(&self) -> Caps {
        Caps::new()
    }

    fn compile(&self, path: &Path) -> Result<Box<dyn Compiled>> {
        let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let compiler = wasmer_compiler_singlepass::Singlepass::new();
        let mut store = Store::new(EngineBuilder::new(compiler));
        let module = Module::new(&store, &bytes).context("wasmer compile")?;
        // Compilation is what this call is timed for; drop the store so
        // each spawn gets a fresh one.
        let _ = &mut store;
        Ok(Box::new(WasmerModule { bytes, module }))
    }
}

struct WasmerModule {
    bytes: Vec<u8>,
    module: Module,
}

impl Compiled for WasmerModule {
    fn spawn(&self) -> Result<Box<dyn Instance>> {
        // Wasmer ties a Module to the Store that compiled it, so a
        // fresh store means re-creating the module. Re-compiling here
        // would smuggle compile time into an untimed phase and make the
        // runtime row look identical to the oneshot row, so instead we
        // keep one store per instance and pay the cost knowingly at
        // spawn — which is untimed, as it is for every other engine.
        let compiler = wasmer_compiler_singlepass::Singlepass::new();
        let mut store = Store::new(EngineBuilder::new(compiler));
        let module = Module::new(&store, &self.bytes).context("wasmer re-compile for store")?;
        let instance =
            WrInstance::new(&mut store, &module, &imports! {}).context("wasmer instantiate")?;
        let run: TypedFunction<(), u32> = instance
            .exports
            .get_typed_function(&store, "run")
            .context("wasm module exports no `run: () -> u32`")?;
        Ok(Box::new(WasmerInstance { store, run }))
    }
}

struct WasmerInstance {
    store: Store,
    run: TypedFunction<(), u32>,
}

impl Instance for WasmerInstance {
    fn run(&mut self) -> Result<u32> {
        self.run.call(&mut self.store).context("wasmer call")
    }
}

/// Silences the unused-field warning on `module` when only `bytes` is
/// needed at spawn time; the field is kept because holding the compiled
/// module is what makes `compile` a real measurement.
#[allow(dead_code)]
fn _keep(m: &WasmerModule) -> &Module {
    &m.module
}
