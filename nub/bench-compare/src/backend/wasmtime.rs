//! Wasmtime — the optimizing-JIT ceiling, plus two useful contrasts.
//!
//! - `wasmtime_cranelift` — a mature optimizing compiler. Not a fair
//!   fight against a single-pass JIT on compile time, and not meant to
//!   be: it is the *upper bound on generated-code quality* that tells
//!   you how much runtime performance a single-pass design gives up.
//! - `wasmtime_cranelift_fuel` — the same, metered. Paired with the row
//!   above it isolates what metering costs a good JIT, which is how the
//!   report brackets nub's always-on gas.
//! - `wasmtime_winch` — Wasmtime's own single-pass baseline compiler.
//!   The like-for-like design comparison, at zero extra dependency.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use wasmtime::{Config, Engine as WtEngine, Instance as WtInstance, Module, Store, TypedFunc};

use crate::backend::{Caps, Compiled, Compiler, Engine, Family, Instance};

#[derive(Clone, Copy, PartialEq)]
enum Strategy {
    Cranelift,
    Winch,
}

pub fn engines() -> Vec<Box<dyn Engine>> {
    vec![
        Box::new(Wasmtime {
            name: "wasmtime_cranelift",
            strategy: Strategy::Cranelift,
            fuel: false,
        }),
        Box::new(Wasmtime {
            name: "wasmtime_cranelift_fuel",
            strategy: Strategy::Cranelift,
            fuel: true,
        }),
        Box::new(Wasmtime {
            name: "wasmtime_winch",
            strategy: Strategy::Winch,
            fuel: false,
        }),
    ]
}

#[derive(Clone, Copy)]
pub struct Wasmtime {
    name: &'static str,
    strategy: Strategy,
    fuel: bool,
}

impl Wasmtime {
    fn config(&self) -> Config {
        let mut config = Config::new();
        config.strategy(match self.strategy {
            Strategy::Cranelift => wasmtime::Strategy::Cranelift,
            Strategy::Winch => wasmtime::Strategy::Winch,
        });
        config.consume_fuel(self.fuel);
        config
    }
}

impl Engine for Wasmtime {
    fn name(&self) -> &'static str {
        self.name
    }
    fn family(&self) -> Family {
        Family::Wasm32
    }
    fn caps(&self) -> Caps {
        let caps = Caps::new();
        if self.fuel {
            caps.metered()
        } else {
            caps
        }
    }

    fn create(&self) -> Result<Box<dyn Compiler>> {
        let engine =
            WtEngine::new(&self.config()).map_err(|e| anyhow::anyhow!("wasmtime engine: {e}"))?;
        Ok(Box::new(WasmtimeCompiler {
            engine: Arc::new(engine),
            fuel: self.fuel,
        }))
    }
}

struct WasmtimeCompiler {
    engine: Arc<WtEngine>,
    fuel: bool,
}

impl Compiler for WasmtimeCompiler {
    fn compile(&self, path: &Path) -> Result<Box<dyn Compiled>> {
        let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let module = Module::new(&self.engine, &bytes)
            .map_err(|e| anyhow::anyhow!("wasmtime compile: {e}"))?;
        Ok(Box::new(WasmtimeModule {
            engine: Arc::clone(&self.engine),
            module,
            fuel: self.fuel,
        }))
    }
}

struct WasmtimeModule {
    engine: Arc<WtEngine>,
    module: Module,
    fuel: bool,
}

impl Compiled for WasmtimeModule {
    fn spawn(&self) -> Result<Box<dyn Instance>> {
        let mut store = Store::new(&self.engine, ());
        if self.fuel {
            // Maximum budget: fuel accounting runs, but never trips.
            store
                .set_fuel(u64::MAX)
                .map_err(|e| anyhow::anyhow!("set fuel: {e}"))?;
        }
        let instance = WtInstance::new(&mut store, &self.module, &[])
            .map_err(|e| anyhow::anyhow!("wasmtime instantiate: {e}"))?;
        let run = instance
            .get_typed_func::<(), u32>(&mut store, "run")
            .map_err(|e| anyhow::anyhow!("wasm module exports no `run: () -> u32`: {e}"))?;
        Ok(Box::new(WasmtimeInstance {
            store,
            run,
            fuel: self.fuel,
            gas_used: 0,
        }))
    }
}

struct WasmtimeInstance {
    store: Store<()>,
    run: TypedFunc<(), u32>,
    fuel: bool,
    gas_used: u64,
}

impl Instance for WasmtimeInstance {
    fn run(&mut self) -> Result<u32> {
        if self.fuel {
            self.store
                .set_fuel(u64::MAX)
                .map_err(|e| anyhow::anyhow!("set fuel: {e}"))?;
        }
        let value = self
            .run
            .call(&mut self.store, ())
            .map_err(|e| anyhow::anyhow!("wasmtime call: {e}"))?;
        if self.fuel {
            self.gas_used = u64::MAX - self.store.get_fuel().unwrap_or(u64::MAX);
        }
        Ok(value)
    }

    fn gas_used(&self) -> Option<u64> {
        self.fuel.then_some(self.gas_used)
    }
}
