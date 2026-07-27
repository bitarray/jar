//! The native floor: the kernel compiled for the host and `dlopen`ed.
//!
//! Every other number in the suite is only meaningful relative to this
//! one. It answers "what does this computation cost with no engine at
//! all", so the interesting figure is always `vs native`.
//!
//! Loaded through `dlopen` rather than linked directly, deliberately.
//! A direct call would let LTO inline the kernel into the timing loop
//! and const-fold across the boundary — the kernels take no arguments
//! and return a constant for a given input, so a sufficiently clever
//! optimizer could compute the answer at build time and measure
//! nothing. Going through a shared object makes the call opaque, which
//! is also exactly what the other engines' FFI boundaries do.

use std::path::Path;

use anyhow::{Context, Result};

use crate::backend::{Caps, Compiled, Engine, Family, Instance};

#[derive(Clone, Copy)]
pub struct Native;

impl Engine for Native {
    fn name(&self) -> &'static str {
        "native"
    }

    fn family(&self) -> Family {
        Family::Native
    }

    fn caps(&self) -> Caps {
        // The OS loader did the work, and it is not gas-metered.
        Caps::new().preloaded()
    }

    fn compile(&self, path: &Path) -> Result<Box<dyn Compiled>> {
        let library = unsafe { libloading::Library::new(path) }
            .with_context(|| format!("dlopen {}", path.display()))?;
        Ok(Box::new(NativeModule { library }))
    }
}

struct NativeModule {
    library: libloading::Library,
}

impl Compiled for NativeModule {
    fn spawn(&self) -> Result<Box<dyn Instance>> {
        let symbol: libloading::Symbol<'_, unsafe extern "C" fn() -> u32> =
            unsafe { self.library.get(b"run\0") }.context("no `run` symbol in the cdylib")?;
        // The symbol borrows the library; the library outlives every
        // instance we hand out (it is owned by the module, which the
        // driver keeps alive for the whole measurement), so detaching
        // the lifetime here is sound.
        let run: unsafe extern "C" fn() -> u32 = *symbol;
        Ok(Box::new(NativeInstance { run }))
    }
}

struct NativeInstance {
    run: unsafe extern "C" fn() -> u32,
}

impl Instance for NativeInstance {
    fn run(&mut self) -> Result<u32> {
        Ok(unsafe { (self.run)() })
    }
}
