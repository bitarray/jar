//! The engine abstraction every comparison row implements.
//!
//! # The lifecycle, and why it has these seams
//!
//! ```text
//!   create()          -> Compiler    # once per engine   — UNTIMED
//!       compile(path) -> Compiled    # timed by `compilation`
//!           spawn()   -> Instance    # once per sample   — UNTIMED
//!               run() -> u32         # timed by `runtime`
//! ```
//!
//! Two of these seams exist purely so the comparison measures the same
//! thing for everyone, and both were bugs before they were seams.
//!
//! `create`/`compile`: constructing an engine reserves guard regions,
//! builds a code allocator and may spawn worker threads. That is a
//! once-per-process cost in real use, but nub has no engine object at
//! all — so folding it into `compile` would have flattered nub by
//! roughly a millisecond against Wasmtime and PolkaVM.
//!
//! `spawn`/`run`: every engine does per-invocation setup — Wasmtime
//! instantiates a store and zeroes linear memory, nub builds its flat
//! address space and predecodes. Putting that inside `run` for one
//! engine and inside `spawn` for another would compare different work.
//! So `spawn` is everything up to "ready to execute", and only `run` is
//! timed.
//!
//! # Dispatch
//!
//! `Box<dyn>`, not monomorphized generics. The vcall costs ~2 ns per
//! `run()`; the fastest row in this suite is a native hash at a few µs,
//! so it is under 0.1% — and every engine pays it identically, so it
//! cannot tilt the comparison. The alternative (benchtool's
//! `define_backends!` sum-type macro) buys that 0.1% for a few hundred
//! lines of macro.
//!
//! # Metering
//!
//! [`Caps::metered`] is reported, never corrected for. Gas is an axis of
//! the comparison, not a confounder to normalize away — see the fairness
//! rules in `README.md`.

use std::path::Path;

use anyhow::Result;

/// Which artifact family an engine consumes. One kernel is compiled to
/// each of these; see `bench-build`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    /// nub's own format: a linked `nub_program::ProgramBlob`.
    Pvm2,
    /// A host cdylib, loaded with `dlopen`.
    Native,
    /// A `wasm32-unknown-unknown` module.
    Wasm32,
    /// A polkavm program blob (RV64EMAC).
    Polkavm64,
}

impl Family {
    pub fn dir(self) -> &'static str {
        match self {
            Family::Pvm2 => "pvm2",
            Family::Native => "native",
            Family::Wasm32 => "wasm32",
            Family::Polkavm64 => "polkavm64",
        }
    }

    pub fn ext(self) -> &'static str {
        match self {
            Family::Pvm2 => "nubp",
            Family::Native => "so",
            Family::Wasm32 => "wasm",
            Family::Polkavm64 => "polkavm",
        }
    }
}

/// What a row can do, and what it costs to do it.
#[derive(Debug, Clone, Copy)]
pub struct Caps {
    /// Has a distinct, measurable compile step, so `compilation/*` is
    /// meaningful. False for `native` (the OS loader did it).
    pub compiles: bool,
    /// Charges gas / fuel / cycles while running. Drives the report's
    /// `metered` column; never used to adjust a number.
    pub metered: bool,
    /// Interpreter-class: orders of magnitude slower, so the harness
    /// takes fewer samples rather than making everyone wait.
    pub slow: bool,
}

impl Caps {
    pub const fn new() -> Self {
        Caps {
            compiles: true,
            metered: false,
            slow: false,
        }
    }
    pub const fn metered(mut self) -> Self {
        self.metered = true;
        self
    }
    pub const fn slow(mut self) -> Self {
        self.slow = true;
        self
    }
    pub const fn preloaded(mut self) -> Self {
        self.compiles = false;
        self
    }
}

impl Default for Caps {
    fn default() -> Self {
        Self::new()
    }
}

/// One comparison row.
pub trait Engine {
    /// Row name in the report, lowercase snake:
    /// `{engine}[_{backend}][_{metering}]`.
    fn name(&self) -> &'static str;

    fn family(&self) -> Family;

    fn caps(&self) -> Caps;

    /// Build the engine: guard regions, code allocator, worker threads.
    /// Untimed — a once-per-process cost in real use.
    fn create(&self) -> Result<Box<dyn Compiler>>;
}

/// A live engine, ready to compile programs.
pub trait Compiler {
    /// Load and compile one program. This is the `compilation` measurement.
    fn compile(&self, path: &Path) -> Result<Box<dyn Compiled>>;
}

/// A compiled program, ready to be instantiated.
pub trait Compiled {
    /// Build a fresh instance. Untimed — see the module docs.
    fn spawn(&self) -> Result<Box<dyn Instance>>;

    /// Discard any cached compilation, so the next run recompiles.
    ///
    /// Only `nub_jit` needs this: it compiles lazily *inside the guest*
    /// on first entry and caches the result per program, so without an
    /// evict its second sample would measure execution alone while
    /// every other engine's `oneshot` sample really does recompile.
    /// Default is a no-op, which is correct for engines that compile
    /// eagerly in [`Compiler::compile`].
    fn reset_compilation(&self) -> Result<()> {
        Ok(())
    }
}

/// An instance, ready to execute.
pub trait Instance {
    /// Execute once and return the kernel's `u32`. This is the timed
    /// unit, and the returned value is what `validate` compares across
    /// engines.
    fn run(&mut self) -> Result<u32>;

    /// Gas / fuel / cycles consumed by the last [`run`](Self::run).
    /// Reported for information; never compared across engines, whose
    /// counters have incomparable semantics.
    fn gas_used(&self) -> Option<u64> {
        None
    }
}

/// Every row that can run on this host, in report order.
///
/// Engines absent at compile time (feature off) or unavailable at run
/// time (no such backend on this CPU) simply do not appear, rather than
/// appearing and failing.
pub fn registry() -> Vec<Box<dyn Engine>> {
    let mut engines: Vec<Box<dyn Engine>> = Vec::new();

    engines.push(Box::new(crate::backend::native::Native));

    engines.extend(crate::backend::nub::engines());

    #[cfg(feature = "polkavm-engine")]
    engines.extend(crate::backend::polkavm::engines());

    #[cfg(feature = "wasmtime-engine")]
    engines.extend(crate::backend::wasmtime::engines());

    #[cfg(feature = "wasmer-engine")]
    engines.extend(crate::backend::wasmer::engines());

    #[cfg(feature = "wasmi-engine")]
    engines.extend(crate::backend::wasmi::engines());

    engines
}

pub mod native;
pub mod nub;

#[cfg(feature = "polkavm-engine")]
pub mod polkavm;
#[cfg(feature = "wasmer-engine")]
pub mod wasmer;
#[cfg(feature = "wasmi-engine")]
pub mod wasmi;
#[cfg(feature = "wasmtime-engine")]
pub mod wasmtime;
