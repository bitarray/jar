//! Solana's sBPF, via `solana-sbpf` — interpreter and x86-64 JIT.
//!
//! Two metered rows, mirroring nub's own split. sBPF's meter is the
//! `ContextObject` trait rather than a counter register, but the
//! fairness rule is the same as everywhere else: set it to maximum so
//! the instrumentation runs on every instruction and never fires.
//!
//! # What this row does and does not tell you
//!
//! Three of the ten kernels are absent, for reasons that belong to the
//! platform rather than to our build of it — a writable `static mut`,
//! a 4 KiB stack frame against k256, and `u128` field arithmetic. See
//! `SBPF_UNSUPPORTED` in `bench-build`.
//!
//! Of the seven that remain, **five run a different multiply than every
//! other engine.** LLVM's BPF backend cannot lower a 64x64 widening
//! multiply, so `gp::mul` has a `cfg(target_arch = "bpf")` arm that
//! reassembles the product from four 32x32 partials. It is verified
//! bit-identical, so the returned values match and `validate` passes —
//! but `goldilocks-mul`, `poseidon2-perm`, `mini-verifier`, `poly-eval`
//! and `fri-fold-tree` are measuring a different program here, not just
//! a different VM. The report says so; do not quietly compare those
//! five against the other engines.
//!
//! # Memory is the harness's choice
//!
//! Solana's on-chain policy is a 32 KiB heap, which two of these
//! kernels exceed. We are measuring the VM, not the chain's resource
//! policy, so the harness maps a 256 KiB heap — the same spirit as
//! setting gas counters to maximum. The stack and frame limits are left
//! at solana-sbpf's own defaults, because those *are* the ISA.

use std::ptr::NonNull;
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use solana_sbpf::{
    aligned_memory::AlignedMemory,
    ebpf,
    elf::Executable,
    error::ProgramResult,
    memory_region::{MemoryMapping, MemoryRegion},
    program::BuiltinProgram,
    verifier::RequisiteVerifier,
    vm::{CallFrame, Config, ContextObject, EbpfVm, ExecutionMode},
};

use crate::backend::{Artifact, Caps, Compiled, Compiler as BcCompiler, Engine, Family, Instance};

/// Must match the `HEAP_LEN` the guest allocator in
/// `guests/bench-abi.rs` bumps through. They are two halves of one
/// contract: the guest assumes this region exists at `MM_HEAP_START`.
const HEAP_LEN: usize = 256 * 1024;

/// Meter ceiling. Maximum so metering is instrumented but never fires.
const METER: u64 = i64::MAX as u64;

/// The instruction meter, and the owner of the memory mapping.
struct Ctx {
    remaining: u64,
    consumed: u64,
    mapping: MemoryMapping,
}

impl ContextObject for Ctx {
    fn consume(&mut self, amount: u64) {
        self.consumed = self.consumed.saturating_add(amount);
        self.remaining = self.remaining.saturating_sub(amount);
    }
    fn get_remaining(&self) -> u64 {
        self.remaining
    }
    fn active_mapping_ptr(&mut self) -> NonNull<MemoryMapping> {
        NonNull::from(&mut self.mapping)
    }
}

pub fn engines() -> Vec<Box<dyn Engine>> {
    let mut v: Vec<Box<dyn Engine>> = vec![Box::new(SbpfInterpreter)];
    #[cfg(target_arch = "x86_64")]
    v.push(Box::new(SbpfJit));
    v
}

#[derive(Clone, Copy)]
pub struct SbpfInterpreter;

impl Engine for SbpfInterpreter {
    fn name(&self) -> &'static str {
        "sbpf_interpreter"
    }
    fn family(&self) -> Family {
        Family::Sbf
    }
    fn caps(&self) -> Caps {
        Caps::new().metered().slow()
    }
    fn create(&self) -> Result<Box<dyn BcCompiler>> {
        Ok(Box::new(SbpfCompiler { jit: false }))
    }
}

#[derive(Clone, Copy)]
pub struct SbpfJit;

impl Engine for SbpfJit {
    fn name(&self) -> &'static str {
        "sbpf_jit"
    }
    fn family(&self) -> Family {
        Family::Sbf
    }
    fn caps(&self) -> Caps {
        Caps::new().metered()
    }
    fn create(&self) -> Result<Box<dyn BcCompiler>> {
        Ok(Box::new(SbpfCompiler { jit: true }))
    }
}

struct SbpfCompiler {
    /// `ExecutionMode` is neither `Copy` nor `Clone` and
    /// `execute_program` takes it by `&mut`, so carry the choice as a
    /// flag and build the mode per run.
    jit: bool,
}

impl BcCompiler for SbpfCompiler {
    fn compile(&self, artifact: &Artifact) -> Result<Box<dyn Compiled>> {
        let loader = Arc::new(BuiltinProgram::new_loader(Config::default()));
        let exe = Executable::<Ctx>::from_elf(&artifact.bytes, loader.clone())
            .map_err(|e| anyhow!("load sbpf elf: {e:?}"))?;
        exe.verify::<RequisiteVerifier>()
            .map_err(|e| anyhow!("verify: {e:?}"))?;
        if self.jit {
            exe.jit_compile().map_err(|e| anyhow!("jit: {e:?}"))?;
        }
        Ok(Box::new(SbpfModule {
            exe: Arc::new(exe),
            loader,
            jit: self.jit,
        }))
    }
}

struct SbpfModule {
    exe: Arc<Executable<Ctx>>,
    loader: Arc<BuiltinProgram<Ctx>>,
    jit: bool,
}

impl Compiled for SbpfModule {
    fn spawn(&self) -> Result<Box<dyn Instance>> {
        // Buffers are allocated here, outside the timed region, exactly
        // as every other engine instantiates before the clock starts.
        let stack = AlignedMemory::zero_filled(self.exe.get_config().stack_size());
        let heap = AlignedMemory::zero_filled(HEAP_LEN);
        Ok(Box::new(SbpfInstance {
            exe: self.exe.clone(),
            loader: self.loader.clone(),
            jit: self.jit,
            stack,
            heap,
            input: vec![0u8; 1024],
            gas_used: 0,
        }))
    }
}

struct SbpfInstance {
    exe: Arc<Executable<Ctx>>,
    loader: Arc<BuiltinProgram<Ctx>>,
    jit: bool,
    stack: AlignedMemory<{ ebpf::HOST_ALIGN }>,
    heap: AlignedMemory<{ ebpf::HOST_ALIGN }>,
    input: Vec<u8>,
    gas_used: u64,
}

impl Instance for SbpfInstance {
    fn run(&mut self) -> Result<u32> {
        // The guest's bump cursor lives in the first 8 bytes of the heap
        // region — it has nowhere else to put it, since sBPF has no
        // writable globals. Clearing it is what makes a second
        // invocation see a fresh arena.
        self.heap.as_slice_mut()[..8].fill(0);

        let sbpf_version = self.exe.get_sbpf_version();
        let stack_len = self.stack.len();
        let regions: Vec<MemoryRegion> = vec![
            self.exe.get_ro_region(),
            MemoryRegion::new(&mut self.stack, ebpf::MM_STACK_START),
            MemoryRegion::new(&mut self.heap, ebpf::MM_HEAP_START),
            MemoryRegion::new(&raw mut self.input[..], ebpf::MM_INPUT_START),
        ];
        // SAFETY: every region points at a buffer this instance owns and
        // outlives the mapping, and the guest is single-threaded.
        let mapping = unsafe {
            MemoryMapping::new(regions, self.exe.get_config(), sbpf_version)
                .map_err(|e| anyhow!("memory mapping: {e:?}"))?
        };
        let mut ctx = Ctx {
            remaining: METER,
            consumed: 0,
            mapping,
        };
        let mut vm = EbpfVm::new(self.loader.clone(), sbpf_version, &mut ctx, stack_len);
        let mut frames = vec![CallFrame::default(); self.exe.get_config().max_call_depth];
        let mut mode = if self.jit {
            ExecutionMode::Jit
        } else {
            ExecutionMode::Interpreted
        };
        let (_, result) = vm.execute_program(&self.exe, &mut mode, &mut frames);

        match result {
            ProgramResult::Ok(v) => {
                self.gas_used = ctx.consumed;
                Ok(v as u32)
            }
            ProgramResult::Err(e) => bail!("sbpf trapped: {e:?}"),
        }
    }

    fn gas_used(&self) -> Option<u64> {
        Some(self.gas_used)
    }
}
