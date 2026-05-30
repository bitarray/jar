//! Sub-VM recursive-spawn bench for the in-kernel JIT path.
//!
//! Measures how many `Cap::Instance`s the KVM microkernel can
//! derive-and-CALL inside one second. The guest at
//! `components/benches/sub-vm-recurse` reads `depth` from φ[7]; if
//! zero, returns; otherwise `derive_spawn`s a child Instance from the
//! same Image and `host_call`s it with `depth - 1`. The in-kernel
//! CALL/HALT loop ([`nub_arch_x86::call_loop`]) keeps each level in a
//! kernel-private call stack; the JIT code cache
//! ([`nub_arch_x86::jit_cache`]) amortises the compile across all
//! levels.
//!
//! ## What this measures
//!
//! Per recursion level the kernel pays:
//!   1. ~3 µs `derive_spawn` (Blake2b chain extend + transient-table
//!      insert).
//!   2. ~10–15 µs PT setup + ring-3 entry + JIT entry.
//!   3. ~10–15 µs HALT exit + PT teardown + parent restore.
//!
//! On bench warmup the first CALL pays the one-time JIT compile
//! (~500 µs); every subsequent CALL hits the cache. The reported
//! VMs/sec at depth ≥ 100 is the steady-state rate.
//!
//! The build/invoke/criterion driver is shared with
//! `sub_vm_data_recurse` via [`javm_bench::run_recurse_bench`].

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use criterion::{Criterion, criterion_group, criterion_main};

const BLOB: &[u8] = include_bytes!(env!("SUB_VM_RECURSE_BLOB"));

fn sub_vm_recurse(c: &mut Criterion) {
    javm_bench::run_recurse_bench(c, BLOB, "sub_vm_recurse");
}

criterion_group!(benches, sub_vm_recurse);
criterion_main!(benches);
