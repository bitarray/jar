//! JIT compile throughput — the cold path.
//!
//! `nub-recompiler-x86` is a pure bytes producer: it turns PVM2 code
//! into x86-64 machine code and never runs it. So compile time is
//! measurable here with no sandbox, no guest kernel and no personality,
//! which is exactly what makes this benchmark possible in nub at all.
//!
//! Executing that output needs the ring-0 substrate in `nub-arch-x86`;
//! see `nub-flat` for the reference personality that provides it.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    eprintln!("the x86-64 recompiler benchmark is Linux x86-64 only");
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
criterion::criterion_main!(imp::benches);

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod imp {
    use criterion::{Criterion, criterion_group};
    use nub_bench::PROGRAMS;
    use nub_exec::gas_const;
    use nub_program::abi::{CODE_BASE, DATA_BASE};
    use nub_recompiler_x86::codegen::{Compiler, HelperFns};

    /// The compiled code is never executed here, only emitted, so the
    /// helper addresses just have to be non-null.
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

    /// A plausible JIT window base. Not zero: the emitted RIP-relative
    /// displacements are computed against it, and a zero base would put
    /// the context pointer out of disp32 range.
    const JIT_VA_BASE: u64 = 0x4000_0000;

    fn bench_compile(c: &mut Criterion) {
        for p in PROGRAMS {
            let blob = p.decode();

            // Same load/store gas tier the interpreter derives, so the
            // emitted gas gates match what the program would actually
            // be charged.
            let mem_cycles = gas_const::mem_cycles_for(gas_const::accessible_pages(
                DATA_BASE + blob.regions.data_extent() as u32,
                DATA_BASE,
            ));

            let mut group = c.benchmark_group(p.name);
            // Report bytes of PVM2 code compiled per second — the
            // figure that makes programs of different sizes comparable.
            group.throughput(criterion::Throughput::Bytes(blob.code.len() as u64));
            group.bench_function("nub_jit_compile", |b| {
                b.iter(|| {
                    let compiler = Compiler::new(
                        dummy_helpers(),
                        blob.code.len(),
                        JIT_VA_BASE,
                        mem_cycles,
                        CODE_BASE,
                    );
                    std::hint::black_box(compiler.compile(std::hint::black_box(&blob.code)))
                })
            });
            group.finish();
        }
    }

    criterion_group!(benches, bench_compile);
}
