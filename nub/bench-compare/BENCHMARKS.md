# nub benchmark comparison

## Compile + execute, metered JIT engines

The bench target: each sample compiles the program and runs it, from cold, with metering on. That is how a metered VM is used when work arrives as a blob — the compile is not amortized away.

Only cost models comparable to nub's appear here. PolkaVM's default `Simple` model is a flat per-instruction cost and is much cheaper to evaluate than nub's pipeline simulation, so the `*_full` rows (`CacheModel::L2Hit`, whose `memory_access_cost: 25` is exactly nub's `MEM_CYCLES_BASE`) are the like-for-like comparison. Full tables for every engine and every measurement kind follow below.

| Program | `nub_jit` | `polkavm64_recompiler_sync_gas_full` | `polkavm64_recompiler_async_gas_full` | `wasmtime_cranelift_fuel` |
|---|--:|--:|--:|--:|
| ed25519 | 1.23 ms (1.60x) | 775.08 µs (1.01x) | **768.92 µs** (1.00x) | 30.21 ms (39.29x) |
| mini-verifier | 1.11 ms (1.60x) | **695.67 µs** (1.00x) | 697.88 µs (1.00x) | 3.74 ms (5.37x) |
| keccak | 187.09 µs (2.08x) | 92.10 µs (1.02x) | **90.07 µs** (1.00x) | 2.87 ms (31.89x) |
| prime-sieve | 948.37 µs (3.47x) | 281.01 µs (1.03x) | **273.54 µs** (1.00x) | 1.01 ms (3.69x) |
| ecrecover | 2.58 ms (1.29x) | 2.03 ms (1.01x) | **2.01 ms** (1.00x) | 44.52 ms (22.18x) |
| blake2b | 263.48 µs (1.49x) | 178.06 µs (1.00x) | **177.20 µs** (1.00x) | 3.31 ms (18.67x) |
| fri-fold-tree | 1.11 ms (1.59x) | 703.56 µs (1.01x) | **699.66 µs** (1.00x) | 12.19 ms (17.43x) |
| poseidon2-perm | 2.27 ms (1.50x) | 1.51 ms (1.00x) | **1.51 ms** (1.00x) | 4.32 ms (2.86x) |
| poly-eval | 1.82 ms (1.41x) | **1.29 ms** (1.00x) | 1.34 ms (1.04x) | 9.85 ms (7.63x) |
| goldilocks-mul | 647.19 µs (1.54x) | 422.64 µs (1.01x) | **420.26 µs** (1.00x) | 1.02 ms (2.42x) |

Bold = fastest for that program; the multiple is versus it.

### Where that time goes

The same rows with **compilation excluded** — a fresh instance per sample, then execute. Every engine pays instantiation here, so this is like-for-like even for nub, which rebuilds its frame on every call and therefore has no warm state to hoist out.

The bracketed figure is the difference against the table above: what compilation costs that engine.

| Program | `nub_jit` | `polkavm64_recompiler_sync_gas_full` | `polkavm64_recompiler_async_gas_full` | `wasmtime_cranelift_fuel` |
|---|--:|--:|--:|--:|
| ed25519 | 153.87 µs (+1.08 ms compile) | 99.11 µs (+675.98 µs compile) | 100.81 µs (+668.10 µs compile) | 241.45 µs (+29.97 ms compile) |
| mini-verifier | 484.97 µs (+629.17 µs compile) | 571.14 µs (+124.53 µs compile) | 577.42 µs (+120.47 µs compile) | 787.91 µs (+2.95 ms compile) |
| keccak | 12.53 µs (+174.57 µs compile) | 10.48 µs (+81.62 µs compile) | 10.98 µs (+79.09 µs compile) | 4.80 µs (+2.87 ms compile) |
| prime-sieve | 260.62 µs (+687.75 µs compile) | 216.96 µs (+64.05 µs compile) | 210.83 µs (+62.70 µs compile) | 173.60 µs (+834.62 µs compile) |
| ecrecover | 386.95 µs (+2.20 ms compile) | 464.06 µs (+1.57 ms compile) | 453.94 µs (+1.55 ms compile) | 266.74 µs (+44.25 ms compile) |
| blake2b | 8.99 µs (+254.50 µs compile) | 7.69 µs (+170.38 µs compile) | 7.71 µs (+169.50 µs compile) | 2.70 µs (+3.31 ms compile) |
| fri-fold-tree | 471.31 µs (+640.63 µs compile) | 568.15 µs (+135.41 µs compile) | 567.43 µs (+132.23 µs compile) | 787.39 µs (+11.41 ms compile) |
| poseidon2-perm | 1.15 ms (+1.12 ms compile) | 1.39 ms (+122.79 µs compile) | 1.39 ms (+117.35 µs compile) | 1.97 ms (+2.35 ms compile) |
| poly-eval | 1.13 ms (+693.12 µs compile) | 1.23 ms (+56.57 µs compile) | 1.27 ms (+66.64 µs compile) | 1.46 ms (+8.39 ms compile) |
| goldilocks-mul | 318.02 µs (+329.17 µs compile) | 384.92 µs (+37.73 µs compile) | 381.52 µs (+38.74 µs compile) | 519.89 µs (+499.00 µs compile) |

## Provenance

- Guest toolchain: `rustc 1.95.0 (59807616e 2026-04-14)`
- CPU: 13th Gen Intel(R) Core(TM) i9-13900K
- ASLR: disabled for the measuring process
- Harness profile: `lto = true`, `codegen-units = 1`

## How to read this

Every row runs the *same Rust compute kernel*, compiled to that engine's target. Only the measured call is timed: compilation and instantiation happen before the clock starts, for every engine alike.

`metered` marks engines charging gas/fuel while running, with the counter set to maximum so the instrumentation runs but never fires. **Metered and unmetered rows are not corrected against each other.** Gas is an axis of this comparison, not a confounder to normalize away — read the cost of metering off the `polkavm64_recompiler_no_gas` / `_sync_gas` pair and the `wasmtime_cranelift` / `_fuel` pair, which bracket it.

`vs native` is the multiple of bare-metal cost. It is the number that says what an engine charges you.


## compilation

Turning the program into executable form. Engine construction and file loading are excluded (a once-per-process cost, and the harness's own I/O). `native` is absent: the OS loader already did it.

**`nub_jit` measures publishing here, not codegen.** nub keeps its object store *inside* the sandbox, so the equivalent up-front work is shipping the blob across the VM boundary, decoding it, content-hashing it and materializing its data image — the JIT itself runs lazily on first entry. `nub_jit_compile` is the codegen-only figure.

### blake2b

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 19.37 µs | 1.00x | - |
| `polkavm64_recompiler_async_gas` | yes | 19.78 µs | 1.02x | - |
| `polkavm64_recompiler_sync_gas` | yes | 20.26 µs | 1.05x | - |
| `polkavm64_recompiler_no_gas` | no | 20.57 µs | 1.06x | - |
| `nub_jit_compile` | yes | 41.46 µs | 2.14x | - |
| `nub_jit` | yes | 72.23 µs | 3.73x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 102.16 µs | 5.27x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 102.91 µs | 5.31x | - |
| `wasmtime_winch` | no | 404.48 µs | 20.88x | - |
| `wasmer_singlepass` | no | 1.06 ms | 54.93x | - |
| `wasmtime_cranelift` | no | 3.15 ms | 162.51x | - |
| `wasmtime_cranelift_fuel` | yes | 3.31 ms | 170.63x | - |

### ecrecover

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 201.66 µs | 1.00x | - |
| `polkavm64_recompiler_sync_gas` | yes | 254.04 µs | 1.26x | - |
| `polkavm64_recompiler_async_gas` | yes | 254.57 µs | 1.26x | - |
| `polkavm64_recompiler_no_gas` | no | 257.98 µs | 1.28x | - |
| `nub_jit` | yes | 634.16 µs | 3.14x | - |
| `nub_jit_compile` | yes | 728.28 µs | 3.61x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.31 ms | 6.51x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 1.36 ms | 6.72x | - |
| `wasmer_singlepass` | no | 3.29 ms | 16.34x | - |
| `wasmtime_winch` | no | 4.94 ms | 24.51x | - |
| `wasmtime_cranelift` | no | 35.44 ms | 175.74x | - |
| `wasmtime_cranelift_fuel` | yes | 43.72 ms | 216.80x | - |

### ed25519

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 90.58 µs | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 114.96 µs | 1.27x | - |
| `polkavm64_recompiler_async_gas` | yes | 115.33 µs | 1.27x | - |
| `polkavm64_recompiler_sync_gas` | yes | 116.15 µs | 1.28x | - |
| `nub_jit` | yes | 310.11 µs | 3.42x | - |
| `nub_jit_compile` | yes | 340.90 µs | 3.76x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 541.93 µs | 5.98x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 543.13 µs | 6.00x | - |
| `wasmtime_winch` | no | 2.79 ms | 30.82x | - |
| `wasmer_singlepass` | no | 3.70 ms | 40.87x | - |
| `wasmtime_cranelift` | no | 23.12 ms | 255.19x | - |
| `wasmtime_cranelift_fuel` | yes | 29.24 ms | 322.79x | - |

### fri-fold-tree

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 10.63 µs | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 12.67 µs | 1.19x | - |
| `polkavm64_recompiler_async_gas` | yes | 12.90 µs | 1.21x | - |
| `polkavm64_recompiler_sync_gas` | yes | 14.29 µs | 1.34x | - |
| `nub_jit_compile` | yes | 31.11 µs | 2.93x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 55.76 µs | 5.24x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 56.89 µs | 5.35x | - |
| `nub_jit` | yes | 82.26 µs | 7.74x | - |
| `wasmer_singlepass` | no | 1.48 ms | 139.54x | - |
| `wasmtime_winch` | no | 1.64 ms | 154.64x | - |
| `wasmtime_cranelift` | no | 7.84 ms | 737.46x | - |
| `wasmtime_cranelift_fuel` | yes | 11.22 ms | 1055.47x | - |

### goldilocks-mul

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 568.0 ns | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 1.50 µs | 2.65x | - |
| `polkavm64_recompiler_async_gas` | yes | 1.55 µs | 2.72x | - |
| `polkavm64_recompiler_sync_gas` | yes | 1.55 µs | 2.73x | - |
| `nub_jit_compile` | yes | 2.11 µs | 3.72x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 3.18 µs | 5.59x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 3.19 µs | 5.62x | - |
| `nub_jit` | yes | 62.28 µs | 109.65x | - |
| `wasmtime_winch` | no | 214.64 µs | 377.89x | - |
| `wasmtime_cranelift` | no | 378.59 µs | 666.52x | - |
| `wasmtime_cranelift_fuel` | yes | 516.34 µs | 909.04x | - |
| `wasmer_singlepass` | no | 829.98 µs | 1461.24x | - |

### keccak

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 7.39 µs | 1.00x | - |
| `polkavm64_recompiler_async_gas` | yes | 7.65 µs | 1.04x | - |
| `polkavm64_recompiler_sync_gas` | yes | 8.09 µs | 1.09x | - |
| `nub_jit_compile` | yes | 9.93 µs | 1.34x | - |
| `polkavm64_recompiler_no_gas` | no | 14.99 µs | 2.03x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 34.58 µs | 4.68x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 34.88 µs | 4.72x | - |
| `nub_jit` | yes | 40.40 µs | 5.47x | - |
| `wasmtime_winch` | no | 771.03 µs | 104.31x | - |
| `wasmer_singlepass` | no | 806.82 µs | 109.15x | - |
| `wasmtime_cranelift` | no | 2.16 ms | 291.85x | - |
| `wasmtime_cranelift_fuel` | yes | 2.85 ms | 385.25x | - |

### mini-verifier

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 10.41 µs | 1.00x | - |
| `polkavm64_recompiler_async_gas` | yes | 10.63 µs | 1.02x | - |
| `polkavm64_recompiler_sync_gas` | yes | 11.07 µs | 1.06x | - |
| `polkavm64_recompiler_no_gas` | no | 11.65 µs | 1.12x | - |
| `nub_jit_compile` | yes | 25.33 µs | 2.43x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 53.02 µs | 5.09x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 53.67 µs | 5.16x | - |
| `nub_jit` | yes | 59.92 µs | 5.76x | - |
| `wasmtime_winch` | no | 552.60 µs | 53.09x | - |
| `wasmer_singlepass` | no | 962.07 µs | 92.43x | - |
| `wasmtime_cranelift` | no | 2.45 ms | 235.65x | - |
| `wasmtime_cranelift_fuel` | yes | 2.87 ms | 275.47x | - |

### poly-eval

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 1.78 µs | 1.00x | - |
| `polkavm64_recompiler_async_gas` | yes | 3.21 µs | 1.80x | - |
| `polkavm64_recompiler_no_gas` | no | 3.24 µs | 1.82x | - |
| `polkavm64_recompiler_sync_gas` | yes | 3.39 µs | 1.90x | - |
| `nub_jit_compile` | yes | 6.57 µs | 3.69x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 11.37 µs | 6.38x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 11.46 µs | 6.43x | - |
| `nub_jit` | yes | 37.59 µs | 21.09x | - |
| `wasmer_singlepass` | no | 1.25 ms | 699.08x | - |
| `wasmtime_winch` | no | 1.30 ms | 728.52x | - |
| `wasmtime_cranelift` | no | 5.40 ms | 3029.17x | - |
| `wasmtime_cranelift_fuel` | yes | 8.24 ms | 4625.96x | - |

### poseidon2-perm

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 8.08 µs | 1.00x | - |
| `polkavm64_recompiler_async_gas` | yes | 8.12 µs | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 8.89 µs | 1.10x | - |
| `polkavm64_recompiler_sync_gas` | yes | 9.05 µs | 1.12x | - |
| `nub_jit_compile` | yes | 38.29 µs | 4.74x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 38.80 µs | 4.80x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 39.18 µs | 4.85x | - |
| `nub_jit` | yes | 52.99 µs | 6.56x | - |
| `wasmtime_winch` | no | 462.68 µs | 57.24x | - |
| `wasmer_singlepass` | no | 932.78 µs | 115.40x | - |
| `wasmtime_cranelift` | no | 1.95 ms | 241.11x | - |
| `wasmtime_cranelift_fuel` | yes | 2.40 ms | 296.80x | - |

### prime-sieve

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 1.88 µs | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 4.66 µs | 2.48x | - |
| `polkavm64_recompiler_async_gas` | yes | 4.70 µs | 2.50x | - |
| `polkavm64_recompiler_sync_gas` | yes | 4.72 µs | 2.51x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 7.06 µs | 3.75x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 7.09 µs | 3.77x | - |
| `nub_jit_compile` | yes | 14.38 µs | 7.64x | - |
| `wasmtime_winch` | no | 330.59 µs | 175.75x | - |
| `wasmtime_cranelift` | no | 499.97 µs | 265.80x | - |
| `nub_jit` | yes | 531.01 µs | 282.30x | - |
| `wasmer_singlepass` | no | 706.09 µs | 375.38x | - |
| `wasmtime_cranelift_fuel` | yes | 826.71 µs | 439.51x | - |

## invoke

Cold invocation with compilation excluded: a fresh instance every sample. Where an engine's *instantiation* strategy shows up. Compare against `runtime` for the same row to see what a cold start costs it.

### blake2b

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 1.03 µs | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 2.64 µs | 2.57x | 2.6x |
| `wasmtime_cranelift_fuel` | yes | 2.70 µs | 2.62x | 2.6x |
| `wasmtime_winch` | no | 3.25 µs | 3.16x | 3.2x |
| `polkavm64_recompiler_sync_gas_full` | yes | 7.69 µs | 7.47x | 7.5x |
| `polkavm64_recompiler_async_gas_full` | yes | 7.71 µs | 7.49x | 7.5x |
| `polkavm64_recompiler_no_gas` | no | 7.98 µs | 7.75x | 7.8x |
| `polkavm64_recompiler_async_gas` | yes | 7.99 µs | 7.77x | 7.8x |
| `polkavm64_recompiler_sync_gas` | yes | 8.49 µs | 8.25x | 8.3x |
| `nub_jit` | yes | 8.99 µs | 8.73x | 8.7x |
| `wasmer_singlepass` | no | 11.49 µs | 11.17x | 11.2x |
| `polkavm64_interpreter` | no | 172.23 µs | 167.37x | 167.4x |
| `nub_interp` | yes | 278.51 µs | 270.66x | 270.7x |

### ecrecover

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 101.45 µs | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 263.87 µs | 2.60x | 2.6x |
| `wasmtime_cranelift_fuel` | yes | 266.74 µs | 2.63x | 2.6x |
| `nub_jit` | yes | 386.95 µs | 3.81x | 3.8x |
| `wasmtime_winch` | no | 392.11 µs | 3.87x | 3.9x |
| `polkavm64_recompiler_no_gas` | no | 412.96 µs | 4.07x | 4.1x |
| `polkavm64_recompiler_async_gas` | yes | 451.85 µs | 4.45x | 4.5x |
| `polkavm64_recompiler_async_gas_full` | yes | 453.94 µs | 4.47x | 4.5x |
| `polkavm64_recompiler_sync_gas` | yes | 460.37 µs | 4.54x | 4.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 464.06 µs | 4.57x | 4.6x |
| `wasmer_singlepass` | no | 883.65 µs | 8.71x | 8.7x |
| `polkavm64_interpreter` | no | 12.14 ms | 119.71x | 119.7x |
| `nub_interp` | yes | 28.49 ms | 280.87x | 280.9x |

### ed25519

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 32.75 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 90.39 µs | 2.76x | 2.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 99.11 µs | 3.03x | 3.0x |
| `polkavm64_recompiler_sync_gas` | yes | 100.29 µs | 3.06x | 3.1x |
| `polkavm64_recompiler_async_gas` | yes | 100.39 µs | 3.07x | 3.1x |
| `polkavm64_recompiler_async_gas_full` | yes | 100.81 µs | 3.08x | 3.1x |
| `nub_jit` | yes | 153.87 µs | 4.70x | 4.7x |
| `wasmtime_cranelift` | no | 199.31 µs | 6.09x | 6.1x |
| `wasmtime_cranelift_fuel` | yes | 241.45 µs | 7.37x | 7.4x |
| `wasmtime_winch` | no | 351.34 µs | 10.73x | 10.7x |
| `wasmer_singlepass` | no | 1.38 ms | 42.13x | 42.1x |
| `polkavm64_interpreter` | no | 1.66 ms | 50.71x | 50.7x |
| `nub_interp` | yes | 5.14 ms | 156.99x | 157.0x |

### fri-fold-tree

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 239.58 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 471.31 µs | 1.97x | 2.0x |
| `polkavm64_recompiler_no_gas` | no | 559.31 µs | 2.33x | 2.3x |
| `polkavm64_recompiler_async_gas` | yes | 566.18 µs | 2.36x | 2.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 567.43 µs | 2.37x | 2.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 568.15 µs | 2.37x | 2.4x |
| `polkavm64_recompiler_sync_gas` | yes | 569.62 µs | 2.38x | 2.4x |
| `wasmtime_cranelift` | no | 769.42 µs | 3.21x | 3.2x |
| `wasmtime_cranelift_fuel` | yes | 787.39 µs | 3.29x | 3.3x |
| `wasmtime_winch` | no | 1.19 ms | 4.96x | 5.0x |
| `wasmer_singlepass` | no | 5.25 ms | 21.90x | 21.9x |
| `polkavm64_interpreter` | no | 9.25 ms | 38.60x | 38.6x |
| `nub_interp` | yes | 13.73 ms | 57.33x | 57.3x |

### goldilocks-mul

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 213.96 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 318.02 µs | 1.49x | 1.5x |
| `polkavm64_recompiler_no_gas` | no | 348.39 µs | 1.63x | 1.6x |
| `polkavm64_recompiler_async_gas_full` | yes | 381.52 µs | 1.78x | 1.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 384.92 µs | 1.80x | 1.8x |
| `polkavm64_recompiler_sync_gas` | yes | 384.93 µs | 1.80x | 1.8x |
| `polkavm64_recompiler_async_gas` | yes | 385.00 µs | 1.80x | 1.8x |
| `wasmtime_cranelift_fuel` | yes | 519.89 µs | 2.43x | 2.4x |
| `wasmtime_cranelift` | no | 534.50 µs | 2.50x | 2.5x |
| `wasmtime_winch` | no | 541.33 µs | 2.53x | 2.5x |
| `wasmer_singlepass` | no | 1.57 ms | 7.34x | 7.3x |
| `polkavm64_interpreter` | no | 2.10 ms | 9.79x | 9.8x |
| `nub_interp` | yes | 4.15 ms | 19.41x | 19.4x |

### keccak

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 2.74 µs | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 4.65 µs | 1.70x | 1.7x |
| `wasmtime_cranelift_fuel` | yes | 4.80 µs | 1.75x | 1.8x |
| `wasmtime_winch` | no | 5.32 µs | 1.94x | 1.9x |
| `wasmer_singlepass` | no | 8.82 µs | 3.22x | 3.2x |
| `polkavm64_recompiler_no_gas` | no | 9.79 µs | 3.57x | 3.6x |
| `polkavm64_recompiler_sync_gas_full` | yes | 10.48 µs | 3.82x | 3.8x |
| `polkavm64_recompiler_sync_gas` | yes | 10.87 µs | 3.97x | 4.0x |
| `polkavm64_recompiler_async_gas_full` | yes | 10.98 µs | 4.01x | 4.0x |
| `polkavm64_recompiler_async_gas` | yes | 11.27 µs | 4.11x | 4.1x |
| `nub_jit` | yes | 12.53 µs | 4.57x | 4.6x |
| `polkavm64_interpreter` | no | 102.26 µs | 37.31x | 37.3x |
| `nub_interp` | yes | 502.67 µs | 183.39x | 183.4x |

### mini-verifier

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 248.15 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 484.97 µs | 1.95x | 2.0x |
| `polkavm64_recompiler_async_gas` | yes | 568.88 µs | 2.29x | 2.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 571.14 µs | 2.30x | 2.3x |
| `polkavm64_recompiler_sync_gas` | yes | 576.71 µs | 2.32x | 2.3x |
| `polkavm64_recompiler_async_gas_full` | yes | 577.42 µs | 2.33x | 2.3x |
| `polkavm64_recompiler_no_gas` | no | 582.22 µs | 2.35x | 2.3x |
| `wasmtime_cranelift` | no | 752.71 µs | 3.03x | 3.0x |
| `wasmtime_cranelift_fuel` | yes | 787.91 µs | 3.18x | 3.2x |
| `wasmtime_winch` | no | 1.27 ms | 5.12x | 5.1x |
| `wasmer_singlepass` | no | 4.35 ms | 17.51x | 17.5x |
| `polkavm64_interpreter` | no | 9.87 ms | 39.79x | 39.8x |
| `nub_interp` | yes | 14.29 ms | 57.58x | 57.6x |

### poly-eval

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 713.53 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 1.13 ms | 1.58x | 1.6x |
| `polkavm64_recompiler_sync_gas` | yes | 1.19 ms | 1.67x | 1.7x |
| `polkavm64_recompiler_no_gas` | no | 1.21 ms | 1.69x | 1.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.23 ms | 1.73x | 1.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.27 ms | 1.78x | 1.8x |
| `polkavm64_recompiler_async_gas` | yes | 1.28 ms | 1.80x | 1.8x |
| `wasmtime_cranelift_fuel` | yes | 1.46 ms | 2.05x | 2.0x |
| `wasmtime_cranelift` | no | 1.51 ms | 2.12x | 2.1x |
| `wasmtime_winch` | no | 1.71 ms | 2.40x | 2.4x |
| `wasmer_singlepass` | no | 6.58 ms | 9.22x | 9.2x |
| `polkavm64_interpreter` | no | 8.03 ms | 11.25x | 11.3x |
| `nub_interp` | yes | 17.56 ms | 24.62x | 24.6x |

### poseidon2-perm

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 605.37 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 1.15 ms | 1.89x | 1.9x |
| `polkavm64_recompiler_no_gas` | no | 1.39 ms | 2.29x | 2.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.39 ms | 2.29x | 2.3x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.39 ms | 2.30x | 2.3x |
| `polkavm64_recompiler_async_gas` | yes | 1.41 ms | 2.32x | 2.3x |
| `polkavm64_recompiler_sync_gas` | yes | 1.41 ms | 2.33x | 2.3x |
| `wasmtime_cranelift` | no | 1.92 ms | 3.17x | 3.2x |
| `wasmtime_cranelift_fuel` | yes | 1.97 ms | 3.25x | 3.3x |
| `wasmtime_winch` | no | 3.09 ms | 5.11x | 5.1x |
| `wasmer_singlepass` | no | 10.63 ms | 17.55x | 17.6x |
| `polkavm64_interpreter` | no | 22.31 ms | 36.85x | 36.9x |
| `nub_interp` | yes | 37.15 ms | 61.36x | 61.4x |

### prime-sieve

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 57.28 µs | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 104.63 µs | 1.83x | 1.8x |
| `polkavm64_recompiler_no_gas` | no | 111.94 µs | 1.95x | 2.0x |
| `wasmer_singlepass` | no | 131.00 µs | 2.29x | 2.3x |
| `wasmtime_cranelift_fuel` | yes | 173.60 µs | 3.03x | 3.0x |
| `wasmtime_winch` | no | 179.35 µs | 3.13x | 3.1x |
| `polkavm64_recompiler_async_gas` | yes | 209.44 µs | 3.66x | 3.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 210.83 µs | 3.68x | 3.7x |
| `polkavm64_recompiler_sync_gas` | yes | 215.73 µs | 3.77x | 3.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 216.96 µs | 3.79x | 3.8x |
| `nub_jit` | yes | 260.62 µs | 4.55x | 4.5x |
| `polkavm64_interpreter` | no | 2.13 ms | 37.13x | 37.1x |
| `nub_interp` | yes | 7.42 ms | 129.47x | 129.5x |

## oneshot

Compile **and** execute, from cold, every sample. The metric that matches how a metered VM is actually used: work arrives as a blob that must be compiled and then run, and each iteration pays both. Engines that cache compilation internally are evicted first, so no row skips the compile half.

### blake2b

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 28.99 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 72.72 µs | 2.51x | 2.5x |
| `polkavm64_recompiler_async_gas` | yes | 75.53 µs | 2.61x | 2.6x |
| `polkavm64_recompiler_sync_gas` | yes | 77.96 µs | 2.69x | 2.7x |
| `polkavm64_interpreter` | no | 123.56 µs | 4.26x | 4.3x |
| `polkavm64_recompiler_async_gas_full` | yes | 177.20 µs | 6.11x | 6.1x |
| `polkavm64_recompiler_sync_gas_full` | yes | 178.06 µs | 6.14x | 6.1x |
| `nub_interp` | yes | 211.74 µs | 7.30x | 7.3x |
| `nub_jit` | yes | 263.48 µs | 9.09x | 9.1x |
| `wasmtime_winch` | no | 433.73 µs | 14.96x | 15.0x |
| `wasmer_singlepass` | no | 2.32 ms | 80.14x | 80.1x |
| `wasmtime_cranelift` | no | 3.19 ms | 110.09x | 110.1x |
| `wasmtime_cranelift_fuel` | yes | 3.31 ms | 114.13x | 114.1x |

### ecrecover

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 369.50 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 879.83 µs | 2.38x | 2.4x |
| `polkavm64_recompiler_async_gas` | yes | 915.86 µs | 2.48x | 2.5x |
| `polkavm64_recompiler_sync_gas` | yes | 933.77 µs | 2.53x | 2.5x |
| `polkavm64_recompiler_async_gas_full` | yes | 2.01 ms | 5.43x | 5.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 2.03 ms | 5.49x | 5.5x |
| `nub_jit` | yes | 2.58 ms | 6.99x | 7.0x |
| `wasmtime_winch` | no | 5.37 ms | 14.53x | 14.5x |
| `wasmer_singlepass` | no | 7.94 ms | 21.50x | 21.5x |
| `polkavm64_interpreter` | no | 12.35 ms | 33.41x | 33.4x |
| `nub_interp` | yes | 27.48 ms | 74.37x | 74.4x |
| `wasmtime_cranelift` | no | 36.22 ms | 98.04x | 98.0x |
| `wasmtime_cranelift_fuel` | yes | 44.52 ms | 120.48x | 120.5x |

### ed25519

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 44.75 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 307.54 µs | 6.87x | 6.9x |
| `polkavm64_recompiler_async_gas` | yes | 310.12 µs | 6.93x | 6.9x |
| `polkavm64_recompiler_sync_gas` | yes | 320.05 µs | 7.15x | 7.2x |
| `polkavm64_recompiler_async_gas_full` | yes | 768.92 µs | 17.18x | 17.2x |
| `polkavm64_recompiler_sync_gas_full` | yes | 775.08 µs | 17.32x | 17.3x |
| `nub_jit` | yes | 1.23 ms | 27.47x | 27.5x |
| `polkavm64_interpreter` | no | 1.81 ms | 40.47x | 40.5x |
| `wasmtime_winch` | no | 3.20 ms | 71.55x | 71.6x |
| `nub_interp` | yes | 5.58 ms | 124.62x | 124.6x |
| `wasmer_singlepass` | no | 8.86 ms | 197.98x | 198.0x |
| `wasmtime_cranelift` | no | 23.61 ms | 527.62x | 527.6x |
| `wasmtime_cranelift_fuel` | yes | 30.21 ms | 675.16x | 675.2x |

### fri-fold-tree

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 252.23 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_async_gas` | yes | 640.01 µs | 2.54x | 2.5x |
| `polkavm64_recompiler_sync_gas` | yes | 643.24 µs | 2.55x | 2.6x |
| `polkavm64_recompiler_no_gas` | no | 647.96 µs | 2.57x | 2.6x |
| `polkavm64_recompiler_async_gas_full` | yes | 699.66 µs | 2.77x | 2.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 703.56 µs | 2.79x | 2.8x |
| `nub_jit` | yes | 1.11 ms | 4.41x | 4.4x |
| `wasmtime_winch` | no | 2.90 ms | 11.48x | 11.5x |
| `wasmer_singlepass` | no | 7.98 ms | 31.63x | 31.6x |
| `wasmtime_cranelift` | no | 8.74 ms | 34.65x | 34.6x |
| `polkavm64_interpreter` | no | 9.10 ms | 36.08x | 36.1x |
| `wasmtime_cranelift_fuel` | yes | 12.19 ms | 48.35x | 48.3x |
| `nub_interp` | yes | 13.47 ms | 53.42x | 53.4x |

### goldilocks-mul

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 223.43 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 385.12 µs | 1.72x | 1.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 420.26 µs | 1.88x | 1.9x |
| `polkavm64_recompiler_async_gas` | yes | 420.39 µs | 1.88x | 1.9x |
| `polkavm64_recompiler_sync_gas_full` | yes | 422.64 µs | 1.89x | 1.9x |
| `polkavm64_recompiler_sync_gas` | yes | 426.21 µs | 1.91x | 1.9x |
| `nub_jit` | yes | 647.19 µs | 2.90x | 2.9x |
| `wasmtime_winch` | no | 765.91 µs | 3.43x | 3.4x |
| `wasmtime_cranelift` | no | 936.12 µs | 4.19x | 4.2x |
| `wasmtime_cranelift_fuel` | yes | 1.02 ms | 4.56x | 4.6x |
| `polkavm64_interpreter` | no | 2.16 ms | 9.69x | 9.7x |
| `wasmer_singlepass` | no | 3.48 ms | 15.59x | 15.6x |
| `nub_interp` | yes | 4.20 ms | 18.78x | 18.8x |

### keccak

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 32.40 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_sync_gas` | yes | 58.86 µs | 1.82x | 1.8x |
| `polkavm64_recompiler_async_gas` | yes | 59.73 µs | 1.84x | 1.8x |
| `polkavm64_recompiler_no_gas` | no | 59.75 µs | 1.84x | 1.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 90.07 µs | 2.78x | 2.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 92.10 µs | 2.84x | 2.8x |
| `polkavm64_interpreter` | no | 110.39 µs | 3.41x | 3.4x |
| `nub_jit` | yes | 187.09 µs | 5.77x | 5.8x |
| `nub_interp` | yes | 274.83 µs | 8.48x | 8.5x |
| `wasmtime_winch` | no | 813.81 µs | 25.12x | 25.1x |
| `wasmer_singlepass` | no | 1.71 ms | 52.69x | 52.7x |
| `wasmtime_cranelift` | no | 2.18 ms | 67.37x | 67.4x |
| `wasmtime_cranelift_fuel` | yes | 2.87 ms | 88.63x | 88.6x |

### mini-verifier

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 260.78 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 640.69 µs | 2.46x | 2.5x |
| `polkavm64_recompiler_async_gas` | yes | 640.74 µs | 2.46x | 2.5x |
| `polkavm64_recompiler_sync_gas` | yes | 647.39 µs | 2.48x | 2.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 695.67 µs | 2.67x | 2.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 697.88 µs | 2.68x | 2.7x |
| `nub_jit` | yes | 1.11 ms | 4.27x | 4.3x |
| `wasmtime_winch` | no | 1.80 ms | 6.89x | 6.9x |
| `wasmtime_cranelift` | no | 3.26 ms | 12.51x | 12.5x |
| `wasmtime_cranelift_fuel` | yes | 3.74 ms | 14.33x | 14.3x |
| `wasmer_singlepass` | no | 6.31 ms | 24.21x | 24.2x |
| `polkavm64_interpreter` | no | 9.63 ms | 36.93x | 36.9x |
| `nub_interp` | yes | 14.62 ms | 56.06x | 56.1x |

### poly-eval

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 729.93 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 1.25 ms | 1.71x | 1.7x |
| `polkavm64_recompiler_sync_gas` | yes | 1.28 ms | 1.76x | 1.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.29 ms | 1.77x | 1.8x |
| `polkavm64_recompiler_async_gas` | yes | 1.33 ms | 1.82x | 1.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.34 ms | 1.83x | 1.8x |
| `nub_jit` | yes | 1.82 ms | 2.49x | 2.5x |
| `wasmtime_winch` | no | 3.07 ms | 4.20x | 4.2x |
| `wasmtime_cranelift` | no | 7.02 ms | 9.61x | 9.6x |
| `polkavm64_interpreter` | no | 8.34 ms | 11.42x | 11.4x |
| `wasmer_singlepass` | no | 8.48 ms | 11.61x | 11.6x |
| `wasmtime_cranelift_fuel` | yes | 9.85 ms | 13.49x | 13.5x |
| `nub_interp` | yes | 17.84 ms | 24.44x | 24.4x |

### poseidon2-perm

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 624.03 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 1.45 ms | 2.32x | 2.3x |
| `polkavm64_recompiler_async_gas` | yes | 1.47 ms | 2.36x | 2.4x |
| `polkavm64_recompiler_sync_gas` | yes | 1.47 ms | 2.36x | 2.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.51 ms | 2.42x | 2.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.51 ms | 2.42x | 2.4x |
| `nub_jit` | yes | 2.27 ms | 3.63x | 3.6x |
| `wasmtime_winch` | no | 3.50 ms | 5.60x | 5.6x |
| `wasmtime_cranelift` | no | 3.88 ms | 6.22x | 6.2x |
| `wasmtime_cranelift_fuel` | yes | 4.32 ms | 6.92x | 6.9x |
| `wasmer_singlepass` | no | 12.54 ms | 20.09x | 20.1x |
| `polkavm64_interpreter` | no | 23.08 ms | 36.98x | 37.0x |
| `nub_interp` | yes | 36.44 ms | 58.40x | 58.4x |

### prime-sieve

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 96.77 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 169.15 µs | 1.75x | 1.7x |
| `polkavm64_recompiler_async_gas` | yes | 267.70 µs | 2.77x | 2.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 273.54 µs | 2.83x | 2.8x |
| `polkavm64_recompiler_sync_gas` | yes | 274.20 µs | 2.83x | 2.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 281.01 µs | 2.90x | 2.9x |
| `wasmtime_winch` | no | 531.49 µs | 5.49x | 5.5x |
| `wasmtime_cranelift` | no | 622.54 µs | 6.43x | 6.4x |
| `nub_jit` | yes | 948.37 µs | 9.80x | 9.8x |
| `wasmtime_cranelift_fuel` | yes | 1.01 ms | 10.42x | 10.4x |
| `wasmer_singlepass` | no | 1.79 ms | 18.48x | 18.5x |
| `polkavm64_interpreter` | no | 2.13 ms | 22.05x | 22.0x |
| `nub_interp` | yes | 7.51 ms | 77.57x | 77.6x |

## runtime

Steady-state execution: one instance, invoked repeatedly. How fast the engine *executes*, with instantiation excluded.

Rows are absent where a program cannot be re-run in one instance (the three guests with a never-freeing bump arena).

**† — this row still contains per-invocation setup.** nub's invocation model builds a fresh frame and address space on every call by design, so there is no warm state to hoist out. Its figure is therefore *not* comparable to a row that reuses one warm instance; compare it against those rows' `invoke` figures instead, which also pay instantiation.

### blake2b

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 692.0 ns | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 796.0 ns | 1.15x | 1.2x |
| `wasmtime_cranelift_fuel` | yes | 822.0 ns | 1.19x | 1.2x |
| `wasmtime_winch` | no | 1.20 µs | 1.74x | 1.7x |
| `polkavm64_recompiler_no_gas` | no | 1.82 µs | 2.62x | 2.6x |
| `polkavm64_recompiler_sync_gas` | yes | 2.33 µs | 3.37x | 3.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 2.43 µs | 3.51x | 3.5x |
| `polkavm64_recompiler_async_gas_full` | yes | 2.51 µs | 3.62x | 3.6x |
| `polkavm64_recompiler_async_gas` | yes | 2.56 µs | 3.69x | 3.7x |
| `wasmer_singlepass` | no | 5.05 µs | 7.29x | 7.3x |
| `nub_jit` † | yes | 8.28 µs | 11.97x | 12.0x |
| `polkavm64_interpreter` | no | 45.21 µs | 65.33x | 65.3x |
| `nub_interp` | yes | 156.97 µs | 226.84x | 226.8x |

### ecrecover

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 99.63 µs | 1.00x | 1.0x |
| `wasmtime_cranelift_fuel` | yes | 264.63 µs | 2.66x | 2.7x |
| `wasmtime_cranelift` | no | 268.32 µs | 2.69x | 2.7x |
| `nub_jit` † | yes | 383.07 µs | 3.84x | 3.8x |
| `wasmtime_winch` | no | 389.62 µs | 3.91x | 3.9x |
| `polkavm64_recompiler_no_gas` | no | 398.96 µs | 4.00x | 4.0x |
| `polkavm64_recompiler_async_gas_full` | yes | 439.76 µs | 4.41x | 4.4x |
| `polkavm64_recompiler_async_gas` | yes | 440.29 µs | 4.42x | 4.4x |
| `polkavm64_recompiler_sync_gas` | yes | 451.13 µs | 4.53x | 4.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 456.66 µs | 4.58x | 4.6x |
| `wasmer_singlepass` | no | 816.71 µs | 8.20x | 8.2x |
| `polkavm64_interpreter` | no | 11.63 ms | 116.75x | 116.7x |
| `nub_interp` | yes | 26.86 ms | 269.56x | 269.6x |

### ed25519

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 32.69 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 81.08 µs | 2.48x | 2.5x |
| `polkavm64_recompiler_async_gas` | yes | 91.16 µs | 2.79x | 2.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 91.23 µs | 2.79x | 2.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 91.25 µs | 2.79x | 2.8x |
| `polkavm64_recompiler_sync_gas` | yes | 91.34 µs | 2.79x | 2.8x |
| `nub_jit` † | yes | 92.39 µs | 2.83x | 2.8x |
| `wasmtime_cranelift` | no | 195.97 µs | 5.99x | 6.0x |
| `wasmtime_cranelift_fuel` | yes | 238.96 µs | 7.31x | 7.3x |
| `wasmtime_winch` | no | 353.19 µs | 10.80x | 10.8x |
| `wasmer_singlepass` | no | 976.75 µs | 29.88x | 29.9x |
| `polkavm64_interpreter` | no | 1.57 ms | 48.11x | 48.1x |
| `nub_interp` | yes | 5.00 ms | 153.04x | 153.0x |

### fri-fold-tree

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 226.15 µs | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 750.25 µs | 3.32x | 3.3x |
| `wasmtime_cranelift_fuel` | yes | 780.85 µs | 3.45x | 3.5x |
| `nub_jit` † | yes | 814.43 µs | 3.60x | 3.6x |
| `wasmtime_winch` | no | 1.21 ms | 5.35x | 5.3x |
| `wasmer_singlepass` | no | 3.68 ms | 16.28x | 16.3x |

### goldilocks-mul

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 202.30 µs | 1.00x | 1.0x |
| `nub_jit` † | yes | 315.43 µs | 1.56x | 1.6x |
| `polkavm64_recompiler_no_gas` | no | 347.03 µs | 1.72x | 1.7x |
| `polkavm64_recompiler_async_gas` | yes | 383.17 µs | 1.89x | 1.9x |
| `polkavm64_recompiler_sync_gas_full` | yes | 383.19 µs | 1.89x | 1.9x |
| `polkavm64_recompiler_sync_gas` | yes | 383.25 µs | 1.89x | 1.9x |
| `polkavm64_recompiler_async_gas_full` | yes | 383.39 µs | 1.90x | 1.9x |
| `wasmtime_winch` | no | 509.93 µs | 2.52x | 2.5x |
| `wasmtime_cranelift_fuel` | yes | 518.19 µs | 2.56x | 2.6x |
| `wasmtime_cranelift` | no | 533.33 µs | 2.64x | 2.6x |
| `wasmer_singlepass` | no | 1.50 ms | 7.41x | 7.4x |
| `polkavm64_interpreter` | no | 2.16 ms | 10.69x | 10.7x |
| `nub_interp` | yes | 3.99 ms | 19.71x | 19.7x |

### keccak

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 1.70 µs | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 2.26 µs | 1.33x | 1.3x |
| `wasmtime_cranelift_fuel` | yes | 2.34 µs | 1.38x | 1.4x |
| `wasmtime_winch` | no | 2.72 µs | 1.60x | 1.6x |
| `polkavm64_recompiler_no_gas` | no | 3.16 µs | 1.86x | 1.9x |
| `polkavm64_recompiler_async_gas_full` | yes | 3.92 µs | 2.31x | 2.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 3.95 µs | 2.32x | 2.3x |
| `polkavm64_recompiler_async_gas` | yes | 3.95 µs | 2.32x | 2.3x |
| `polkavm64_recompiler_sync_gas` | yes | 3.96 µs | 2.33x | 2.3x |
| `wasmer_singlepass` | no | 6.59 µs | 3.87x | 3.9x |
| `nub_jit` † | yes | 6.72 µs | 3.95x | 4.0x |
| `polkavm64_interpreter` | no | 78.43 µs | 46.14x | 46.1x |
| `nub_interp` | yes | 239.66 µs | 140.97x | 141.0x |

### mini-verifier

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 225.89 µs | 1.00x | 1.0x |
| `nub_jit` † | yes | 482.64 µs | 2.14x | 2.1x |
| `polkavm64_recompiler_sync_gas` | yes | 574.72 µs | 2.54x | 2.5x |
| `polkavm64_recompiler_async_gas_full` | yes | 574.97 µs | 2.55x | 2.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 575.82 µs | 2.55x | 2.5x |
| `polkavm64_recompiler_no_gas` | no | 577.16 µs | 2.56x | 2.6x |
| `polkavm64_recompiler_async_gas` | yes | 579.17 µs | 2.56x | 2.6x |
| `wasmtime_cranelift` | no | 782.58 µs | 3.46x | 3.5x |
| `wasmtime_cranelift_fuel` | yes | 809.98 µs | 3.59x | 3.6x |
| `wasmtime_winch` | no | 1.23 ms | 5.43x | 5.4x |
| `wasmer_singlepass` | no | 3.97 ms | 17.59x | 17.6x |
| `polkavm64_interpreter` | no | 9.89 ms | 43.79x | 43.8x |
| `nub_interp` | yes | 14.25 ms | 63.09x | 63.1x |

### poly-eval

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 678.06 µs | 1.00x | 1.0x |
| `nub_jit` † | yes | 1.13 ms | 1.66x | 1.7x |
| `wasmtime_cranelift_fuel` | yes | 1.49 ms | 2.20x | 2.2x |
| `wasmtime_cranelift` | no | 1.55 ms | 2.29x | 2.3x |
| `wasmtime_winch` | no | 1.69 ms | 2.50x | 2.5x |
| `wasmer_singlepass` | no | 4.99 ms | 7.36x | 7.4x |

### poseidon2-perm

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 574.69 µs | 1.00x | 1.0x |
| `nub_jit` † | yes | 1.20 ms | 2.09x | 2.1x |
| `polkavm64_recompiler_no_gas` | no | 1.39 ms | 2.42x | 2.4x |
| `polkavm64_recompiler_sync_gas` | yes | 1.39 ms | 2.42x | 2.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.40 ms | 2.43x | 2.4x |
| `polkavm64_recompiler_async_gas` | yes | 1.40 ms | 2.43x | 2.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.40 ms | 2.44x | 2.4x |
| `wasmtime_cranelift` | no | 1.94 ms | 3.37x | 3.4x |
| `wasmtime_cranelift_fuel` | yes | 1.97 ms | 3.42x | 3.4x |
| `wasmtime_winch` | no | 3.21 ms | 5.59x | 5.6x |
| `wasmer_singlepass` | no | 9.86 ms | 17.15x | 17.2x |
| `polkavm64_interpreter` | no | 22.73 ms | 39.55x | 39.5x |
| `nub_interp` | yes | 36.54 ms | 63.59x | 63.6x |

### prime-sieve

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `wasmtime_cranelift` | no | 77.17 µs | 1.00x | 0.8x |
| `polkavm64_recompiler_no_gas` | no | 89.70 µs | 1.16x | 0.9x |
| `native` | no | 97.07 µs | 1.26x | 1.0x |
| `wasmer_singlepass` | no | 130.29 µs | 1.69x | 1.3x |
| `wasmtime_cranelift_fuel` | yes | 146.83 µs | 1.90x | 1.5x |
| `wasmtime_winch` | no | 153.45 µs | 1.99x | 1.6x |
| `polkavm64_recompiler_async_gas` | yes | 189.97 µs | 2.46x | 2.0x |
| `polkavm64_recompiler_async_gas_full` | yes | 190.02 µs | 2.46x | 2.0x |
| `polkavm64_recompiler_sync_gas` | yes | 195.45 µs | 2.53x | 2.0x |
| `polkavm64_recompiler_sync_gas_full` | yes | 195.46 µs | 2.53x | 2.0x |
| `nub_jit` † | yes | 284.20 µs | 3.68x | 2.9x |
| `polkavm64_interpreter` | no | 2.14 ms | 27.72x | 22.0x |
| `nub_interp` | yes | 7.47 ms | 96.77x | 76.9x |
