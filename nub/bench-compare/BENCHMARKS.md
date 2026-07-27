# nub benchmark comparison

## Compile + execute, metered JIT engines

The bench target: each sample compiles the program and runs it, from cold, with metering on. That is how a metered VM is used when work arrives as a blob — the compile is not amortized away.

Only cost models comparable to nub's appear here. PolkaVM's default `Simple` model is a flat per-instruction cost and is much cheaper to evaluate than nub's pipeline simulation, so the `*_full` rows (`CacheModel::L2Hit`, whose `memory_access_cost: 25` is exactly nub's `MEM_CYCLES_BASE`) are the like-for-like comparison. Full tables for every engine and every measurement kind follow below.

| Program | `nub_jit` | `polkavm64_recompiler_sync_gas_full` | `polkavm64_recompiler_async_gas_full` | `wasmtime_cranelift_fuel` |
|---|--:|--:|--:|--:|
| ed25519 | 1.23 ms (1.59x) | **775.33 µs** (1.00x) | 777.50 µs (1.00x) | 29.41 ms (37.93x) |
| goldilocks-mul | 660.57 µs (1.57x) | 420.69 µs (1.00x) | **420.38 µs** (1.00x) | 1.06 ms (2.52x) |
| mini-verifier | 1.11 ms (1.58x) | **705.19 µs** (1.00x) | 706.48 µs (1.00x) | 3.80 ms (5.38x) |
| prime-sieve | 985.55 µs (3.62x) | 274.48 µs (1.01x) | **272.38 µs** (1.00x) | 1.03 ms (3.78x) |
| ecrecover | 2.63 ms (1.29x) | 2.06 ms (1.01x) | **2.04 ms** (1.00x) | 44.38 ms (21.72x) |
| fri-fold-tree | 1.15 ms (1.62x) | **710.26 µs** (1.00x) | 716.79 µs (1.01x) | 12.49 ms (17.58x) |
| keccak | 194.06 µs (1.97x) | **98.30 µs** (1.00x) | 100.12 µs (1.02x) | 2.89 ms (29.36x) |
| poseidon2-perm | 2.29 ms (1.51x) | **1.51 ms** (1.00x) | 1.51 ms (1.00x) | 4.35 ms (2.88x) |
| poly-eval | 1.84 ms (1.42x) | **1.29 ms** (1.00x) | 1.34 ms (1.04x) | 10.32 ms (7.97x) |
| blake2b | 269.77 µs (1.46x) | **185.25 µs** (1.00x) | 186.06 µs (1.00x) | 3.35 ms (18.09x) |

Bold = fastest for that program; the multiple is versus it.

### Where that time goes

Steady-state execution for the same rows, with compilation and instantiation excluded. The difference against the table above is each engine's cold-start cost.

| Program | `nub_jit` | `polkavm64_recompiler_sync_gas_full` | `polkavm64_recompiler_async_gas_full` | `wasmtime_cranelift_fuel` |
|---|--:|--:|--:|--:|
| ed25519 | 102.70 µs (+1.13 ms cold) | 91.10 µs (+684.23 µs cold) | 91.25 µs (+686.25 µs cold) | 238.30 µs (+29.17 ms cold) |
| goldilocks-mul | 325.27 µs (+335.29 µs cold) | 383.21 µs (+37.48 µs cold) | 383.21 µs (+37.16 µs cold) | 510.77 µs (+548.75 µs cold) |
| mini-verifier | 861.35 µs (+253.18 µs cold) | 577.89 µs (+127.29 µs cold) | 578.11 µs (+128.37 µs cold) | 813.90 µs (+2.98 ms cold) |
| prime-sieve | 316.81 µs (+668.74 µs cold) | 195.69 µs (+78.78 µs cold) | 190.43 µs (+81.95 µs cold) | 146.98 µs (+883.20 µs cold) |
| ecrecover | 397.72 µs (+2.23 ms cold) | 457.05 µs (+1.60 ms cold) | 439.05 µs (+1.60 ms cold) | 266.91 µs (+44.11 ms cold) |
| fri-fold-tree | 495.93 µs (+658.04 µs cold) | - | - | 741.42 µs (+11.75 ms cold) |
| keccak | 12.62 µs (+181.44 µs cold) | 3.90 µs (+94.40 µs cold) | 4.71 µs (+95.41 µs cold) | 2.35 µs (+2.88 ms cold) |
| poseidon2-perm | 1.20 ms (+1.08 ms cold) | 1.39 ms (+120.15 µs cold) | 1.40 ms (+112.94 µs cold) | 1.91 ms (+2.44 ms cold) |
| poly-eval | 1.09 ms (+747.30 µs cold) | - | - | 1.44 ms (+8.88 ms cold) |
| blake2b | 10.89 µs (+258.88 µs cold) | 2.42 µs (+182.84 µs cold) | 2.35 µs (+183.71 µs cold) | 819.0 ns (+3.35 ms cold) |

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

Turning the program into executable form. Engine construction is excluded (a once-per-process cost). `native` is absent: the OS loader already did it.

### blake2b

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 22.07 µs | 1.00x | - |
| `polkavm64_recompiler_sync_gas` | yes | 22.14 µs | 1.00x | - |
| `polkavm64_recompiler_async_gas` | yes | 22.57 µs | 1.02x | - |
| `polkavm64_recompiler_no_gas` | no | 23.18 µs | 1.05x | - |
| `nub_jit_compile` | yes | 43.04 µs | 1.95x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 105.21 µs | 4.77x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 105.91 µs | 4.80x | - |
| `wasmtime_winch` | no | 459.50 µs | 20.82x | - |
| `wasmer_singlepass` | no | 1.20 ms | 54.29x | - |
| `wasmtime_cranelift` | no | 3.25 ms | 147.13x | - |
| `wasmtime_cranelift_fuel` | yes | 3.44 ms | 155.82x | - |

### ecrecover

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 216.36 µs | 1.00x | - |
| `polkavm64_recompiler_async_gas` | yes | 270.80 µs | 1.25x | - |
| `polkavm64_recompiler_no_gas` | no | 271.35 µs | 1.25x | - |
| `polkavm64_recompiler_sync_gas` | yes | 272.72 µs | 1.26x | - |
| `nub_jit_compile` | yes | 726.22 µs | 3.36x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 1.40 ms | 6.48x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.41 ms | 6.53x | - |
| `wasmer_singlepass` | no | 3.29 ms | 15.21x | - |
| `wasmtime_winch` | no | 5.24 ms | 24.23x | - |
| `wasmtime_cranelift` | no | 37.09 ms | 171.41x | - |
| `wasmtime_cranelift_fuel` | yes | 45.17 ms | 208.79x | - |

### ed25519

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 94.43 µs | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 117.73 µs | 1.25x | - |
| `polkavm64_recompiler_async_gas` | yes | 120.03 µs | 1.27x | - |
| `polkavm64_recompiler_sync_gas` | yes | 122.81 µs | 1.30x | - |
| `nub_jit_compile` | yes | 339.13 µs | 3.59x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 548.09 µs | 5.80x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 565.14 µs | 5.98x | - |
| `wasmtime_winch` | no | 2.88 ms | 30.48x | - |
| `wasmer_singlepass` | no | 3.98 ms | 42.19x | - |
| `wasmtime_cranelift` | no | 24.65 ms | 261.00x | - |
| `wasmtime_cranelift_fuel` | yes | 30.52 ms | 323.21x | - |

### fri-fold-tree

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 12.47 µs | 1.00x | - |
| `polkavm64_recompiler_async_gas` | yes | 14.30 µs | 1.15x | - |
| `polkavm64_recompiler_sync_gas` | yes | 15.31 µs | 1.23x | - |
| `polkavm64_recompiler_no_gas` | no | 15.55 µs | 1.25x | - |
| `nub_jit_compile` | yes | 32.92 µs | 2.64x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 58.02 µs | 4.65x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 58.13 µs | 4.66x | - |
| `wasmer_singlepass` | no | 1.54 ms | 123.52x | - |
| `wasmtime_winch` | no | 1.69 ms | 135.34x | - |
| `wasmtime_cranelift` | no | 8.11 ms | 650.31x | - |
| `wasmtime_cranelift_fuel` | yes | 11.57 ms | 928.34x | - |

### goldilocks-mul

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_recompiler_no_gas` | no | 3.67 µs | 1.00x | - |
| `polkavm64_recompiler_async_gas` | yes | 3.80 µs | 1.04x | - |
| `polkavm64_recompiler_sync_gas` | yes | 3.85 µs | 1.05x | - |
| `polkavm64_interpreter` | no | 5.07 µs | 1.38x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 5.32 µs | 1.45x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 5.32 µs | 1.45x | - |
| `nub_jit_compile` | yes | 8.24 µs | 2.24x | - |
| `wasmtime_winch` | no | 232.25 µs | 63.21x | - |
| `wasmtime_cranelift` | no | 409.31 µs | 111.41x | - |
| `wasmtime_cranelift_fuel` | yes | 544.80 µs | 148.28x | - |
| `wasmer_singlepass` | no | 728.06 µs | 198.17x | - |

### keccak

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_recompiler_async_gas` | yes | 9.83 µs | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 10.19 µs | 1.04x | - |
| `polkavm64_recompiler_sync_gas` | yes | 10.29 µs | 1.05x | - |
| `polkavm64_interpreter` | no | 14.78 µs | 1.50x | - |
| `nub_jit_compile` | yes | 26.14 µs | 2.66x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 37.01 µs | 3.76x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 37.15 µs | 3.78x | - |
| `wasmtime_winch` | no | 781.69 µs | 79.49x | - |
| `wasmer_singlepass` | no | 922.07 µs | 93.76x | - |
| `wasmtime_cranelift` | no | 2.18 ms | 222.07x | - |
| `wasmtime_cranelift_fuel` | yes | 2.96 ms | 300.84x | - |

### mini-verifier

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 12.39 µs | 1.00x | - |
| `polkavm64_recompiler_sync_gas` | yes | 13.76 µs | 1.11x | - |
| `polkavm64_recompiler_no_gas` | no | 14.39 µs | 1.16x | - |
| `polkavm64_recompiler_async_gas` | yes | 14.52 µs | 1.17x | - |
| `nub_jit_compile` | yes | 27.69 µs | 2.24x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 56.19 µs | 4.54x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 57.16 µs | 4.61x | - |
| `wasmtime_winch` | no | 583.61 µs | 47.11x | - |
| `wasmer_singlepass` | no | 1.02 ms | 82.59x | - |
| `wasmtime_cranelift` | no | 2.45 ms | 197.94x | - |
| `wasmtime_cranelift_fuel` | yes | 2.96 ms | 238.92x | - |

### poly-eval

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 4.03 µs | 1.00x | - |
| `polkavm64_recompiler_async_gas` | yes | 5.33 µs | 1.32x | - |
| `polkavm64_recompiler_no_gas` | no | 5.50 µs | 1.37x | - |
| `polkavm64_recompiler_sync_gas` | yes | 5.58 µs | 1.38x | - |
| `nub_jit_compile` | yes | 8.86 µs | 2.20x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 13.72 µs | 3.41x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 13.75 µs | 3.41x | - |
| `wasmtime_winch` | no | 1.35 ms | 335.23x | - |
| `wasmer_singlepass` | no | 1.49 ms | 369.93x | - |
| `wasmtime_cranelift` | no | 5.44 ms | 1349.90x | - |
| `wasmtime_cranelift_fuel` | yes | 8.60 ms | 2134.93x | - |

### poseidon2-perm

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 10.48 µs | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 10.51 µs | 1.00x | - |
| `polkavm64_recompiler_async_gas` | yes | 10.72 µs | 1.02x | - |
| `polkavm64_recompiler_sync_gas` | yes | 11.17 µs | 1.07x | - |
| `nub_jit_compile` | yes | 23.15 µs | 2.21x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 41.73 µs | 3.98x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 42.03 µs | 4.01x | - |
| `wasmtime_winch` | no | 497.88 µs | 47.52x | - |
| `wasmer_singlepass` | no | 950.25 µs | 90.69x | - |
| `wasmtime_cranelift` | no | 2.01 ms | 191.48x | - |
| `wasmtime_cranelift_fuel` | yes | 2.45 ms | 233.61x | - |

### prime-sieve

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 4.45 µs | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 6.83 µs | 1.53x | - |
| `polkavm64_recompiler_async_gas` | yes | 6.88 µs | 1.54x | - |
| `polkavm64_recompiler_sync_gas` | yes | 6.89 µs | 1.55x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 9.31 µs | 2.09x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 9.33 µs | 2.09x | - |
| `nub_jit_compile` | yes | 11.46 µs | 2.57x | - |
| `wasmtime_winch` | no | 393.20 µs | 88.28x | - |
| `wasmtime_cranelift` | no | 548.80 µs | 123.21x | - |
| `wasmer_singlepass` | no | 742.64 µs | 166.74x | - |
| `wasmtime_cranelift_fuel` | yes | 853.28 µs | 191.58x | - |

## invoke

Cold invocation with compilation excluded: a fresh instance every sample. Where an engine's *instantiation* strategy shows up. Compare against `runtime` for the same row to see what a cold start costs it.

### blake2b

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 693.0 ns | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 2.65 µs | 3.83x | 3.8x |
| `wasmtime_cranelift_fuel` | yes | 2.70 µs | 3.89x | 3.9x |
| `wasmtime_winch` | no | 3.23 µs | 4.66x | 4.7x |
| `polkavm64_recompiler_no_gas` | no | 7.23 µs | 10.43x | 10.4x |
| `polkavm64_recompiler_async_gas` | yes | 7.72 µs | 11.14x | 11.1x |
| `polkavm64_recompiler_sync_gas_full` | yes | 7.78 µs | 11.23x | 11.2x |
| `polkavm64_recompiler_sync_gas` | yes | 7.81 µs | 11.28x | 11.3x |
| `polkavm64_recompiler_async_gas_full` | yes | 8.66 µs | 12.50x | 12.5x |
| `nub_jit` | yes | 11.78 µs | 17.00x | 17.0x |
| `wasmer_singlepass` | no | 11.98 µs | 17.28x | 17.3x |
| `polkavm64_interpreter` | no | 102.07 µs | 147.29x | 147.3x |
| `nub_interp` | yes | 164.31 µs | 237.10x | 237.1x |

### ecrecover

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `wasmtime_cranelift` | no | 263.01 µs | 1.00x | 0.8x |
| `wasmtime_cranelift_fuel` | yes | 270.31 µs | 1.03x | 0.9x |
| `native` | no | 317.55 µs | 1.21x | 1.0x |
| `wasmtime_winch` | no | 389.13 µs | 1.48x | 1.2x |
| `nub_jit` | yes | 393.69 µs | 1.50x | 1.2x |
| `polkavm64_recompiler_no_gas` | no | 410.73 µs | 1.56x | 1.3x |
| `polkavm64_recompiler_async_gas_full` | yes | 449.22 µs | 1.71x | 1.4x |
| `polkavm64_recompiler_async_gas` | yes | 449.92 µs | 1.71x | 1.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 466.29 µs | 1.77x | 1.5x |
| `polkavm64_recompiler_sync_gas` | yes | 468.18 µs | 1.78x | 1.5x |
| `wasmer_singlepass` | no | 1.36 ms | 5.18x | 4.3x |
| `polkavm64_interpreter` | no | 11.79 ms | 44.84x | 37.1x |
| `nub_interp` | yes | 26.50 ms | 100.74x | 83.4x |

### ed25519

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 31.06 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 90.73 µs | 2.92x | 2.9x |
| `polkavm64_recompiler_sync_gas_full` | yes | 99.70 µs | 3.21x | 3.2x |
| `polkavm64_recompiler_async_gas` | yes | 100.58 µs | 3.24x | 3.2x |
| `polkavm64_recompiler_async_gas_full` | yes | 100.94 µs | 3.25x | 3.2x |
| `polkavm64_recompiler_sync_gas` | yes | 101.09 µs | 3.25x | 3.3x |
| `nub_jit` | yes | 175.16 µs | 5.64x | 5.6x |
| `wasmtime_cranelift` | no | 198.77 µs | 6.40x | 6.4x |
| `wasmtime_cranelift_fuel` | yes | 241.58 µs | 7.78x | 7.8x |
| `wasmtime_winch` | no | 349.67 µs | 11.26x | 11.3x |
| `wasmer_singlepass` | no | 1.38 ms | 44.54x | 44.5x |
| `polkavm64_interpreter` | no | 1.69 ms | 54.30x | 54.3x |
| `nub_interp` | yes | 5.21 ms | 167.65x | 167.6x |

### fri-fold-tree

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 239.43 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 488.02 µs | 2.04x | 2.0x |
| `polkavm64_recompiler_no_gas` | no | 564.52 µs | 2.36x | 2.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 565.26 µs | 2.36x | 2.4x |
| `polkavm64_recompiler_async_gas` | yes | 567.14 µs | 2.37x | 2.4x |
| `polkavm64_recompiler_sync_gas` | yes | 569.46 µs | 2.38x | 2.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 569.73 µs | 2.38x | 2.4x |
| `wasmtime_cranelift` | no | 765.25 µs | 3.20x | 3.2x |
| `wasmtime_cranelift_fuel` | yes | 787.84 µs | 3.29x | 3.3x |
| `wasmtime_winch` | no | 1.30 ms | 5.44x | 5.4x |
| `wasmer_singlepass` | no | 5.31 ms | 22.17x | 22.2x |
| `polkavm64_interpreter` | no | 9.29 ms | 38.82x | 38.8x |
| `nub_interp` | yes | 13.71 ms | 57.24x | 57.2x |

### goldilocks-mul

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 212.05 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 322.87 µs | 1.52x | 1.5x |
| `polkavm64_recompiler_no_gas` | no | 348.60 µs | 1.64x | 1.6x |
| `polkavm64_recompiler_async_gas_full` | yes | 384.73 µs | 1.81x | 1.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 384.74 µs | 1.81x | 1.8x |
| `polkavm64_recompiler_async_gas` | yes | 384.99 µs | 1.82x | 1.8x |
| `polkavm64_recompiler_sync_gas` | yes | 385.04 µs | 1.82x | 1.8x |
| `wasmtime_cranelift_fuel` | yes | 516.04 µs | 2.43x | 2.4x |
| `wasmtime_cranelift` | no | 534.85 µs | 2.52x | 2.5x |
| `wasmtime_winch` | no | 554.11 µs | 2.61x | 2.6x |
| `wasmer_singlepass` | no | 1.57 ms | 7.42x | 7.4x |
| `polkavm64_interpreter` | no | 2.07 ms | 9.77x | 9.8x |
| `nub_interp` | yes | 4.13 ms | 19.50x | 19.5x |

### keccak

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 2.88 µs | 1.00x | 1.0x |
| `wasmtime_cranelift_fuel` | yes | 4.59 µs | 1.60x | 1.6x |
| `wasmtime_cranelift` | no | 4.66 µs | 1.62x | 1.6x |
| `wasmtime_winch` | no | 4.99 µs | 1.73x | 1.7x |
| `wasmer_singlepass` | no | 5.98 µs | 2.08x | 2.1x |
| `polkavm64_recompiler_no_gas` | no | 10.60 µs | 3.69x | 3.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 11.29 µs | 3.93x | 3.9x |
| `polkavm64_recompiler_async_gas` | yes | 11.31 µs | 3.93x | 3.9x |
| `polkavm64_recompiler_async_gas_full` | yes | 11.46 µs | 3.98x | 4.0x |
| `polkavm64_recompiler_sync_gas` | yes | 11.89 µs | 4.14x | 4.1x |
| `nub_jit` | yes | 28.11 µs | 9.78x | 9.8x |
| `polkavm64_interpreter` | no | 194.22 µs | 67.56x | 67.6x |
| `nub_interp` | yes | 519.86 µs | 180.82x | 180.8x |

### mini-verifier

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 247.87 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 482.44 µs | 1.95x | 1.9x |
| `polkavm64_recompiler_sync_gas_full` | yes | 565.94 µs | 2.28x | 2.3x |
| `polkavm64_recompiler_no_gas` | no | 579.55 µs | 2.34x | 2.3x |
| `polkavm64_recompiler_async_gas_full` | yes | 583.12 µs | 2.35x | 2.4x |
| `polkavm64_recompiler_async_gas` | yes | 583.70 µs | 2.35x | 2.4x |
| `polkavm64_recompiler_sync_gas` | yes | 584.35 µs | 2.36x | 2.4x |
| `wasmtime_cranelift` | no | 785.70 µs | 3.17x | 3.2x |
| `wasmtime_cranelift_fuel` | yes | 786.80 µs | 3.17x | 3.2x |
| `wasmtime_winch` | no | 1.28 ms | 5.18x | 5.2x |
| `wasmer_singlepass` | no | 4.36 ms | 17.60x | 17.6x |
| `polkavm64_interpreter` | no | 9.68 ms | 39.07x | 39.1x |
| `nub_interp` | yes | 14.45 ms | 58.29x | 58.3x |

### poly-eval

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 712.14 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 1.14 ms | 1.60x | 1.6x |
| `polkavm64_recompiler_no_gas` | no | 1.21 ms | 1.70x | 1.7x |
| `polkavm64_recompiler_sync_gas` | yes | 1.22 ms | 1.71x | 1.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.23 ms | 1.72x | 1.7x |
| `polkavm64_recompiler_async_gas` | yes | 1.27 ms | 1.78x | 1.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.28 ms | 1.80x | 1.8x |
| `wasmtime_cranelift_fuel` | yes | 1.48 ms | 2.07x | 2.1x |
| `wasmtime_cranelift` | no | 1.57 ms | 2.20x | 2.2x |
| `wasmtime_winch` | no | 1.71 ms | 2.40x | 2.4x |
| `wasmer_singlepass` | no | 6.39 ms | 8.98x | 9.0x |
| `polkavm64_interpreter` | no | 8.21 ms | 11.53x | 11.5x |
| `nub_interp` | yes | 17.72 ms | 24.89x | 24.9x |

### poseidon2-perm

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 603.48 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 1.20 ms | 1.98x | 2.0x |
| `polkavm64_recompiler_no_gas` | no | 1.40 ms | 2.31x | 2.3x |
| `polkavm64_recompiler_sync_gas` | yes | 1.40 ms | 2.32x | 2.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.41 ms | 2.33x | 2.3x |
| `polkavm64_recompiler_async_gas` | yes | 1.41 ms | 2.33x | 2.3x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.41 ms | 2.33x | 2.3x |
| `wasmtime_cranelift` | no | 1.94 ms | 3.21x | 3.2x |
| `wasmtime_cranelift_fuel` | yes | 1.96 ms | 3.24x | 3.2x |
| `wasmtime_winch` | no | 3.20 ms | 5.30x | 5.3x |
| `wasmer_singlepass` | no | 10.60 ms | 17.57x | 17.6x |
| `polkavm64_interpreter` | no | 22.03 ms | 36.50x | 36.5x |
| `nub_interp` | yes | 37.38 ms | 61.94x | 61.9x |

### prime-sieve

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 57.18 µs | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 95.80 µs | 1.68x | 1.7x |
| `polkavm64_recompiler_no_gas` | no | 114.25 µs | 2.00x | 2.0x |
| `wasmer_singlepass` | no | 131.72 µs | 2.30x | 2.3x |
| `wasmtime_cranelift_fuel` | yes | 165.72 µs | 2.90x | 2.9x |
| `wasmtime_winch` | no | 168.82 µs | 2.95x | 3.0x |
| `polkavm64_recompiler_async_gas` | yes | 210.18 µs | 3.68x | 3.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 210.51 µs | 3.68x | 3.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 214.60 µs | 3.75x | 3.8x |
| `polkavm64_recompiler_sync_gas` | yes | 215.67 µs | 3.77x | 3.8x |
| `nub_jit` | yes | 271.63 µs | 4.75x | 4.8x |
| `polkavm64_interpreter` | no | 2.05 ms | 35.82x | 35.8x |
| `nub_interp` | yes | 7.34 ms | 128.35x | 128.3x |

## oneshot

Compile **and** execute, from cold, every sample. The metric that matches how a metered VM is actually used: work arrives as a blob that must be compiled and then run, and each iteration pays both. Engines that cache compilation internally are evicted first, so no row skips the compile half.

### blake2b

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 14.02 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 80.53 µs | 5.75x | 5.7x |
| `polkavm64_recompiler_async_gas` | yes | 83.34 µs | 5.95x | 5.9x |
| `polkavm64_recompiler_sync_gas` | yes | 84.54 µs | 6.03x | 6.0x |
| `polkavm64_interpreter` | no | 126.46 µs | 9.02x | 9.0x |
| `polkavm64_recompiler_sync_gas_full` | yes | 185.25 µs | 13.22x | 13.2x |
| `polkavm64_recompiler_async_gas_full` | yes | 186.06 µs | 13.27x | 13.3x |
| `nub_interp` | yes | 223.98 µs | 15.98x | 16.0x |
| `nub_jit` | yes | 269.77 µs | 19.25x | 19.2x |
| `wasmtime_winch` | no | 471.41 µs | 33.63x | 33.6x |
| `wasmer_singlepass` | no | 2.25 ms | 160.45x | 160.4x |
| `wasmtime_cranelift` | no | 3.21 ms | 228.92x | 228.9x |
| `wasmtime_cranelift_fuel` | yes | 3.35 ms | 239.09x | 239.1x |

### ecrecover

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 118.66 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 884.61 µs | 7.45x | 7.5x |
| `polkavm64_recompiler_async_gas` | yes | 918.46 µs | 7.74x | 7.7x |
| `polkavm64_recompiler_sync_gas` | yes | 947.82 µs | 7.99x | 8.0x |
| `polkavm64_recompiler_async_gas_full` | yes | 2.04 ms | 17.22x | 17.2x |
| `polkavm64_recompiler_sync_gas_full` | yes | 2.06 ms | 17.38x | 17.4x |
| `nub_jit` | yes | 2.63 ms | 22.16x | 22.2x |
| `wasmtime_winch` | no | 5.31 ms | 44.78x | 44.8x |
| `wasmer_singlepass` | no | 8.01 ms | 67.46x | 67.5x |
| `polkavm64_interpreter` | no | 12.06 ms | 101.67x | 101.7x |
| `nub_interp` | yes | 28.13 ms | 237.08x | 237.1x |
| `wasmtime_cranelift` | no | 35.45 ms | 298.71x | 298.7x |
| `wasmtime_cranelift_fuel` | yes | 44.38 ms | 373.97x | 374.0x |

### ed25519

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 47.37 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 310.05 µs | 6.55x | 6.5x |
| `polkavm64_recompiler_async_gas` | yes | 315.77 µs | 6.67x | 6.7x |
| `polkavm64_recompiler_sync_gas` | yes | 318.93 µs | 6.73x | 6.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 775.33 µs | 16.37x | 16.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 777.50 µs | 16.42x | 16.4x |
| `nub_jit` | yes | 1.23 ms | 25.98x | 26.0x |
| `polkavm64_interpreter` | no | 1.77 ms | 37.27x | 37.3x |
| `wasmtime_winch` | no | 3.10 ms | 65.55x | 65.5x |
| `nub_interp` | yes | 5.59 ms | 118.02x | 118.0x |
| `wasmer_singlepass` | no | 8.92 ms | 188.28x | 188.3x |
| `wasmtime_cranelift` | no | 24.13 ms | 509.45x | 509.4x |
| `wasmtime_cranelift_fuel` | yes | 29.41 ms | 620.96x | 621.0x |

### fri-fold-tree

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 259.38 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 648.45 µs | 2.50x | 2.5x |
| `polkavm64_recompiler_async_gas` | yes | 650.36 µs | 2.51x | 2.5x |
| `polkavm64_recompiler_sync_gas` | yes | 655.64 µs | 2.53x | 2.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 710.26 µs | 2.74x | 2.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 716.79 µs | 2.76x | 2.8x |
| `nub_jit` | yes | 1.15 ms | 4.45x | 4.4x |
| `wasmtime_winch` | no | 3.05 ms | 11.78x | 11.8x |
| `wasmer_singlepass` | no | 7.62 ms | 29.38x | 29.4x |
| `wasmtime_cranelift` | no | 8.96 ms | 34.55x | 34.5x |
| `polkavm64_interpreter` | no | 9.30 ms | 35.85x | 35.9x |
| `wasmtime_cranelift_fuel` | yes | 12.49 ms | 48.15x | 48.1x |
| `nub_interp` | yes | 14.39 ms | 55.48x | 55.5x |

### goldilocks-mul

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 381.31 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 384.06 µs | 1.01x | 1.0x |
| `polkavm64_recompiler_async_gas_full` | yes | 420.38 µs | 1.10x | 1.1x |
| `polkavm64_recompiler_sync_gas_full` | yes | 420.69 µs | 1.10x | 1.1x |
| `polkavm64_recompiler_sync_gas` | yes | 421.26 µs | 1.10x | 1.1x |
| `polkavm64_recompiler_async_gas` | yes | 422.86 µs | 1.11x | 1.1x |
| `nub_jit` | yes | 660.57 µs | 1.73x | 1.7x |
| `wasmtime_winch` | no | 775.53 µs | 2.03x | 2.0x |
| `wasmtime_cranelift` | no | 952.31 µs | 2.50x | 2.5x |
| `wasmtime_cranelift_fuel` | yes | 1.06 ms | 2.78x | 2.8x |
| `polkavm64_interpreter` | no | 2.16 ms | 5.66x | 5.7x |
| `wasmer_singlepass` | no | 2.94 ms | 7.70x | 7.7x |
| `nub_interp` | yes | 4.05 ms | 10.61x | 10.6x |

### keccak

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 14.81 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_sync_gas` | yes | 64.47 µs | 4.35x | 4.4x |
| `polkavm64_recompiler_async_gas` | yes | 65.52 µs | 4.42x | 4.4x |
| `polkavm64_recompiler_no_gas` | no | 65.53 µs | 4.42x | 4.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 98.30 µs | 6.64x | 6.6x |
| `polkavm64_recompiler_async_gas_full` | yes | 100.12 µs | 6.76x | 6.8x |
| `polkavm64_interpreter` | no | 113.79 µs | 7.68x | 7.7x |
| `nub_jit` | yes | 194.06 µs | 13.10x | 13.1x |
| `nub_interp` | yes | 278.04 µs | 18.77x | 18.8x |
| `wasmtime_winch` | no | 819.21 µs | 55.31x | 55.3x |
| `wasmer_singlepass` | no | 1.82 ms | 122.96x | 123.0x |
| `wasmtime_cranelift` | no | 2.20 ms | 148.52x | 148.5x |
| `wasmtime_cranelift_fuel` | yes | 2.89 ms | 194.90x | 194.9x |

### mini-verifier

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 261.06 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 645.11 µs | 2.47x | 2.5x |
| `polkavm64_recompiler_sync_gas` | yes | 647.55 µs | 2.48x | 2.5x |
| `polkavm64_recompiler_async_gas` | yes | 647.90 µs | 2.48x | 2.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 705.19 µs | 2.70x | 2.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 706.48 µs | 2.71x | 2.7x |
| `nub_jit` | yes | 1.11 ms | 4.27x | 4.3x |
| `wasmtime_winch` | no | 1.93 ms | 7.38x | 7.4x |
| `wasmtime_cranelift` | no | 3.25 ms | 12.47x | 12.5x |
| `wasmtime_cranelift_fuel` | yes | 3.80 ms | 14.54x | 14.5x |
| `wasmer_singlepass` | no | 6.40 ms | 24.51x | 24.5x |
| `polkavm64_interpreter` | no | 9.91 ms | 37.97x | 38.0x |
| `nub_interp` | yes | 14.69 ms | 56.28x | 56.3x |

### poly-eval

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 724.84 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 1.25 ms | 1.73x | 1.7x |
| `polkavm64_recompiler_sync_gas` | yes | 1.28 ms | 1.77x | 1.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.29 ms | 1.79x | 1.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.34 ms | 1.85x | 1.9x |
| `polkavm64_recompiler_async_gas` | yes | 1.34 ms | 1.85x | 1.9x |
| `nub_jit` | yes | 1.84 ms | 2.54x | 2.5x |
| `wasmtime_winch` | no | 3.20 ms | 4.42x | 4.4x |
| `wasmtime_cranelift` | no | 7.29 ms | 10.06x | 10.1x |
| `polkavm64_interpreter` | no | 8.30 ms | 11.46x | 11.5x |
| `wasmer_singlepass` | no | 9.69 ms | 13.37x | 13.4x |
| `wasmtime_cranelift_fuel` | yes | 10.32 ms | 14.24x | 14.2x |
| `nub_interp` | yes | 17.70 ms | 24.42x | 24.4x |

### poseidon2-perm

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 622.57 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 1.46 ms | 2.35x | 2.4x |
| `polkavm64_recompiler_sync_gas` | yes | 1.47 ms | 2.37x | 2.4x |
| `polkavm64_recompiler_async_gas` | yes | 1.48 ms | 2.37x | 2.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.51 ms | 2.43x | 2.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.51 ms | 2.43x | 2.4x |
| `nub_jit` | yes | 2.29 ms | 3.67x | 3.7x |
| `wasmtime_winch` | no | 3.58 ms | 5.75x | 5.7x |
| `wasmtime_cranelift` | no | 3.93 ms | 6.31x | 6.3x |
| `wasmtime_cranelift_fuel` | yes | 4.35 ms | 6.99x | 7.0x |
| `wasmer_singlepass` | no | 12.52 ms | 20.11x | 20.1x |
| `polkavm64_interpreter` | no | 21.76 ms | 34.95x | 35.0x |
| `nub_interp` | yes | 35.76 ms | 57.44x | 57.4x |

### prime-sieve

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 92.35 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 174.94 µs | 1.89x | 1.9x |
| `polkavm64_recompiler_async_gas` | yes | 269.34 µs | 2.92x | 2.9x |
| `polkavm64_recompiler_async_gas_full` | yes | 272.38 µs | 2.95x | 2.9x |
| `polkavm64_recompiler_sync_gas_full` | yes | 274.48 µs | 2.97x | 3.0x |
| `polkavm64_recompiler_sync_gas` | yes | 278.06 µs | 3.01x | 3.0x |
| `wasmtime_winch` | no | 535.44 µs | 5.80x | 5.8x |
| `wasmtime_cranelift` | no | 645.66 µs | 6.99x | 7.0x |
| `nub_jit` | yes | 985.55 µs | 10.67x | 10.7x |
| `wasmtime_cranelift_fuel` | yes | 1.03 ms | 11.16x | 11.2x |
| `wasmer_singlepass` | no | 1.65 ms | 17.88x | 17.9x |
| `polkavm64_interpreter` | no | 2.14 ms | 23.21x | 23.2x |
| `nub_interp` | yes | 7.50 ms | 81.20x | 81.2x |

## runtime

Steady-state execution: one instance, invoked repeatedly. How fast the engine *executes*, with instantiation excluded.

Rows are absent where a program cannot be re-run in one instance (the three guests with a never-freeing bump arena).

### blake2b

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `wasmtime_cranelift` | no | 795.0 ns | 1.00x | 0.8x |
| `wasmtime_cranelift_fuel` | yes | 819.0 ns | 1.03x | 0.8x |
| `native` | no | 1.03 µs | 1.30x | 1.0x |
| `wasmtime_winch` | no | 1.29 µs | 1.62x | 1.2x |
| `polkavm64_recompiler_no_gas` | no | 1.81 µs | 2.28x | 1.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 2.35 µs | 2.95x | 2.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 2.42 µs | 3.04x | 2.3x |
| `polkavm64_recompiler_sync_gas` | yes | 2.45 µs | 3.08x | 2.4x |
| `polkavm64_recompiler_async_gas` | yes | 2.51 µs | 3.16x | 2.4x |
| `wasmer_singlepass` | no | 5.14 µs | 6.47x | 5.0x |
| `nub_jit` | yes | 10.89 µs | 13.70x | 10.5x |
| `polkavm64_interpreter` | no | 44.48 µs | 55.95x | 43.1x |
| `nub_interp` | yes | 273.24 µs | 343.70x | 264.5x |

### ecrecover

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 100.08 µs | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 258.55 µs | 2.58x | 2.6x |
| `wasmtime_cranelift_fuel` | yes | 266.91 µs | 2.67x | 2.7x |
| `wasmtime_winch` | no | 388.31 µs | 3.88x | 3.9x |
| `polkavm64_recompiler_no_gas` | no | 397.20 µs | 3.97x | 4.0x |
| `nub_jit` | yes | 397.72 µs | 3.97x | 4.0x |
| `polkavm64_recompiler_async_gas_full` | yes | 439.05 µs | 4.39x | 4.4x |
| `polkavm64_recompiler_async_gas` | yes | 439.92 µs | 4.40x | 4.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 457.05 µs | 4.57x | 4.6x |
| `polkavm64_recompiler_sync_gas` | yes | 457.89 µs | 4.58x | 4.6x |
| `wasmer_singlepass` | no | 824.00 µs | 8.23x | 8.2x |
| `polkavm64_interpreter` | no | 11.64 ms | 116.27x | 116.3x |
| `nub_interp` | yes | 27.33 ms | 273.11x | 273.1x |

### ed25519

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 32.09 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 81.03 µs | 2.52x | 2.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 91.10 µs | 2.84x | 2.8x |
| `polkavm64_recompiler_sync_gas` | yes | 91.12 µs | 2.84x | 2.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 91.25 µs | 2.84x | 2.8x |
| `polkavm64_recompiler_async_gas` | yes | 91.46 µs | 2.85x | 2.8x |
| `nub_jit` | yes | 102.70 µs | 3.20x | 3.2x |
| `wasmtime_cranelift` | no | 196.77 µs | 6.13x | 6.1x |
| `wasmtime_cranelift_fuel` | yes | 238.30 µs | 7.43x | 7.4x |
| `wasmtime_winch` | no | 345.55 µs | 10.77x | 10.8x |
| `wasmer_singlepass` | no | 975.88 µs | 30.41x | 30.4x |
| `polkavm64_interpreter` | no | 1.45 ms | 45.13x | 45.1x |
| `nub_interp` | yes | 5.11 ms | 159.12x | 159.1x |

### fri-fold-tree

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 217.80 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 495.93 µs | 2.28x | 2.3x |
| `wasmtime_cranelift` | no | 721.13 µs | 3.31x | 3.3x |
| `wasmtime_cranelift_fuel` | yes | 741.42 µs | 3.40x | 3.4x |
| `wasmtime_winch` | no | 1.23 ms | 5.64x | 5.6x |
| `wasmer_singlepass` | no | 3.58 ms | 16.44x | 16.4x |

### goldilocks-mul

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 202.31 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 325.27 µs | 1.61x | 1.6x |
| `polkavm64_recompiler_no_gas` | no | 346.99 µs | 1.72x | 1.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 383.21 µs | 1.89x | 1.9x |
| `polkavm64_recompiler_async_gas_full` | yes | 383.21 µs | 1.89x | 1.9x |
| `polkavm64_recompiler_sync_gas` | yes | 383.22 µs | 1.89x | 1.9x |
| `polkavm64_recompiler_async_gas` | yes | 383.27 µs | 1.89x | 1.9x |
| `wasmtime_winch` | no | 506.88 µs | 2.51x | 2.5x |
| `wasmtime_cranelift_fuel` | yes | 510.77 µs | 2.52x | 2.5x |
| `wasmtime_cranelift` | no | 533.35 µs | 2.64x | 2.6x |
| `wasmer_singlepass` | no | 1.47 ms | 7.28x | 7.3x |
| `polkavm64_interpreter` | no | 2.13 ms | 10.51x | 10.5x |
| `nub_interp` | yes | 4.09 ms | 20.22x | 20.2x |

### keccak

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 1.65 µs | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 2.25 µs | 1.36x | 1.4x |
| `wasmtime_cranelift_fuel` | yes | 2.35 µs | 1.42x | 1.4x |
| `wasmtime_winch` | no | 2.77 µs | 1.68x | 1.7x |
| `polkavm64_recompiler_no_gas` | no | 3.16 µs | 1.91x | 1.9x |
| `polkavm64_recompiler_sync_gas_full` | yes | 3.90 µs | 2.36x | 2.4x |
| `polkavm64_recompiler_async_gas` | yes | 3.91 µs | 2.37x | 2.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 4.71 µs | 2.85x | 2.8x |
| `polkavm64_recompiler_sync_gas` | yes | 4.76 µs | 2.88x | 2.9x |
| `wasmer_singlepass` | no | 6.37 µs | 3.85x | 3.8x |
| `nub_jit` | yes | 12.62 µs | 7.63x | 7.6x |
| `polkavm64_interpreter` | no | 73.59 µs | 44.49x | 44.5x |
| `nub_interp` | yes | 237.61 µs | 143.66x | 143.7x |

### mini-verifier

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 222.46 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_async_gas` | yes | 576.96 µs | 2.59x | 2.6x |
| `polkavm64_recompiler_no_gas` | no | 576.97 µs | 2.59x | 2.6x |
| `polkavm64_recompiler_sync_gas` | yes | 577.79 µs | 2.60x | 2.6x |
| `polkavm64_recompiler_sync_gas_full` | yes | 577.89 µs | 2.60x | 2.6x |
| `polkavm64_recompiler_async_gas_full` | yes | 578.11 µs | 2.60x | 2.6x |
| `wasmtime_cranelift` | no | 786.25 µs | 3.53x | 3.5x |
| `wasmtime_cranelift_fuel` | yes | 813.90 µs | 3.66x | 3.7x |
| `nub_jit` | yes | 861.35 µs | 3.87x | 3.9x |
| `wasmtime_winch` | no | 1.36 ms | 6.13x | 6.1x |
| `wasmer_singlepass` | no | 3.97 ms | 17.86x | 17.9x |
| `polkavm64_interpreter` | no | 9.45 ms | 42.50x | 42.5x |
| `nub_interp` | yes | 13.97 ms | 62.81x | 62.8x |

### poly-eval

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 651.90 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 1.09 ms | 1.67x | 1.7x |
| `wasmtime_cranelift_fuel` | yes | 1.44 ms | 2.21x | 2.2x |
| `wasmtime_cranelift` | no | 1.49 ms | 2.29x | 2.3x |
| `wasmtime_winch` | no | 1.61 ms | 2.48x | 2.5x |
| `wasmer_singlepass` | no | 4.86 ms | 7.46x | 7.5x |

### poseidon2-perm

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 573.50 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 1.20 ms | 2.10x | 2.1x |
| `polkavm64_recompiler_sync_gas` | yes | 1.36 ms | 2.38x | 2.4x |
| `polkavm64_recompiler_no_gas` | no | 1.39 ms | 2.42x | 2.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.39 ms | 2.43x | 2.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.40 ms | 2.44x | 2.4x |
| `polkavm64_recompiler_async_gas` | yes | 1.40 ms | 2.45x | 2.4x |
| `wasmtime_cranelift` | no | 1.87 ms | 3.25x | 3.3x |
| `wasmtime_cranelift_fuel` | yes | 1.91 ms | 3.32x | 3.3x |
| `wasmtime_winch` | no | 3.08 ms | 5.37x | 5.4x |
| `wasmer_singlepass` | no | 9.60 ms | 16.74x | 16.7x |
| `polkavm64_interpreter` | no | 21.93 ms | 38.24x | 38.2x |
| `nub_interp` | yes | 35.92 ms | 62.63x | 62.6x |

### prime-sieve

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 59.24 µs | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 77.13 µs | 1.30x | 1.3x |
| `polkavm64_recompiler_no_gas` | no | 89.88 µs | 1.52x | 1.5x |
| `wasmer_singlepass` | no | 127.82 µs | 2.16x | 2.2x |
| `wasmtime_cranelift_fuel` | yes | 146.98 µs | 2.48x | 2.5x |
| `wasmtime_winch` | no | 151.35 µs | 2.55x | 2.6x |
| `polkavm64_recompiler_async_gas` | yes | 190.25 µs | 3.21x | 3.2x |
| `polkavm64_recompiler_async_gas_full` | yes | 190.43 µs | 3.21x | 3.2x |
| `polkavm64_recompiler_sync_gas` | yes | 195.55 µs | 3.30x | 3.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 195.69 µs | 3.30x | 3.3x |
| `nub_jit` | yes | 316.81 µs | 5.35x | 5.3x |
| `polkavm64_interpreter` | no | 2.14 ms | 36.18x | 36.2x |
| `nub_interp` | yes | 7.46 ms | 125.97x | 126.0x |
