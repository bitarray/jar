# nub benchmark comparison

## Compile + execute, metered JIT engines

The bench target: each sample compiles the program and runs it, from cold, with metering on. That is how a metered VM is used when work arrives as a blob — the compile is not amortized away.

Only cost models comparable to nub's appear here. PolkaVM's default `Simple` model is a flat per-instruction cost and is much cheaper to evaluate than nub's pipeline simulation, so the `*_full` rows (`CacheModel::L2Hit`, whose `memory_access_cost: 25` is exactly nub's `MEM_CYCLES_BASE`) are the like-for-like comparison. Full tables for every engine and every measurement kind follow below.

| Program | `nub_jit` | `polkavm64_recompiler_sync_gas_full` | `polkavm64_recompiler_async_gas_full` | `wasmtime_cranelift_fuel` |
|---|--:|--:|--:|--:|
| ecrecover | 2.58 ms (1.25x) | 2.07 ms (1.00x) | **2.06 ms** (1.00x) | 43.73 ms (21.24x) |
| goldilocks-mul | 655.10 µs (1.54x) | **424.78 µs** (1.00x) | 427.01 µs (1.01x) | 1.07 ms (2.51x) |
| blake2b | 272.82 µs (1.50x) | **182.29 µs** (1.00x) | 184.85 µs (1.01x) | 3.36 ms (18.43x) |
| poseidon2-perm | 2.27 ms (1.50x) | 1.52 ms (1.01x) | **1.51 ms** (1.00x) | 4.39 ms (2.90x) |
| ed25519 | 1.23 ms (1.57x) | **780.95 µs** (1.00x) | 783.59 µs (1.00x) | 29.93 ms (38.32x) |
| poly-eval | 1.83 ms (1.41x) | **1.29 ms** (1.00x) | 1.34 ms (1.04x) | 9.95 ms (7.68x) |
| prime-sieve | 964.36 µs (3.52x) | 281.40 µs (1.03x) | **274.16 µs** (1.00x) | 1.15 ms (4.20x) |
| fri-fold-tree | 1.12 ms (1.59x) | 704.15 µs (1.00x) | **702.51 µs** (1.00x) | 12.12 ms (17.25x) |
| keccak | 194.18 µs (2.00x) | 100.74 µs (1.04x) | **97.14 µs** (1.00x) | 2.85 ms (29.38x) |
| mini-verifier | 1.12 ms (1.59x) | **704.52 µs** (1.00x) | 707.00 µs (1.00x) | 3.79 ms (5.37x) |

Bold = fastest for that program; the multiple is versus it.

### Where that time goes

The same rows with **compilation excluded** — a fresh instance per sample, then execute. Every engine pays instantiation here, so this is like-for-like even for nub, which rebuilds its frame on every call and therefore has no warm state to hoist out.

The bracketed figure is the difference against the table above: what compilation costs that engine.

| Program | `nub_jit` | `polkavm64_recompiler_sync_gas_full` | `polkavm64_recompiler_async_gas_full` | `wasmtime_cranelift_fuel` |
|---|--:|--:|--:|--:|
| ecrecover | 597.45 µs (+1.99 ms compile) | 465.23 µs (+1.60 ms compile) | 451.32 µs (+1.61 ms compile) | 269.41 µs (+43.47 ms compile) |
| goldilocks-mul | 474.26 µs (+180.84 µs compile) | 384.97 µs (+39.81 µs compile) | 380.37 µs (+46.64 µs compile) | 516.39 µs (+549.11 µs compile) |
| blake2b | 4.79 µs (+268.03 µs compile) | 7.84 µs (+174.46 µs compile) | 7.59 µs (+177.25 µs compile) | 2.58 µs (+3.36 ms compile) |
| poseidon2-perm | 1.20 ms (+1.07 ms compile) | 1.37 ms (+157.07 µs compile) | 1.41 ms (+108.15 µs compile) | 1.94 ms (+2.45 ms compile) |
| ed25519 | 153.92 µs (+1.08 ms compile) | 100.60 µs (+680.35 µs compile) | 100.77 µs (+682.83 µs compile) | 236.53 µs (+29.69 ms compile) |
| poly-eval | 1.08 ms (+747.31 µs compile) | 1.23 ms (+60.80 µs compile) | 1.28 ms (+62.95 µs compile) | 1.47 ms (+8.47 ms compile) |
| prime-sieve | 261.35 µs (+703.02 µs compile) | 215.84 µs (+65.56 µs compile) | 209.99 µs (+64.18 µs compile) | 165.98 µs (+986.06 µs compile) |
| fri-fold-tree | 470.78 µs (+649.12 µs compile) | 564.95 µs (+139.20 µs compile) | 563.77 µs (+138.73 µs compile) | 777.51 µs (+11.34 ms compile) |
| keccak | 7.31 µs (+186.86 µs compile) | 10.91 µs (+89.83 µs compile) | 11.01 µs (+86.14 µs compile) | 4.56 µs (+2.85 ms compile) |
| mini-verifier | 483.23 µs (+634.45 µs compile) | 581.35 µs (+123.17 µs compile) | 584.15 µs (+122.85 µs compile) | 816.78 µs (+2.97 ms compile) |

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
| `polkavm64_recompiler_async_gas` | yes | 22.55 µs | 1.00x | - |
| `polkavm64_recompiler_sync_gas` | yes | 23.61 µs | 1.05x | - |
| `polkavm64_recompiler_no_gas` | no | 24.08 µs | 1.07x | - |
| `polkavm64_interpreter` | no | 30.99 µs | 1.37x | - |
| `nub_jit_compile` | yes | 83.31 µs | 3.70x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 105.41 µs | 4.68x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 105.66 µs | 4.69x | - |
| `wasmtime_winch` | no | 448.24 µs | 19.88x | - |
| `wasmer_singlepass` | no | 1.08 ms | 48.07x | - |
| `wasmtime_cranelift` | no | 3.24 ms | 143.86x | - |
| `wasmtime_cranelift_fuel` | yes | 3.31 ms | 147.04x | - |

### ecrecover

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 207.15 µs | 1.00x | - |
| `polkavm64_recompiler_async_gas` | yes | 269.90 µs | 1.30x | - |
| `polkavm64_recompiler_no_gas` | no | 270.63 µs | 1.31x | - |
| `polkavm64_recompiler_sync_gas` | yes | 271.79 µs | 1.31x | - |
| `nub_jit_compile` | yes | 721.40 µs | 3.48x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.38 ms | 6.67x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 1.38 ms | 6.68x | - |
| `wasmer_singlepass` | no | 3.33 ms | 16.07x | - |
| `wasmtime_winch` | no | 4.93 ms | 23.81x | - |
| `wasmtime_cranelift` | no | 35.23 ms | 170.08x | - |
| `wasmtime_cranelift_fuel` | yes | 43.76 ms | 211.25x | - |

### ed25519

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 92.38 µs | 1.00x | - |
| `polkavm64_recompiler_async_gas` | yes | 120.18 µs | 1.30x | - |
| `polkavm64_recompiler_sync_gas` | yes | 121.60 µs | 1.32x | - |
| `polkavm64_recompiler_no_gas` | no | 122.88 µs | 1.33x | - |
| `nub_jit_compile` | yes | 336.84 µs | 3.65x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 551.69 µs | 5.97x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 554.82 µs | 6.01x | - |
| `wasmtime_winch` | no | 2.75 ms | 29.75x | - |
| `wasmer_singlepass` | no | 3.90 ms | 42.25x | - |
| `wasmtime_cranelift` | no | 23.98 ms | 259.59x | - |
| `wasmtime_cranelift_fuel` | yes | 29.27 ms | 316.87x | - |

### fri-fold-tree

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_recompiler_async_gas` | yes | 15.06 µs | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 15.61 µs | 1.04x | - |
| `polkavm64_recompiler_sync_gas` | yes | 16.81 µs | 1.12x | - |
| `polkavm64_interpreter` | no | 21.88 µs | 1.45x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 58.64 µs | 3.89x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 60.55 µs | 4.02x | - |
| `nub_jit_compile` | yes | 61.26 µs | 4.07x | - |
| `wasmer_singlepass` | no | 1.48 ms | 98.15x | - |
| `wasmtime_winch` | no | 1.63 ms | 108.03x | - |
| `wasmtime_cranelift` | no | 7.87 ms | 522.42x | - |
| `wasmtime_cranelift_fuel` | yes | 11.20 ms | 743.62x | - |

### goldilocks-mul

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_recompiler_async_gas` | yes | 3.65 µs | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 3.82 µs | 1.05x | - |
| `polkavm64_recompiler_sync_gas` | yes | 3.87 µs | 1.06x | - |
| `polkavm64_interpreter` | no | 4.84 µs | 1.33x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 5.30 µs | 1.45x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 5.30 µs | 1.45x | - |
| `nub_jit_compile` | yes | 7.81 µs | 2.14x | - |
| `wasmtime_winch` | no | 229.94 µs | 63.00x | - |
| `wasmtime_cranelift` | no | 402.90 µs | 110.38x | - |
| `wasmtime_cranelift_fuel` | yes | 530.90 µs | 145.45x | - |
| `wasmer_singlepass` | no | 815.62 µs | 223.46x | - |

### keccak

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 9.39 µs | 1.00x | - |
| `polkavm64_recompiler_async_gas` | yes | 10.52 µs | 1.12x | - |
| `polkavm64_recompiler_no_gas` | no | 10.56 µs | 1.13x | - |
| `polkavm64_recompiler_sync_gas` | yes | 10.60 µs | 1.13x | - |
| `nub_jit_compile` | yes | 13.08 µs | 1.39x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 37.32 µs | 3.97x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 37.38 µs | 3.98x | - |
| `wasmtime_winch` | no | 774.12 µs | 82.44x | - |
| `wasmer_singlepass` | no | 950.23 µs | 101.20x | - |
| `wasmtime_cranelift` | no | 2.17 ms | 230.59x | - |
| `wasmtime_cranelift_fuel` | yes | 2.81 ms | 299.09x | - |

### mini-verifier

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 11.97 µs | 1.00x | - |
| `polkavm64_recompiler_sync_gas` | yes | 13.38 µs | 1.12x | - |
| `polkavm64_recompiler_async_gas` | yes | 13.56 µs | 1.13x | - |
| `polkavm64_recompiler_no_gas` | no | 15.39 µs | 1.29x | - |
| `nub_jit_compile` | yes | 28.23 µs | 2.36x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 55.38 µs | 4.63x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 56.23 µs | 4.70x | - |
| `wasmtime_winch` | no | 561.32 µs | 46.90x | - |
| `wasmer_singlepass` | no | 1.04 ms | 86.68x | - |
| `wasmtime_cranelift` | no | 2.36 ms | 197.18x | - |
| `wasmtime_cranelift_fuel` | yes | 2.88 ms | 240.92x | - |

### poly-eval

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 4.05 µs | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 5.50 µs | 1.36x | - |
| `polkavm64_recompiler_async_gas` | yes | 5.65 µs | 1.40x | - |
| `polkavm64_recompiler_sync_gas` | yes | 5.71 µs | 1.41x | - |
| `nub_jit_compile` | yes | 8.99 µs | 2.22x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 13.75 µs | 3.40x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 14.57 µs | 3.60x | - |
| `wasmtime_winch` | no | 1.30 ms | 321.47x | - |
| `wasmer_singlepass` | no | 1.43 ms | 354.63x | - |
| `wasmtime_cranelift` | no | 5.28 ms | 1305.38x | - |
| `wasmtime_cranelift_fuel` | yes | 8.28 ms | 2046.12x | - |

### poseidon2-perm

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 10.17 µs | 1.00x | - |
| `polkavm64_recompiler_async_gas` | yes | 10.23 µs | 1.01x | - |
| `polkavm64_recompiler_sync_gas` | yes | 11.46 µs | 1.13x | - |
| `polkavm64_recompiler_no_gas` | no | 23.36 µs | 2.30x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 41.27 µs | 4.06x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 41.98 µs | 4.13x | - |
| `nub_jit_compile` | yes | 44.32 µs | 4.36x | - |
| `wasmtime_winch` | no | 502.14 µs | 49.36x | - |
| `wasmer_singlepass` | no | 1.03 ms | 101.10x | - |
| `wasmtime_cranelift` | no | 1.96 ms | 192.43x | - |
| `wasmtime_cranelift_fuel` | yes | 2.40 ms | 235.99x | - |

### prime-sieve

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 4.25 µs | 1.00x | - |
| `polkavm64_recompiler_async_gas` | yes | 6.90 µs | 1.62x | - |
| `polkavm64_recompiler_sync_gas` | yes | 6.96 µs | 1.64x | - |
| `polkavm64_recompiler_no_gas` | no | 7.26 µs | 1.71x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 9.23 µs | 2.17x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 9.27 µs | 2.18x | - |
| `nub_jit_compile` | yes | 11.35 µs | 2.67x | - |
| `wasmtime_winch` | no | 346.98 µs | 81.58x | - |
| `wasmtime_cranelift` | no | 521.56 µs | 122.63x | - |
| `wasmer_singlepass` | no | 698.07 µs | 164.14x | - |
| `wasmtime_cranelift_fuel` | yes | 839.88 µs | 197.48x | - |

## invoke

Cold invocation with compilation excluded: a fresh instance every sample. Where an engine's *instantiation* strategy shows up. Compare against `runtime` for the same row to see what a cold start costs it.

### blake2b

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 693.0 ns | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 2.57 µs | 3.71x | 3.7x |
| `wasmtime_cranelift_fuel` | yes | 2.58 µs | 3.72x | 3.7x |
| `wasmtime_winch` | no | 3.21 µs | 4.63x | 4.6x |
| `nub_jit` | yes | 4.79 µs | 6.92x | 6.9x |
| `polkavm64_recompiler_no_gas` | no | 7.24 µs | 10.45x | 10.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 7.59 µs | 10.96x | 11.0x |
| `polkavm64_recompiler_sync_gas_full` | yes | 7.84 µs | 11.31x | 11.3x |
| `polkavm64_recompiler_async_gas` | yes | 7.93 µs | 11.45x | 11.4x |
| `polkavm64_recompiler_sync_gas` | yes | 8.37 µs | 12.08x | 12.1x |
| `wasmer_singlepass` | no | 11.98 µs | 17.29x | 17.3x |
| `polkavm64_interpreter` | no | 101.12 µs | 145.92x | 145.9x |
| `nub_interp` | yes | 161.80 µs | 233.48x | 233.5x |

### ecrecover

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 101.18 µs | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 264.77 µs | 2.62x | 2.6x |
| `wasmtime_cranelift_fuel` | yes | 269.41 µs | 2.66x | 2.7x |
| `wasmtime_winch` | no | 383.56 µs | 3.79x | 3.8x |
| `polkavm64_recompiler_no_gas` | no | 410.35 µs | 4.06x | 4.1x |
| `polkavm64_recompiler_async_gas` | yes | 448.59 µs | 4.43x | 4.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 451.32 µs | 4.46x | 4.5x |
| `polkavm64_recompiler_sync_gas` | yes | 464.07 µs | 4.59x | 4.6x |
| `polkavm64_recompiler_sync_gas_full` | yes | 465.23 µs | 4.60x | 4.6x |
| `nub_jit` | yes | 597.45 µs | 5.90x | 5.9x |
| `wasmer_singlepass` | no | 1.35 ms | 13.35x | 13.4x |
| `polkavm64_interpreter` | no | 12.15 ms | 120.05x | 120.0x |
| `nub_interp` | yes | 27.40 ms | 270.80x | 270.8x |

### ed25519

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 32.14 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 90.10 µs | 2.80x | 2.8x |
| `polkavm64_recompiler_async_gas` | yes | 100.22 µs | 3.12x | 3.1x |
| `polkavm64_recompiler_sync_gas_full` | yes | 100.60 µs | 3.13x | 3.1x |
| `polkavm64_recompiler_async_gas_full` | yes | 100.77 µs | 3.14x | 3.1x |
| `polkavm64_recompiler_sync_gas` | yes | 100.84 µs | 3.14x | 3.1x |
| `nub_jit` | yes | 153.92 µs | 4.79x | 4.8x |
| `wasmtime_cranelift` | no | 200.75 µs | 6.25x | 6.2x |
| `wasmtime_cranelift_fuel` | yes | 236.53 µs | 7.36x | 7.4x |
| `wasmtime_winch` | no | 341.06 µs | 10.61x | 10.6x |
| `wasmer_singlepass` | no | 1.39 ms | 43.28x | 43.3x |
| `polkavm64_interpreter` | no | 1.67 ms | 52.11x | 52.1x |
| `nub_interp` | yes | 5.23 ms | 162.88x | 162.9x |

### fri-fold-tree

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 235.74 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 470.78 µs | 2.00x | 2.0x |
| `polkavm64_recompiler_async_gas_full` | yes | 563.77 µs | 2.39x | 2.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 564.95 µs | 2.40x | 2.4x |
| `polkavm64_recompiler_async_gas` | yes | 565.05 µs | 2.40x | 2.4x |
| `polkavm64_recompiler_no_gas` | no | 566.71 µs | 2.40x | 2.4x |
| `polkavm64_recompiler_sync_gas` | yes | 566.90 µs | 2.40x | 2.4x |
| `wasmtime_cranelift` | no | 764.35 µs | 3.24x | 3.2x |
| `wasmtime_cranelift_fuel` | yes | 777.51 µs | 3.30x | 3.3x |
| `wasmtime_winch` | no | 1.28 ms | 5.43x | 5.4x |
| `wasmer_singlepass` | no | 5.31 ms | 22.54x | 22.5x |
| `polkavm64_interpreter` | no | 9.45 ms | 40.09x | 40.1x |
| `nub_interp` | yes | 13.85 ms | 58.74x | 58.7x |

### goldilocks-mul

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_recompiler_no_gas` | no | 334.10 µs | 1.00x | 0.9x |
| `native` | no | 355.59 µs | 1.06x | 1.0x |
| `polkavm64_recompiler_async_gas_full` | yes | 380.37 µs | 1.14x | 1.1x |
| `polkavm64_recompiler_sync_gas` | yes | 381.14 µs | 1.14x | 1.1x |
| `polkavm64_recompiler_async_gas` | yes | 384.24 µs | 1.15x | 1.1x |
| `polkavm64_recompiler_sync_gas_full` | yes | 384.97 µs | 1.15x | 1.1x |
| `nub_jit` | yes | 474.26 µs | 1.42x | 1.3x |
| `wasmtime_cranelift_fuel` | yes | 516.39 µs | 1.55x | 1.5x |
| `wasmtime_cranelift` | no | 534.78 µs | 1.60x | 1.5x |
| `wasmtime_winch` | no | 536.62 µs | 1.61x | 1.5x |
| `wasmer_singlepass` | no | 1.59 ms | 4.77x | 4.5x |
| `polkavm64_interpreter` | no | 2.12 ms | 6.36x | 6.0x |
| `nub_interp` | yes | 4.09 ms | 12.23x | 11.5x |

### keccak

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 1.79 µs | 1.00x | 1.0x |
| `wasmtime_cranelift_fuel` | yes | 4.56 µs | 2.54x | 2.5x |
| `wasmtime_cranelift` | no | 4.60 µs | 2.56x | 2.6x |
| `wasmtime_winch` | no | 4.92 µs | 2.74x | 2.7x |
| `wasmer_singlepass` | no | 5.75 µs | 3.21x | 3.2x |
| `nub_jit` | yes | 7.31 µs | 4.07x | 4.1x |
| `polkavm64_recompiler_no_gas` | no | 10.26 µs | 5.71x | 5.7x |
| `polkavm64_recompiler_async_gas` | yes | 10.56 µs | 5.88x | 5.9x |
| `polkavm64_recompiler_sync_gas` | yes | 10.85 µs | 6.04x | 6.0x |
| `polkavm64_recompiler_sync_gas_full` | yes | 10.91 µs | 6.08x | 6.1x |
| `polkavm64_recompiler_async_gas_full` | yes | 11.01 µs | 6.13x | 6.1x |
| `polkavm64_interpreter` | no | 99.16 µs | 55.24x | 55.2x |
| `nub_interp` | yes | 254.90 µs | 142.00x | 142.0x |

### mini-verifier

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 247.95 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 483.23 µs | 1.95x | 1.9x |
| `polkavm64_recompiler_async_gas` | yes | 578.34 µs | 2.33x | 2.3x |
| `polkavm64_recompiler_no_gas` | no | 578.79 µs | 2.33x | 2.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 581.35 µs | 2.34x | 2.3x |
| `polkavm64_recompiler_async_gas_full` | yes | 584.15 µs | 2.36x | 2.4x |
| `polkavm64_recompiler_sync_gas` | yes | 591.56 µs | 2.39x | 2.4x |
| `wasmtime_cranelift` | no | 784.71 µs | 3.16x | 3.2x |
| `wasmtime_cranelift_fuel` | yes | 816.78 µs | 3.29x | 3.3x |
| `wasmtime_winch` | no | 1.33 ms | 5.36x | 5.4x |
| `wasmer_singlepass` | no | 4.33 ms | 17.48x | 17.5x |
| `polkavm64_interpreter` | no | 9.86 ms | 39.77x | 39.8x |
| `nub_interp` | yes | 14.70 ms | 59.28x | 59.3x |

### poly-eval

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 712.55 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 1.08 ms | 1.52x | 1.5x |
| `polkavm64_recompiler_no_gas` | no | 1.21 ms | 1.69x | 1.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.23 ms | 1.73x | 1.7x |
| `polkavm64_recompiler_sync_gas` | yes | 1.23 ms | 1.73x | 1.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.28 ms | 1.80x | 1.8x |
| `polkavm64_recompiler_async_gas` | yes | 1.28 ms | 1.80x | 1.8x |
| `wasmtime_cranelift_fuel` | yes | 1.47 ms | 2.07x | 2.1x |
| `wasmtime_cranelift` | no | 1.57 ms | 2.20x | 2.2x |
| `wasmtime_winch` | no | 1.65 ms | 2.32x | 2.3x |
| `wasmer_singlepass` | no | 5.74 ms | 8.06x | 8.1x |
| `polkavm64_interpreter` | no | 8.04 ms | 11.28x | 11.3x |
| `nub_interp` | yes | 17.30 ms | 24.28x | 24.3x |

### poseidon2-perm

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 603.97 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 1.20 ms | 1.99x | 2.0x |
| `polkavm64_recompiler_no_gas` | no | 1.34 ms | 2.22x | 2.2x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.37 ms | 2.26x | 2.3x |
| `polkavm64_recompiler_async_gas` | yes | 1.40 ms | 2.31x | 2.3x |
| `polkavm64_recompiler_sync_gas` | yes | 1.40 ms | 2.31x | 2.3x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.41 ms | 2.33x | 2.3x |
| `wasmtime_cranelift` | no | 1.93 ms | 3.20x | 3.2x |
| `wasmtime_cranelift_fuel` | yes | 1.94 ms | 3.22x | 3.2x |
| `wasmtime_winch` | no | 3.02 ms | 4.99x | 5.0x |
| `wasmer_singlepass` | no | 10.61 ms | 17.57x | 17.6x |
| `polkavm64_interpreter` | no | 22.46 ms | 37.19x | 37.2x |
| `nub_interp` | yes | 36.66 ms | 60.70x | 60.7x |

### prime-sieve

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 54.36 µs | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 95.83 µs | 1.76x | 1.8x |
| `polkavm64_recompiler_no_gas` | no | 119.34 µs | 2.20x | 2.2x |
| `wasmer_singlepass` | no | 131.88 µs | 2.43x | 2.4x |
| `wasmtime_cranelift_fuel` | yes | 165.98 µs | 3.05x | 3.1x |
| `wasmtime_winch` | no | 168.83 µs | 3.11x | 3.1x |
| `polkavm64_recompiler_async_gas` | yes | 209.73 µs | 3.86x | 3.9x |
| `polkavm64_recompiler_async_gas_full` | yes | 209.99 µs | 3.86x | 3.9x |
| `polkavm64_recompiler_sync_gas_full` | yes | 215.84 µs | 3.97x | 4.0x |
| `polkavm64_recompiler_sync_gas` | yes | 219.84 µs | 4.04x | 4.0x |
| `nub_jit` | yes | 261.35 µs | 4.81x | 4.8x |
| `polkavm64_interpreter` | no | 2.11 ms | 38.77x | 38.8x |
| `nub_interp` | yes | 7.27 ms | 133.72x | 133.7x |

## oneshot

Compile **and** execute, from cold, every sample. The metric that matches how a metered VM is actually used: work arrives as a blob that must be compiled and then run, and each iteration pays both. Engines that cache compilation internally are evicted first, so no row skips the compile half.

### blake2b

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 13.54 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_async_gas` | yes | 79.06 µs | 5.84x | 5.8x |
| `polkavm64_recompiler_no_gas` | no | 79.27 µs | 5.86x | 5.9x |
| `polkavm64_recompiler_sync_gas` | yes | 79.44 µs | 5.87x | 5.9x |
| `polkavm64_interpreter` | no | 126.09 µs | 9.31x | 9.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 182.29 µs | 13.46x | 13.5x |
| `polkavm64_recompiler_async_gas_full` | yes | 184.85 µs | 13.65x | 13.7x |
| `nub_interp` | yes | 218.23 µs | 16.12x | 16.1x |
| `nub_jit` | yes | 272.82 µs | 20.15x | 20.2x |
| `wasmtime_winch` | no | 475.03 µs | 35.09x | 35.1x |
| `wasmer_singlepass` | no | 2.29 ms | 168.80x | 168.8x |
| `wasmtime_cranelift` | no | 3.25 ms | 240.31x | 240.3x |
| `wasmtime_cranelift_fuel` | yes | 3.36 ms | 248.09x | 248.1x |

### ecrecover

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 118.08 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 887.85 µs | 7.52x | 7.5x |
| `polkavm64_recompiler_async_gas` | yes | 933.25 µs | 7.90x | 7.9x |
| `polkavm64_recompiler_sync_gas` | yes | 946.61 µs | 8.02x | 8.0x |
| `polkavm64_recompiler_async_gas_full` | yes | 2.06 ms | 17.44x | 17.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 2.07 ms | 17.50x | 17.5x |
| `nub_jit` | yes | 2.58 ms | 21.88x | 21.9x |
| `wasmtime_winch` | no | 5.30 ms | 44.90x | 44.9x |
| `wasmer_singlepass` | no | 7.85 ms | 66.45x | 66.5x |
| `polkavm64_interpreter` | no | 12.36 ms | 104.66x | 104.7x |
| `nub_interp` | yes | 27.32 ms | 231.39x | 231.4x |
| `wasmtime_cranelift` | no | 35.59 ms | 301.42x | 301.4x |
| `wasmtime_cranelift_fuel` | yes | 43.73 ms | 370.37x | 370.4x |

### ed25519

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 47.19 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 312.02 µs | 6.61x | 6.6x |
| `polkavm64_recompiler_async_gas` | yes | 320.77 µs | 6.80x | 6.8x |
| `polkavm64_recompiler_sync_gas` | yes | 323.38 µs | 6.85x | 6.9x |
| `polkavm64_recompiler_sync_gas_full` | yes | 780.95 µs | 16.55x | 16.5x |
| `polkavm64_recompiler_async_gas_full` | yes | 783.59 µs | 16.61x | 16.6x |
| `nub_jit` | yes | 1.23 ms | 26.05x | 26.1x |
| `polkavm64_interpreter` | no | 1.77 ms | 37.58x | 37.6x |
| `wasmtime_winch` | no | 3.27 ms | 69.20x | 69.2x |
| `nub_interp` | yes | 5.53 ms | 117.28x | 117.3x |
| `wasmer_singlepass` | no | 8.62 ms | 182.74x | 182.7x |
| `wasmtime_cranelift` | no | 24.40 ms | 517.04x | 517.0x |
| `wasmtime_cranelift_fuel` | yes | 29.93 ms | 634.23x | 634.2x |

### fri-fold-tree

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 251.03 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 638.87 µs | 2.54x | 2.5x |
| `polkavm64_recompiler_async_gas` | yes | 645.92 µs | 2.57x | 2.6x |
| `polkavm64_recompiler_sync_gas` | yes | 647.87 µs | 2.58x | 2.6x |
| `polkavm64_recompiler_async_gas_full` | yes | 702.51 µs | 2.80x | 2.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 704.15 µs | 2.81x | 2.8x |
| `nub_jit` | yes | 1.12 ms | 4.46x | 4.5x |
| `wasmtime_winch` | no | 2.97 ms | 11.84x | 11.8x |
| `wasmer_singlepass` | no | 7.92 ms | 31.54x | 31.5x |
| `wasmtime_cranelift` | no | 8.71 ms | 34.70x | 34.7x |
| `polkavm64_interpreter` | no | 9.38 ms | 37.36x | 37.4x |
| `wasmtime_cranelift_fuel` | yes | 12.12 ms | 48.27x | 48.3x |
| `nub_interp` | yes | 13.85 ms | 55.16x | 55.2x |

### goldilocks-mul

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 227.05 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 386.55 µs | 1.70x | 1.7x |
| `polkavm64_recompiler_async_gas` | yes | 422.41 µs | 1.86x | 1.9x |
| `polkavm64_recompiler_sync_gas_full` | yes | 424.78 µs | 1.87x | 1.9x |
| `polkavm64_recompiler_sync_gas` | yes | 424.93 µs | 1.87x | 1.9x |
| `polkavm64_recompiler_async_gas_full` | yes | 427.01 µs | 1.88x | 1.9x |
| `nub_jit` | yes | 655.10 µs | 2.89x | 2.9x |
| `wasmtime_winch` | no | 788.87 µs | 3.47x | 3.5x |
| `wasmtime_cranelift` | no | 949.12 µs | 4.18x | 4.2x |
| `wasmtime_cranelift_fuel` | yes | 1.07 ms | 4.69x | 4.7x |
| `polkavm64_interpreter` | no | 2.14 ms | 9.41x | 9.4x |
| `wasmer_singlepass` | no | 2.92 ms | 12.85x | 12.8x |
| `nub_interp` | yes | 4.12 ms | 18.13x | 18.1x |

### keccak

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 30.55 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_sync_gas` | yes | 61.21 µs | 2.00x | 2.0x |
| `polkavm64_recompiler_no_gas` | no | 62.53 µs | 2.05x | 2.0x |
| `polkavm64_recompiler_async_gas` | yes | 62.74 µs | 2.05x | 2.1x |
| `polkavm64_recompiler_async_gas_full` | yes | 97.14 µs | 3.18x | 3.2x |
| `polkavm64_recompiler_sync_gas_full` | yes | 100.74 µs | 3.30x | 3.3x |
| `polkavm64_interpreter` | no | 112.54 µs | 3.68x | 3.7x |
| `nub_jit` | yes | 194.18 µs | 6.36x | 6.4x |
| `nub_interp` | yes | 569.83 µs | 18.65x | 18.7x |
| `wasmtime_winch` | no | 797.28 µs | 26.10x | 26.1x |
| `wasmer_singlepass` | no | 1.77 ms | 57.80x | 57.8x |
| `wasmtime_cranelift` | no | 2.19 ms | 71.77x | 71.8x |
| `wasmtime_cranelift_fuel` | yes | 2.85 ms | 93.43x | 93.4x |

### mini-verifier

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 260.74 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 648.00 µs | 2.49x | 2.5x |
| `polkavm64_recompiler_async_gas` | yes | 649.67 µs | 2.49x | 2.5x |
| `polkavm64_recompiler_sync_gas` | yes | 650.08 µs | 2.49x | 2.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 704.52 µs | 2.70x | 2.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 707.00 µs | 2.71x | 2.7x |
| `nub_jit` | yes | 1.12 ms | 4.29x | 4.3x |
| `wasmtime_winch` | no | 1.94 ms | 7.44x | 7.4x |
| `wasmtime_cranelift` | no | 3.19 ms | 12.24x | 12.2x |
| `wasmtime_cranelift_fuel` | yes | 3.79 ms | 14.52x | 14.5x |
| `wasmer_singlepass` | no | 6.31 ms | 24.19x | 24.2x |
| `polkavm64_interpreter` | no | 9.85 ms | 37.76x | 37.8x |
| `nub_interp` | yes | 14.32 ms | 54.93x | 54.9x |

### poly-eval

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 719.84 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 1.26 ms | 1.75x | 1.7x |
| `polkavm64_recompiler_sync_gas` | yes | 1.28 ms | 1.78x | 1.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.29 ms | 1.80x | 1.8x |
| `polkavm64_recompiler_async_gas` | yes | 1.33 ms | 1.85x | 1.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.34 ms | 1.87x | 1.9x |
| `nub_jit` | yes | 1.83 ms | 2.54x | 2.5x |
| `wasmtime_winch` | no | 3.10 ms | 4.31x | 4.3x |
| `wasmtime_cranelift` | no | 7.04 ms | 9.78x | 9.8x |
| `polkavm64_interpreter` | no | 8.30 ms | 11.52x | 11.5x |
| `wasmer_singlepass` | no | 8.87 ms | 12.32x | 12.3x |
| `wasmtime_cranelift_fuel` | yes | 9.95 ms | 13.82x | 13.8x |
| `nub_interp` | yes | 17.86 ms | 24.81x | 24.8x |

### poseidon2-perm

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 624.73 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 1.46 ms | 2.34x | 2.3x |
| `polkavm64_recompiler_async_gas` | yes | 1.48 ms | 2.37x | 2.4x |
| `polkavm64_recompiler_sync_gas` | yes | 1.48 ms | 2.37x | 2.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.51 ms | 2.42x | 2.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.52 ms | 2.44x | 2.4x |
| `nub_jit` | yes | 2.27 ms | 3.64x | 3.6x |
| `wasmtime_winch` | no | 3.53 ms | 5.66x | 5.7x |
| `wasmtime_cranelift` | no | 3.94 ms | 6.30x | 6.3x |
| `wasmtime_cranelift_fuel` | yes | 4.39 ms | 7.03x | 7.0x |
| `wasmer_singlepass` | no | 12.48 ms | 19.98x | 20.0x |
| `polkavm64_interpreter` | no | 22.53 ms | 36.06x | 36.1x |
| `nub_interp` | yes | 36.65 ms | 58.66x | 58.7x |

### prime-sieve

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 158.37 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 174.32 µs | 1.10x | 1.1x |
| `polkavm64_recompiler_sync_gas` | yes | 270.32 µs | 1.71x | 1.7x |
| `polkavm64_recompiler_async_gas` | yes | 272.25 µs | 1.72x | 1.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 274.16 µs | 1.73x | 1.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 281.40 µs | 1.78x | 1.8x |
| `wasmtime_cranelift` | no | 675.15 µs | 4.26x | 4.3x |
| `wasmtime_winch` | no | 688.13 µs | 4.35x | 4.3x |
| `nub_jit` | yes | 964.36 µs | 6.09x | 6.1x |
| `wasmtime_cranelift_fuel` | yes | 1.15 ms | 7.27x | 7.3x |
| `wasmer_singlepass` | no | 1.62 ms | 10.20x | 10.2x |
| `polkavm64_interpreter` | no | 2.15 ms | 13.60x | 13.6x |
| `nub_interp` | yes | 7.56 ms | 47.74x | 47.7x |

## runtime

Steady-state execution: one instance, invoked repeatedly. How fast the engine *executes*, with instantiation excluded.

Rows are absent where a program cannot be re-run in one instance (the three guests with a never-freeing bump arena).

**† — this row still contains per-invocation setup.** nub's invocation model builds a fresh frame and address space on every call by design, so there is no warm state to hoist out. Its figure is therefore *not* comparable to a row that reuses one warm instance; compare it against those rows' `invoke` figures instead, which also pay instantiation.

### blake2b

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 690.0 ns | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 794.0 ns | 1.15x | 1.2x |
| `wasmtime_cranelift_fuel` | yes | 823.0 ns | 1.19x | 1.2x |
| `wasmtime_winch` | no | 1.27 µs | 1.84x | 1.8x |
| `polkavm64_recompiler_no_gas` | no | 2.18 µs | 3.16x | 3.2x |
| `polkavm64_recompiler_sync_gas` | yes | 2.45 µs | 3.55x | 3.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 2.46 µs | 3.56x | 3.6x |
| `polkavm64_recompiler_async_gas` | yes | 2.53 µs | 3.67x | 3.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 2.54 µs | 3.69x | 3.7x |
| `wasmer_singlepass` | no | 5.04 µs | 7.30x | 7.3x |
| `nub_jit` † | yes | 8.11 µs | 11.75x | 11.8x |
| `polkavm64_interpreter` | no | 42.84 µs | 62.09x | 62.1x |
| `nub_interp` | yes | 159.06 µs | 230.52x | 230.5x |

### ecrecover

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 101.17 µs | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 248.86 µs | 2.46x | 2.5x |
| `wasmtime_cranelift_fuel` | yes | 254.90 µs | 2.52x | 2.5x |
| `wasmtime_winch` | no | 377.61 µs | 3.73x | 3.7x |
| `polkavm64_recompiler_no_gas` | no | 396.59 µs | 3.92x | 3.9x |
| `polkavm64_recompiler_async_gas_full` | yes | 436.32 µs | 4.31x | 4.3x |
| `polkavm64_recompiler_async_gas` | yes | 437.94 µs | 4.33x | 4.3x |
| `polkavm64_recompiler_sync_gas` | yes | 445.70 µs | 4.41x | 4.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 450.81 µs | 4.46x | 4.5x |
| `nub_jit` † | yes | 598.04 µs | 5.91x | 5.9x |
| `wasmer_singlepass` | no | 809.31 µs | 8.00x | 8.0x |
| `polkavm64_interpreter` | no | 11.74 ms | 116.06x | 116.1x |
| `nub_interp` | yes | 26.37 ms | 260.62x | 260.6x |

### ed25519

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 33.47 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 79.71 µs | 2.38x | 2.4x |
| `polkavm64_recompiler_async_gas` | yes | 90.82 µs | 2.71x | 2.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 91.34 µs | 2.73x | 2.7x |
| `polkavm64_recompiler_sync_gas` | yes | 91.36 µs | 2.73x | 2.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 91.42 µs | 2.73x | 2.7x |
| `nub_jit` † | yes | 97.27 µs | 2.91x | 2.9x |
| `wasmtime_cranelift` | no | 197.86 µs | 5.91x | 5.9x |
| `wasmtime_cranelift_fuel` | yes | 263.60 µs | 7.88x | 7.9x |
| `wasmtime_winch` | no | 347.24 µs | 10.38x | 10.4x |
| `wasmer_singlepass` | no | 966.49 µs | 28.88x | 28.9x |
| `polkavm64_interpreter` | no | 1.46 ms | 43.49x | 43.5x |
| `nub_interp` | yes | 5.05 ms | 150.82x | 150.8x |

### fri-fold-tree

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 226.49 µs | 1.00x | 1.0x |
| `nub_jit` † | yes | 469.08 µs | 2.07x | 2.1x |
| `wasmtime_cranelift` | no | 750.89 µs | 3.32x | 3.3x |
| `wasmtime_cranelift_fuel` | yes | 753.75 µs | 3.33x | 3.3x |
| `wasmtime_winch` | no | 1.28 ms | 5.66x | 5.7x |
| `wasmer_singlepass` | no | 3.64 ms | 16.08x | 16.1x |

### goldilocks-mul

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 202.32 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 346.80 µs | 1.71x | 1.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 366.71 µs | 1.81x | 1.8x |
| `polkavm64_recompiler_async_gas` | yes | 383.16 µs | 1.89x | 1.9x |
| `polkavm64_recompiler_sync_gas_full` | yes | 383.17 µs | 1.89x | 1.9x |
| `polkavm64_recompiler_sync_gas` | yes | 383.42 µs | 1.90x | 1.9x |
| `nub_jit` † | yes | 474.02 µs | 2.34x | 2.3x |
| `wasmtime_cranelift_fuel` | yes | 499.80 µs | 2.47x | 2.5x |
| `wasmtime_winch` | no | 505.67 µs | 2.50x | 2.5x |
| `wasmtime_cranelift` | no | 529.49 µs | 2.62x | 2.6x |
| `wasmer_singlepass` | no | 1.47 ms | 7.27x | 7.3x |
| `polkavm64_interpreter` | no | 2.14 ms | 10.57x | 10.6x |
| `nub_interp` | yes | 4.11 ms | 20.33x | 20.3x |

### keccak

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 1.67 µs | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 2.14 µs | 1.28x | 1.3x |
| `wasmtime_cranelift_fuel` | yes | 2.35 µs | 1.41x | 1.4x |
| `wasmtime_winch` | no | 2.62 µs | 1.57x | 1.6x |
| `polkavm64_recompiler_no_gas` | no | 3.15 µs | 1.89x | 1.9x |
| `wasmer_singlepass` | no | 3.72 µs | 2.23x | 2.2x |
| `polkavm64_recompiler_async_gas_full` | yes | 3.91 µs | 2.35x | 2.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 3.93 µs | 2.36x | 2.4x |
| `polkavm64_recompiler_sync_gas` | yes | 3.94 µs | 2.36x | 2.4x |
| `polkavm64_recompiler_async_gas` | yes | 3.95 µs | 2.37x | 2.4x |
| `nub_jit` † | yes | 6.88 µs | 4.13x | 4.1x |
| `polkavm64_interpreter` | no | 72.26 µs | 43.32x | 43.3x |
| `nub_interp` | yes | 238.19 µs | 142.80x | 142.8x |

### mini-verifier

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 222.35 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 550.83 µs | 2.48x | 2.5x |
| `polkavm64_recompiler_async_gas` | yes | 555.69 µs | 2.50x | 2.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 570.92 µs | 2.57x | 2.6x |
| `polkavm64_recompiler_sync_gas` | yes | 576.01 µs | 2.59x | 2.6x |
| `polkavm64_recompiler_async_gas_full` | yes | 576.29 µs | 2.59x | 2.6x |
| `wasmtime_cranelift` | no | 778.14 µs | 3.50x | 3.5x |
| `wasmtime_cranelift_fuel` | yes | 784.86 µs | 3.53x | 3.5x |
| `nub_jit` † | yes | 846.79 µs | 3.81x | 3.8x |
| `wasmtime_winch` | no | 1.29 ms | 5.80x | 5.8x |
| `wasmer_singlepass` | no | 3.95 ms | 17.79x | 17.8x |
| `polkavm64_interpreter` | no | 9.83 ms | 44.21x | 44.2x |
| `nub_interp` | yes | 14.40 ms | 64.75x | 64.8x |

### poly-eval

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 673.44 µs | 1.00x | 1.0x |
| `nub_jit` † | yes | 1.13 ms | 1.67x | 1.7x |
| `wasmtime_cranelift_fuel` | yes | 1.45 ms | 2.15x | 2.1x |
| `wasmtime_cranelift` | no | 1.53 ms | 2.27x | 2.3x |
| `wasmtime_winch` | no | 1.64 ms | 2.44x | 2.4x |
| `wasmer_singlepass` | no | 5.00 ms | 7.43x | 7.4x |

### poseidon2-perm

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 549.25 µs | 1.00x | 1.0x |
| `nub_jit` † | yes | 1.16 ms | 2.11x | 2.1x |
| `polkavm64_recompiler_async_gas` | yes | 1.35 ms | 2.45x | 2.5x |
| `polkavm64_recompiler_no_gas` | no | 1.35 ms | 2.46x | 2.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.38 ms | 2.51x | 2.5x |
| `polkavm64_recompiler_sync_gas` | yes | 1.39 ms | 2.53x | 2.5x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.39 ms | 2.53x | 2.5x |
| `wasmtime_cranelift` | no | 1.91 ms | 3.48x | 3.5x |
| `wasmtime_cranelift_fuel` | yes | 1.92 ms | 3.49x | 3.5x |
| `wasmtime_winch` | no | 2.99 ms | 5.45x | 5.5x |
| `wasmer_singlepass` | no | 9.62 ms | 17.51x | 17.5x |
| `polkavm64_interpreter` | no | 22.54 ms | 41.04x | 41.0x |
| `nub_interp` | yes | 36.62 ms | 66.67x | 66.7x |

### prime-sieve

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 57.29 µs | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 77.17 µs | 1.35x | 1.3x |
| `polkavm64_recompiler_no_gas` | no | 89.95 µs | 1.57x | 1.6x |
| `wasmer_singlepass` | no | 129.99 µs | 2.27x | 2.3x |
| `wasmtime_cranelift_fuel` | yes | 146.49 µs | 2.56x | 2.6x |
| `wasmtime_winch` | no | 152.28 µs | 2.66x | 2.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 190.25 µs | 3.32x | 3.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 190.66 µs | 3.33x | 3.3x |
| `polkavm64_recompiler_async_gas` | yes | 190.98 µs | 3.33x | 3.3x |
| `polkavm64_recompiler_sync_gas` | yes | 195.67 µs | 3.42x | 3.4x |
| `nub_jit` † | yes | 284.01 µs | 4.96x | 5.0x |
| `polkavm64_interpreter` | no | 2.13 ms | 37.21x | 37.2x |
| `nub_interp` | yes | 7.47 ms | 130.39x | 130.4x |
