# nub benchmark comparison

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
| `polkavm64_interpreter` | no | 20.59 µs | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 21.93 µs | 1.07x | - |
| `polkavm64_recompiler_sync_gas` | yes | 22.99 µs | 1.12x | - |
| `polkavm64_recompiler_async_gas` | yes | 23.35 µs | 1.13x | - |
| `nub_jit_compile` | yes | 44.11 µs | 2.14x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 110.31 µs | 5.36x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 112.77 µs | 5.48x | - |
| `wasmtime_winch` | no | 453.72 µs | 22.03x | - |
| `wasmer_singlepass` | no | 1.13 ms | 54.86x | - |
| `wasmtime_cranelift` | no | 3.22 ms | 156.39x | - |
| `wasmtime_cranelift_fuel` | yes | 3.33 ms | 161.57x | - |

### ecrecover

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 204.25 µs | 1.00x | - |
| `polkavm64_recompiler_async_gas` | yes | 267.98 µs | 1.31x | - |
| `polkavm64_recompiler_no_gas` | no | 268.71 µs | 1.32x | - |
| `polkavm64_recompiler_sync_gas` | yes | 272.18 µs | 1.33x | - |
| `nub_jit_compile` | yes | 727.09 µs | 3.56x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.38 ms | 6.77x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 1.38 ms | 6.77x | - |
| `wasmer_singlepass` | no | 3.20 ms | 15.67x | - |
| `wasmtime_winch` | no | 4.94 ms | 24.18x | - |
| `wasmtime_cranelift` | no | 35.45 ms | 173.55x | - |
| `wasmtime_cranelift_fuel` | yes | 44.02 ms | 215.50x | - |

### ed25519

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 95.46 µs | 1.00x | - |
| `polkavm64_recompiler_async_gas` | yes | 116.55 µs | 1.22x | - |
| `polkavm64_recompiler_sync_gas` | yes | 118.87 µs | 1.25x | - |
| `polkavm64_recompiler_no_gas` | no | 124.17 µs | 1.30x | - |
| `nub_jit_compile` | yes | 340.20 µs | 3.56x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 548.37 µs | 5.74x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 548.88 µs | 5.75x | - |
| `wasmtime_winch` | no | 2.75 ms | 28.84x | - |
| `wasmer_singlepass` | no | 3.82 ms | 40.01x | - |
| `wasmtime_cranelift` | no | 24.09 ms | 252.33x | - |
| `wasmtime_cranelift_fuel` | yes | 29.63 ms | 310.42x | - |

### fri-fold-tree

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 13.12 µs | 1.00x | - |
| `polkavm64_recompiler_async_gas` | yes | 29.48 µs | 2.25x | - |
| `polkavm64_recompiler_sync_gas` | yes | 29.85 µs | 2.27x | - |
| `polkavm64_recompiler_no_gas` | no | 29.87 µs | 2.28x | - |
| `nub_jit_compile` | yes | 58.91 µs | 4.49x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 59.24 µs | 4.51x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 129.63 µs | 9.88x | - |
| `wasmer_singlepass` | no | 1.50 ms | 114.62x | - |
| `wasmtime_winch` | no | 1.61 ms | 122.67x | - |
| `wasmtime_cranelift` | no | 8.03 ms | 611.84x | - |
| `wasmtime_cranelift_fuel` | yes | 11.25 ms | 857.27x | - |

### goldilocks-mul

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 4.45 µs | 1.00x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 5.60 µs | 1.26x | - |
| `polkavm64_recompiler_async_gas` | yes | 6.31 µs | 1.42x | - |
| `polkavm64_recompiler_sync_gas` | yes | 6.34 µs | 1.43x | - |
| `polkavm64_recompiler_no_gas` | no | 6.55 µs | 1.47x | - |
| `nub_jit_compile` | yes | 7.93 µs | 1.78x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 9.55 µs | 2.15x | - |
| `wasmtime_winch` | no | 232.73 µs | 52.31x | - |
| `wasmtime_cranelift` | no | 417.05 µs | 93.74x | - |
| `wasmtime_cranelift_fuel` | yes | 526.57 µs | 118.36x | - |
| `wasmer_singlepass` | no | 650.82 µs | 146.28x | - |

### keccak

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 9.19 µs | 1.00x | - |
| `polkavm64_recompiler_async_gas` | yes | 9.75 µs | 1.06x | - |
| `polkavm64_recompiler_no_gas` | no | 10.23 µs | 1.11x | - |
| `polkavm64_recompiler_sync_gas` | yes | 10.48 µs | 1.14x | - |
| `nub_jit_compile` | yes | 13.27 µs | 1.44x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 37.91 µs | 4.12x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 39.38 µs | 4.28x | - |
| `wasmtime_winch` | no | 812.45 µs | 88.37x | - |
| `wasmer_singlepass` | no | 838.46 µs | 91.20x | - |
| `wasmtime_cranelift` | no | 2.20 ms | 239.66x | - |
| `wasmtime_cranelift_fuel` | yes | 2.91 ms | 315.98x | - |

### mini-verifier

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 12.59 µs | 1.00x | - |
| `polkavm64_recompiler_sync_gas` | yes | 13.24 µs | 1.05x | - |
| `polkavm64_recompiler_async_gas` | yes | 13.38 µs | 1.06x | - |
| `polkavm64_recompiler_no_gas` | no | 13.94 µs | 1.11x | - |
| `nub_jit_compile` | yes | 28.00 µs | 2.22x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 56.78 µs | 4.51x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 59.15 µs | 4.70x | - |
| `wasmtime_winch` | no | 575.15 µs | 45.67x | - |
| `wasmer_singlepass` | no | 934.62 µs | 74.21x | - |
| `wasmtime_cranelift` | no | 2.46 ms | 195.46x | - |
| `wasmtime_cranelift_fuel` | yes | 2.88 ms | 228.64x | - |

### poly-eval

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 4.02 µs | 1.00x | - |
| `nub_jit_compile` | yes | 8.95 µs | 2.23x | - |
| `polkavm64_recompiler_async_gas` | yes | 10.12 µs | 2.52x | - |
| `polkavm64_recompiler_no_gas` | no | 10.21 µs | 2.54x | - |
| `polkavm64_recompiler_sync_gas` | yes | 10.59 µs | 2.63x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 27.44 µs | 6.83x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 27.45 µs | 6.83x | - |
| `wasmtime_winch` | no | 1.29 ms | 321.06x | - |
| `wasmer_singlepass` | no | 1.42 ms | 353.01x | - |
| `wasmtime_cranelift` | no | 5.38 ms | 1338.91x | - |
| `wasmtime_cranelift_fuel` | yes | 8.27 ms | 2056.91x | - |

### poseidon2-perm

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_recompiler_no_gas` | no | 10.44 µs | 1.00x | - |
| `polkavm64_recompiler_async_gas` | yes | 10.71 µs | 1.03x | - |
| `polkavm64_recompiler_sync_gas` | yes | 11.05 µs | 1.06x | - |
| `polkavm64_interpreter` | no | 16.65 µs | 1.60x | - |
| `nub_jit_compile` | yes | 43.66 µs | 4.18x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 44.36 µs | 4.25x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 45.55 µs | 4.36x | - |
| `wasmtime_winch` | no | 505.12 µs | 48.41x | - |
| `wasmer_singlepass` | no | 898.31 µs | 86.09x | - |
| `wasmtime_cranelift` | no | 1.99 ms | 190.51x | - |
| `wasmtime_cranelift_fuel` | yes | 2.44 ms | 233.46x | - |

### prime-sieve

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 4.44 µs | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 7.25 µs | 1.63x | - |
| `polkavm64_recompiler_sync_gas` | yes | 7.30 µs | 1.65x | - |
| `polkavm64_recompiler_async_gas` | yes | 7.33 µs | 1.65x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 9.81 µs | 2.21x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 10.03 µs | 2.26x | - |
| `nub_jit_compile` | yes | 11.44 µs | 2.58x | - |
| `wasmtime_winch` | no | 354.25 µs | 79.82x | - |
| `wasmtime_cranelift` | no | 536.58 µs | 120.91x | - |
| `wasmer_singlepass` | no | 677.35 µs | 152.63x | - |
| `wasmtime_cranelift_fuel` | yes | 858.05 µs | 193.34x | - |

## oneshot

Cold invocation: a fresh instance every sample. This is nub's real production model — every invocation builds a new address space — and it is where an engine's instantiation strategy shows up. Compare against `runtime` for the same row to see what a cold start costs that engine.

### blake2b

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 1.08 µs | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 2.67 µs | 2.46x | 2.5x |
| `wasmtime_cranelift_fuel` | yes | 2.79 µs | 2.58x | 2.6x |
| `wasmtime_winch` | no | 3.18 µs | 2.93x | 2.9x |
| `polkavm64_recompiler_no_gas` | no | 7.29 µs | 6.72x | 6.7x |
| `polkavm64_recompiler_async_gas` | yes | 8.20 µs | 7.56x | 7.6x |
| `polkavm64_recompiler_async_gas_full` | yes | 8.34 µs | 7.70x | 7.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 8.50 µs | 7.84x | 7.8x |
| `polkavm64_recompiler_sync_gas` | yes | 8.92 µs | 8.23x | 8.2x |
| `wasmer_singlepass` | no | 9.97 µs | 9.20x | 9.2x |
| `polkavm64_interpreter` | no | 99.80 µs | 92.07x | 92.1x |
| `nub_interp` | yes | 158.62 µs | 146.33x | 146.3x |

### ecrecover

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 102.90 µs | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 264.09 µs | 2.57x | 2.6x |
| `wasmtime_cranelift_fuel` | yes | 271.13 µs | 2.63x | 2.6x |
| `wasmtime_winch` | no | 391.85 µs | 3.81x | 3.8x |
| `polkavm64_recompiler_no_gas` | no | 412.48 µs | 4.01x | 4.0x |
| `polkavm64_recompiler_async_gas` | yes | 451.94 µs | 4.39x | 4.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 454.24 µs | 4.41x | 4.4x |
| `polkavm64_recompiler_sync_gas` | yes | 467.37 µs | 4.54x | 4.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 468.15 µs | 4.55x | 4.5x |
| `wasmer_singlepass` | no | 1.35 ms | 13.15x | 13.2x |
| `polkavm64_interpreter` | no | 11.68 ms | 113.46x | 113.5x |
| `nub_interp` | yes | 26.32 ms | 255.79x | 255.8x |

### ed25519

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 76.32 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 88.97 µs | 1.17x | 1.2x |
| `polkavm64_recompiler_async_gas_full` | yes | 96.70 µs | 1.27x | 1.3x |
| `polkavm64_recompiler_sync_gas` | yes | 97.66 µs | 1.28x | 1.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 99.93 µs | 1.31x | 1.3x |
| `polkavm64_recompiler_async_gas` | yes | 100.29 µs | 1.31x | 1.3x |
| `wasmtime_cranelift` | no | 200.48 µs | 2.63x | 2.6x |
| `wasmtime_cranelift_fuel` | yes | 242.56 µs | 3.18x | 3.2x |
| `wasmtime_winch` | no | 349.94 µs | 4.58x | 4.6x |
| `wasmer_singlepass` | no | 1.38 ms | 18.11x | 18.1x |
| `polkavm64_interpreter` | no | 1.73 ms | 22.66x | 22.7x |
| `nub_interp` | yes | 5.20 ms | 68.09x | 68.1x |

### fri-fold-tree

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 235.95 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 540.77 µs | 2.29x | 2.3x |
| `polkavm64_recompiler_sync_gas` | yes | 561.56 µs | 2.38x | 2.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 566.48 µs | 2.40x | 2.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 568.42 µs | 2.41x | 2.4x |
| `polkavm64_recompiler_async_gas` | yes | 571.35 µs | 2.42x | 2.4x |
| `wasmtime_cranelift` | no | 767.19 µs | 3.25x | 3.3x |
| `wasmtime_cranelift_fuel` | yes | 790.17 µs | 3.35x | 3.3x |
| `wasmtime_winch` | no | 1.25 ms | 5.32x | 5.3x |
| `wasmer_singlepass` | no | 4.45 ms | 18.87x | 18.9x |
| `polkavm64_interpreter` | no | 8.79 ms | 37.25x | 37.3x |
| `nub_interp` | yes | 14.02 ms | 59.44x | 59.4x |

### goldilocks-mul

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 213.98 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 348.66 µs | 1.63x | 1.6x |
| `polkavm64_recompiler_sync_gas` | yes | 370.94 µs | 1.73x | 1.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 381.39 µs | 1.78x | 1.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 384.52 µs | 1.80x | 1.8x |
| `polkavm64_recompiler_async_gas` | yes | 385.01 µs | 1.80x | 1.8x |
| `wasmtime_cranelift_fuel` | yes | 519.23 µs | 2.43x | 2.4x |
| `wasmtime_cranelift` | no | 535.09 µs | 2.50x | 2.5x |
| `wasmtime_winch` | no | 535.92 µs | 2.50x | 2.5x |
| `wasmer_singlepass` | no | 1.60 ms | 7.48x | 7.5x |
| `polkavm64_interpreter` | no | 2.14 ms | 10.02x | 10.0x |
| `nub_interp` | yes | 3.93 ms | 18.36x | 18.4x |

### keccak

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 2.88 µs | 1.00x | 1.0x |
| `wasmtime_cranelift_fuel` | yes | 4.51 µs | 1.57x | 1.6x |
| `wasmtime_cranelift` | no | 4.61 µs | 1.60x | 1.6x |
| `wasmtime_winch` | no | 5.24 µs | 1.82x | 1.8x |
| `wasmer_singlepass` | no | 6.12 µs | 2.13x | 2.1x |
| `polkavm64_recompiler_no_gas` | no | 8.58 µs | 2.99x | 3.0x |
| `polkavm64_recompiler_sync_gas_full` | yes | 10.40 µs | 3.62x | 3.6x |
| `polkavm64_recompiler_async_gas_full` | yes | 10.62 µs | 3.69x | 3.7x |
| `polkavm64_recompiler_async_gas` | yes | 10.81 µs | 3.76x | 3.8x |
| `polkavm64_recompiler_sync_gas` | yes | 11.32 µs | 3.94x | 3.9x |
| `polkavm64_interpreter` | no | 216.10 µs | 75.17x | 75.2x |
| `nub_interp` | yes | 499.61 µs | 173.78x | 173.8x |

### mini-verifier

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 247.47 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 554.91 µs | 2.24x | 2.2x |
| `polkavm64_recompiler_sync_gas_full` | yes | 556.29 µs | 2.25x | 2.2x |
| `polkavm64_recompiler_async_gas` | yes | 583.75 µs | 2.36x | 2.4x |
| `polkavm64_recompiler_sync_gas` | yes | 583.95 µs | 2.36x | 2.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 584.68 µs | 2.36x | 2.4x |
| `wasmtime_cranelift` | no | 789.23 µs | 3.19x | 3.2x |
| `wasmtime_cranelift_fuel` | yes | 815.10 µs | 3.29x | 3.3x |
| `wasmtime_winch` | no | 1.32 ms | 5.34x | 5.3x |
| `wasmer_singlepass` | no | 4.34 ms | 17.56x | 17.6x |
| `polkavm64_interpreter` | no | 9.62 ms | 38.88x | 38.9x |
| `nub_interp` | yes | 14.62 ms | 59.09x | 59.1x |

### poly-eval

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 697.24 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.17 ms | 1.68x | 1.7x |
| `polkavm64_recompiler_no_gas` | no | 1.19 ms | 1.71x | 1.7x |
| `polkavm64_recompiler_sync_gas` | yes | 1.19 ms | 1.71x | 1.7x |
| `polkavm64_recompiler_async_gas` | yes | 1.22 ms | 1.76x | 1.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.23 ms | 1.77x | 1.8x |
| `wasmtime_cranelift_fuel` | yes | 1.44 ms | 2.06x | 2.1x |
| `wasmtime_cranelift` | no | 1.53 ms | 2.19x | 2.2x |
| `wasmtime_winch` | no | 1.65 ms | 2.37x | 2.4x |
| `wasmer_singlepass` | no | 5.35 ms | 7.67x | 7.7x |
| `polkavm64_interpreter` | no | 8.01 ms | 11.49x | 11.5x |
| `nub_interp` | yes | 16.53 ms | 23.71x | 23.7x |

### poseidon2-perm

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 605.31 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.35 ms | 2.24x | 2.2x |
| `polkavm64_recompiler_async_gas` | yes | 1.37 ms | 2.26x | 2.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.37 ms | 2.27x | 2.3x |
| `polkavm64_recompiler_no_gas` | no | 1.39 ms | 2.29x | 2.3x |
| `polkavm64_recompiler_sync_gas` | yes | 1.41 ms | 2.32x | 2.3x |
| `wasmtime_cranelift` | no | 1.93 ms | 3.19x | 3.2x |
| `wasmtime_cranelift_fuel` | yes | 1.97 ms | 3.26x | 3.3x |
| `wasmtime_winch` | no | 3.15 ms | 5.20x | 5.2x |
| `wasmer_singlepass` | no | 10.60 ms | 17.51x | 17.5x |
| `polkavm64_interpreter` | no | 22.19 ms | 36.67x | 36.7x |
| `nub_interp` | yes | 36.06 ms | 59.57x | 59.6x |

### prime-sieve

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 57.28 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 113.72 µs | 1.99x | 2.0x |
| `wasmtime_cranelift` | no | 116.04 µs | 2.03x | 2.0x |
| `wasmer_singlepass` | no | 150.34 µs | 2.62x | 2.6x |
| `wasmtime_cranelift_fuel` | yes | 165.89 µs | 2.90x | 2.9x |
| `wasmtime_winch` | no | 172.98 µs | 3.02x | 3.0x |
| `polkavm64_recompiler_async_gas` | yes | 209.26 µs | 3.65x | 3.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 210.84 µs | 3.68x | 3.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 215.75 µs | 3.77x | 3.8x |
| `polkavm64_recompiler_sync_gas` | yes | 215.98 µs | 3.77x | 3.8x |
| `polkavm64_interpreter` | no | 2.10 ms | 36.71x | 36.7x |
| `nub_interp` | yes | 7.05 ms | 123.11x | 123.1x |

## runtime

Steady-state execution: one instance, invoked repeatedly. How fast the engine *executes*, with instantiation excluded.

Rows are absent where a program cannot be re-run in one instance (the three guests with a never-freeing bump arena).

### blake2b

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 679.0 ns | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 750.0 ns | 1.10x | 1.1x |
| `wasmtime_cranelift_fuel` | yes | 783.0 ns | 1.15x | 1.2x |
| `wasmtime_winch` | no | 1.22 µs | 1.79x | 1.8x |
| `polkavm64_recompiler_no_gas` | no | 1.74 µs | 2.56x | 2.6x |
| `polkavm64_recompiler_sync_gas_full` | yes | 2.31 µs | 3.41x | 3.4x |
| `polkavm64_recompiler_async_gas` | yes | 2.41 µs | 3.55x | 3.6x |
| `polkavm64_recompiler_sync_gas` | yes | 2.45 µs | 3.61x | 3.6x |
| `polkavm64_recompiler_async_gas_full` | yes | 2.47 µs | 3.63x | 3.6x |
| `wasmer_singlepass` | no | 5.14 µs | 7.57x | 7.6x |
| `polkavm64_interpreter` | no | 45.35 µs | 66.79x | 66.8x |
| `nub_interp` | yes | 150.44 µs | 221.56x | 221.6x |

### ecrecover

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 101.20 µs | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 257.58 µs | 2.55x | 2.5x |
| `wasmtime_cranelift_fuel` | yes | 261.33 µs | 2.58x | 2.6x |
| `wasmtime_winch` | no | 386.96 µs | 3.82x | 3.8x |
| `polkavm64_recompiler_no_gas` | no | 400.52 µs | 3.96x | 4.0x |
| `polkavm64_recompiler_async_gas` | yes | 440.57 µs | 4.35x | 4.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 441.13 µs | 4.36x | 4.4x |
| `polkavm64_recompiler_sync_gas` | yes | 455.87 µs | 4.50x | 4.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 456.19 µs | 4.51x | 4.5x |
| `wasmer_singlepass` | no | 821.52 µs | 8.12x | 8.1x |
| `polkavm64_interpreter` | no | 11.13 ms | 110.00x | 110.0x |
| `nub_interp` | yes | 26.30 ms | 259.89x | 259.9x |

### ed25519

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 30.27 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 80.33 µs | 2.65x | 2.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 90.89 µs | 3.00x | 3.0x |
| `polkavm64_recompiler_sync_gas` | yes | 91.38 µs | 3.02x | 3.0x |
| `polkavm64_recompiler_async_gas_full` | yes | 91.68 µs | 3.03x | 3.0x |
| `polkavm64_recompiler_async_gas` | yes | 92.04 µs | 3.04x | 3.0x |
| `wasmtime_cranelift` | no | 197.44 µs | 6.52x | 6.5x |
| `wasmtime_cranelift_fuel` | yes | 239.29 µs | 7.91x | 7.9x |
| `wasmtime_winch` | no | 343.39 µs | 11.34x | 11.3x |
| `wasmer_singlepass` | no | 963.52 µs | 31.83x | 31.8x |
| `polkavm64_interpreter` | no | 1.43 ms | 47.39x | 47.4x |
| `nub_interp` | yes | 4.97 ms | 164.15x | 164.1x |

### fri-fold-tree

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 226.54 µs | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 754.94 µs | 3.33x | 3.3x |
| `wasmtime_cranelift_fuel` | yes | 772.40 µs | 3.41x | 3.4x |
| `wasmtime_winch` | no | 1.27 ms | 5.61x | 5.6x |
| `wasmer_singlepass` | no | 3.68 ms | 16.23x | 16.2x |

### goldilocks-mul

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 202.32 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 346.13 µs | 1.71x | 1.7x |
| `polkavm64_recompiler_async_gas` | yes | 377.20 µs | 1.86x | 1.9x |
| `polkavm64_recompiler_sync_gas_full` | yes | 379.68 µs | 1.88x | 1.9x |
| `polkavm64_recompiler_async_gas_full` | yes | 383.18 µs | 1.89x | 1.9x |
| `polkavm64_recompiler_sync_gas` | yes | 383.24 µs | 1.89x | 1.9x |
| `wasmtime_winch` | no | 505.37 µs | 2.50x | 2.5x |
| `wasmtime_cranelift_fuel` | yes | 509.26 µs | 2.52x | 2.5x |
| `wasmtime_cranelift` | no | 534.25 µs | 2.64x | 2.6x |
| `wasmer_singlepass` | no | 1.50 ms | 7.43x | 7.4x |
| `polkavm64_interpreter` | no | 2.09 ms | 10.33x | 10.3x |
| `nub_interp` | yes | 3.78 ms | 18.70x | 18.7x |

### keccak

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 1.67 µs | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 2.13 µs | 1.28x | 1.3x |
| `wasmtime_cranelift_fuel` | yes | 2.23 µs | 1.34x | 1.3x |
| `wasmtime_winch` | no | 2.60 µs | 1.56x | 1.6x |
| `polkavm64_recompiler_no_gas` | no | 3.16 µs | 1.90x | 1.9x |
| `wasmer_singlepass` | no | 3.67 µs | 2.20x | 2.2x |
| `polkavm64_recompiler_async_gas_full` | yes | 3.69 µs | 2.22x | 2.2x |
| `polkavm64_recompiler_sync_gas_full` | yes | 3.75 µs | 2.25x | 2.3x |
| `polkavm64_recompiler_sync_gas` | yes | 3.75 µs | 2.25x | 2.3x |
| `polkavm64_recompiler_async_gas` | yes | 3.91 µs | 2.35x | 2.3x |
| `polkavm64_interpreter` | no | 75.56 µs | 45.38x | 45.4x |
| `nub_interp` | yes | 242.68 µs | 145.76x | 145.8x |

### mini-verifier

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 234.39 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 573.75 µs | 2.45x | 2.4x |
| `polkavm64_recompiler_async_gas` | yes | 573.81 µs | 2.45x | 2.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 575.13 µs | 2.45x | 2.5x |
| `polkavm64_recompiler_sync_gas` | yes | 575.98 µs | 2.46x | 2.5x |
| `polkavm64_recompiler_async_gas_full` | yes | 577.33 µs | 2.46x | 2.5x |
| `wasmtime_cranelift_fuel` | yes | 773.94 µs | 3.30x | 3.3x |
| `wasmtime_cranelift` | no | 783.98 µs | 3.34x | 3.3x |
| `wasmtime_winch` | no | 1.33 ms | 5.68x | 5.7x |
| `wasmer_singlepass` | no | 4.03 ms | 17.20x | 17.2x |
| `polkavm64_interpreter` | no | 9.68 ms | 41.29x | 41.3x |
| `nub_interp` | yes | 14.85 ms | 63.34x | 63.3x |

### poly-eval

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 675.23 µs | 1.00x | 1.0x |
| `wasmtime_cranelift_fuel` | yes | 1.50 ms | 2.22x | 2.2x |
| `wasmtime_cranelift` | no | 1.55 ms | 2.30x | 2.3x |
| `wasmtime_winch` | no | 1.68 ms | 2.49x | 2.5x |
| `wasmer_singlepass` | no | 5.01 ms | 7.42x | 7.4x |

### poseidon2-perm

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 579.93 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 1.39 ms | 2.39x | 2.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.40 ms | 2.41x | 2.4x |
| `polkavm64_recompiler_sync_gas` | yes | 1.40 ms | 2.41x | 2.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.40 ms | 2.41x | 2.4x |
| `polkavm64_recompiler_async_gas` | yes | 1.41 ms | 2.43x | 2.4x |
| `wasmtime_cranelift` | no | 1.92 ms | 3.30x | 3.3x |
| `wasmtime_cranelift_fuel` | yes | 1.95 ms | 3.37x | 3.4x |
| `wasmtime_winch` | no | 3.00 ms | 5.17x | 5.2x |
| `wasmer_singlepass` | no | 9.92 ms | 17.11x | 17.1x |
| `polkavm64_interpreter` | no | 22.87 ms | 39.44x | 39.4x |
| `nub_interp` | yes | 37.72 ms | 65.05x | 65.0x |

### prime-sieve

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `wasmtime_cranelift` | no | 77.09 µs | 1.00x | 0.8x |
| `polkavm64_recompiler_no_gas` | no | 86.75 µs | 1.13x | 0.9x |
| `native` | no | 96.95 µs | 1.26x | 1.0x |
| `wasmer_singlepass` | no | 128.06 µs | 1.66x | 1.3x |
| `wasmtime_cranelift_fuel` | yes | 146.93 µs | 1.91x | 1.5x |
| `wasmtime_winch` | no | 152.38 µs | 1.98x | 1.6x |
| `polkavm64_recompiler_sync_gas_full` | yes | 189.28 µs | 2.46x | 2.0x |
| `polkavm64_recompiler_async_gas` | yes | 190.09 µs | 2.47x | 2.0x |
| `polkavm64_recompiler_async_gas_full` | yes | 190.44 µs | 2.47x | 2.0x |
| `polkavm64_recompiler_sync_gas` | yes | 195.65 µs | 2.54x | 2.0x |
| `polkavm64_interpreter` | no | 2.14 ms | 27.81x | 22.1x |
| `nub_interp` | yes | 7.08 ms | 91.79x | 73.0x |
