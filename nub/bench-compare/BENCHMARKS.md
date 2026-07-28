# nub benchmark comparison

## Cold recompile + execute, metered JIT engines

The bench target. Each sample starts with no compiled code and ends with the program having run — the cost a VM pays when a work-package arrives, is turned into native code, and executed once. Metering on.

Storage is deliberately excluded. Getting a blob *into* an engine's object store is dominated by hashing and belongs to a different subsystem than the recompiler; for nub that step is measured separately under `compilation`.

Only cost models comparable to nub's appear here. PolkaVM's default `Simple` model is a flat per-instruction cost and is much cheaper to evaluate than nub's pipeline simulation, so the `*_full` rows (`CacheModel::L2Hit`, whose `memory_access_cost: 25` is exactly nub's `MEM_CYCLES_BASE`) are the like-for-like comparison. Full tables for every engine and every measurement kind follow below.

| Program | `nub_jit` | `polkavm64_recompiler_sync_gas_full` | `polkavm64_recompiler_async_gas_full` | `wasmtime_cranelift_fuel` |
|---|--:|--:|--:|--:|
| blake2b | 125.69 µs (1.05x) | **119.73 µs** (1.00x) | 120.17 µs (1.00x) | 3.50 ms (29.26x) |
| keccak | 81.74 µs (1.43x) | 57.40 µs (1.01x) | **57.10 µs** (1.00x) | 3.02 ms (52.85x) |
| poly-eval | **1.17 ms** (1.00x) | 1.26 ms (1.07x) | 1.31 ms (1.11x) | 10.44 ms (8.90x) |
| prime-sieve | 364.31 µs (1.60x) | 233.21 µs (1.03x) | **227.15 µs** (1.00x) | 1.03 ms (4.54x) |
| mini-verifier | **568.04 µs** (1.00x) | 663.26 µs (1.17x) | 658.86 µs (1.16x) | 3.81 ms (6.71x) |
| fri-fold-tree | **553.61 µs** (1.00x) | 642.19 µs (1.16x) | 640.33 µs (1.16x) | 12.74 ms (23.02x) |
| goldilocks-mul | 552.10 µs (1.40x) | **394.50 µs** (1.00x) | 395.53 µs (1.00x) | 1.05 ms (2.67x) |
| ecrecover | **1.21 ms** (1.00x) | 1.85 ms (1.52x) | 1.84 ms (1.51x) | 45.40 ms (37.37x) |
| poseidon2-perm | **1.23 ms** (1.00x) | 1.47 ms (1.19x) | 1.47 ms (1.19x) | 4.42 ms (3.59x) |
| ed25519 | **517.33 µs** (1.00x) | 659.55 µs (1.27x) | 664.57 µs (1.28x) | 30.79 ms (59.52x) |

Bold = fastest for that program; the multiple is versus it.

### Where that time goes

The same rows with **compilation excluded** — a fresh instance per sample, then execute. Every engine pays instantiation here, so this is like-for-like even for nub, which rebuilds its frame on every call and therefore has no warm state to hoist out.

The bracketed figure is the difference against the table above: what the recompile costs that engine.

| Program | `nub_jit` | `polkavm64_recompiler_sync_gas_full` | `polkavm64_recompiler_async_gas_full` | `wasmtime_cranelift_fuel` |
|---|--:|--:|--:|--:|
| blake2b | 8.39 µs (+117.30 µs recompile) | 8.58 µs (+111.15 µs recompile) | 8.52 µs (+111.65 µs recompile) | 2.54 µs (+3.50 ms recompile) |
| keccak | 7.24 µs (+74.49 µs recompile) | 10.85 µs (+46.55 µs recompile) | 10.83 µs (+46.27 µs recompile) | 4.55 µs (+3.01 ms recompile) |
| poly-eval | 1.63 ms (+0.0 ns recompile) | 1.24 ms (+22.62 µs recompile) | 1.29 ms (+13.19 µs recompile) | 1.53 ms (+8.91 ms recompile) |
| prime-sieve | 285.75 µs (+78.57 µs recompile) | 228.77 µs (+4.44 µs recompile) | 212.82 µs (+14.34 µs recompile) | 166.11 µs (+866.01 µs recompile) |
| mini-verifier | 485.18 µs (+82.86 µs recompile) | 582.62 µs (+80.64 µs recompile) | 581.46 µs (+77.40 µs recompile) | 815.06 µs (+3.00 ms recompile) |
| fri-fold-tree | 469.68 µs (+83.92 µs recompile) | 566.60 µs (+75.60 µs recompile) | 568.09 µs (+72.24 µs recompile) | 794.62 µs (+11.95 ms recompile) |
| goldilocks-mul | 319.67 µs (+232.44 µs recompile) | 385.11 µs (+9.40 µs recompile) | 385.08 µs (+10.45 µs recompile) | 520.62 µs (+533.38 µs recompile) |
| ecrecover | 387.97 µs (+826.84 µs recompile) | 467.27 µs (+1.38 ms recompile) | 453.23 µs (+1.38 ms recompile) | 273.20 µs (+45.13 ms recompile) |
| poseidon2-perm | 1.21 ms (+23.89 µs recompile) | 1.42 ms (+50.65 µs recompile) | 1.41 ms (+51.29 µs recompile) | 2.00 ms (+2.42 ms recompile) |
| ed25519 | 154.53 µs (+362.80 µs recompile) | 100.06 µs (+559.49 µs recompile) | 100.00 µs (+564.57 µs recompile) | 246.69 µs (+30.54 ms recompile) |

## Provenance

- Guest toolchain: `rustc 1.95.0 (59807616e 2026-04-14)`
- CPU: 13th Gen Intel(R) Core(TM) i9-13900K
- ASLR: disabled for the measuring process
- Harness profile: `lto = true`, `codegen-units = 1`

## How to read this

Every row runs the *same Rust compute kernel*, compiled to that engine's target. Only the measured call is timed: compilation and instantiation happen before the clock starts, for every engine alike.

`metered` marks engines charging gas/fuel while running, with the counter set to maximum so the instrumentation runs but never fires. **Metered and unmetered rows are not corrected against each other.** Gas is an axis of this comparison, not a confounder to normalize away — read the cost of metering off the `polkavm64_recompiler_no_gas` / `_sync_gas` pair and the `wasmtime_cranelift` / `_fuel` pair, which bracket it.

`vs native` is the multiple of bare-metal cost. It is the number that says what an engine charges you.


## cold

**The bench target.** Cold recompile + execute: each sample begins with no compiled code and ends with the program having run.

Storage is excluded. An eager engine compiles inside the clock; nub compiles lazily on first entry, so it publishes once up front (untimed) and its JIT cache is evicted before each sample (also untimed), leaving `run` to recompile. Both shapes measure the same thing against different designs.

### blake2b

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 13.50 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_async_gas` | yes | 39.84 µs | 2.95x | 3.0x |
| `polkavm64_recompiler_no_gas` | no | 39.95 µs | 2.96x | 3.0x |
| `polkavm64_recompiler_sync_gas` | yes | 40.80 µs | 3.02x | 3.0x |
| `polkavm64_recompiler_sync_gas_full` | yes | 119.73 µs | 8.87x | 8.9x |
| `polkavm64_recompiler_async_gas_full` | yes | 120.17 µs | 8.90x | 8.9x |
| `nub_jit` | yes | 125.69 µs | 9.31x | 9.3x |
| `polkavm64_interpreter` | no | 130.78 µs | 9.69x | 9.7x |
| `nub_interp` | yes | 209.44 µs | 15.52x | 15.5x |
| `wasmtime_winch` | no | 458.07 µs | 33.94x | 33.9x |
| `wasmer_singlepass` | no | 2.19 ms | 162.07x | 162.1x |
| `wasmtime_cranelift` | no | 3.30 ms | 244.66x | 244.7x |
| `wasmtime_cranelift_fuel` | yes | 3.50 ms | 259.58x | 259.6x |

### ecrecover

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 118.99 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 686.57 µs | 5.77x | 5.8x |
| `polkavm64_recompiler_async_gas` | yes | 722.62 µs | 6.07x | 6.1x |
| `polkavm64_recompiler_sync_gas` | yes | 740.69 µs | 6.22x | 6.2x |
| `nub_jit` | yes | 1.21 ms | 10.21x | 10.2x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.84 ms | 15.43x | 15.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.85 ms | 15.52x | 15.5x |
| `wasmtime_winch` | no | 5.54 ms | 46.59x | 46.6x |
| `wasmer_singlepass` | no | 7.36 ms | 61.90x | 61.9x |
| `polkavm64_interpreter` | no | 13.08 ms | 109.92x | 109.9x |
| `nub_interp` | yes | 28.08 ms | 235.99x | 236.0x |
| `wasmtime_cranelift` | no | 36.86 ms | 309.74x | 309.7x |
| `wasmtime_cranelift_fuel` | yes | 45.40 ms | 381.54x | 381.5x |

### ed25519

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 46.38 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 213.50 µs | 4.60x | 4.6x |
| `polkavm64_recompiler_async_gas` | yes | 225.61 µs | 4.86x | 4.9x |
| `polkavm64_recompiler_sync_gas` | yes | 225.80 µs | 4.87x | 4.9x |
| `nub_jit` | yes | 517.33 µs | 11.15x | 11.2x |
| `polkavm64_recompiler_sync_gas_full` | yes | 659.55 µs | 14.22x | 14.2x |
| `polkavm64_recompiler_async_gas_full` | yes | 664.57 µs | 14.33x | 14.3x |
| `polkavm64_interpreter` | no | 1.96 ms | 42.31x | 42.3x |
| `wasmtime_winch` | no | 3.20 ms | 68.90x | 68.9x |
| `nub_interp` | yes | 5.55 ms | 119.71x | 119.7x |
| `wasmer_singlepass` | no | 8.91 ms | 192.03x | 192.0x |
| `wasmtime_cranelift` | no | 24.17 ms | 521.12x | 521.1x |
| `wasmtime_cranelift_fuel` | yes | 30.79 ms | 663.85x | 663.8x |

### fri-fold-tree

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 253.72 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 553.61 µs | 2.18x | 2.2x |
| `polkavm64_recompiler_no_gas` | no | 563.04 µs | 2.22x | 2.2x |
| `polkavm64_recompiler_async_gas` | yes | 602.00 µs | 2.37x | 2.4x |
| `polkavm64_recompiler_sync_gas` | yes | 624.30 µs | 2.46x | 2.5x |
| `polkavm64_recompiler_async_gas_full` | yes | 640.33 µs | 2.52x | 2.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 642.19 µs | 2.53x | 2.5x |
| `wasmtime_winch` | no | 3.03 ms | 11.95x | 12.0x |
| `wasmer_singlepass` | no | 8.06 ms | 31.75x | 31.7x |
| `wasmtime_cranelift` | no | 9.18 ms | 36.18x | 36.2x |
| `polkavm64_interpreter` | no | 10.03 ms | 39.52x | 39.5x |
| `wasmtime_cranelift_fuel` | yes | 12.74 ms | 50.22x | 50.2x |
| `nub_interp` | yes | 13.42 ms | 52.89x | 52.9x |

### goldilocks-mul

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 227.07 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 356.48 µs | 1.57x | 1.6x |
| `polkavm64_recompiler_async_gas` | yes | 392.86 µs | 1.73x | 1.7x |
| `polkavm64_recompiler_sync_gas` | yes | 393.31 µs | 1.73x | 1.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 394.50 µs | 1.74x | 1.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 395.53 µs | 1.74x | 1.7x |
| `nub_jit` | yes | 552.10 µs | 2.43x | 2.4x |
| `wasmtime_winch` | no | 758.70 µs | 3.34x | 3.3x |
| `wasmtime_cranelift` | no | 940.96 µs | 4.14x | 4.1x |
| `wasmtime_cranelift_fuel` | yes | 1.05 ms | 4.64x | 4.6x |
| `polkavm64_interpreter` | no | 2.46 ms | 10.81x | 10.8x |
| `wasmer_singlepass` | no | 2.90 ms | 12.79x | 12.8x |
| `nub_interp` | yes | 4.19 ms | 18.46x | 18.5x |

### keccak

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_recompiler_no_gas` | no | 31.16 µs | 1.00x | 1.0x |
| `native` | no | 31.41 µs | 1.01x | 1.0x |
| `polkavm64_recompiler_async_gas` | yes | 32.24 µs | 1.03x | 1.0x |
| `polkavm64_recompiler_sync_gas` | yes | 32.34 µs | 1.04x | 1.0x |
| `polkavm64_recompiler_async_gas_full` | yes | 57.10 µs | 1.83x | 1.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 57.40 µs | 1.84x | 1.8x |
| `nub_jit` | yes | 81.74 µs | 2.62x | 2.6x |
| `polkavm64_interpreter` | no | 117.56 µs | 3.77x | 3.7x |
| `nub_interp` | yes | 578.20 µs | 18.56x | 18.4x |
| `wasmtime_winch` | no | 843.35 µs | 27.06x | 26.8x |
| `wasmer_singlepass` | no | 1.77 ms | 56.78x | 56.3x |
| `wasmtime_cranelift` | no | 2.27 ms | 72.87x | 72.3x |
| `wasmtime_cranelift_fuel` | yes | 3.02 ms | 96.84x | 96.1x |

### mini-verifier

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 258.30 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 568.04 µs | 2.20x | 2.2x |
| `polkavm64_recompiler_no_gas` | no | 611.12 µs | 2.37x | 2.4x |
| `polkavm64_recompiler_sync_gas` | yes | 616.87 µs | 2.39x | 2.4x |
| `polkavm64_recompiler_async_gas` | yes | 621.54 µs | 2.41x | 2.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 658.86 µs | 2.55x | 2.6x |
| `polkavm64_recompiler_sync_gas_full` | yes | 663.26 µs | 2.57x | 2.6x |
| `wasmtime_winch` | no | 1.91 ms | 7.38x | 7.4x |
| `wasmtime_cranelift` | no | 3.32 ms | 12.87x | 12.9x |
| `wasmtime_cranelift_fuel` | yes | 3.81 ms | 14.76x | 14.8x |
| `wasmer_singlepass` | no | 6.53 ms | 25.27x | 25.3x |
| `polkavm64_interpreter` | no | 11.15 ms | 43.18x | 43.2x |
| `nub_interp` | yes | 14.04 ms | 54.34x | 54.3x |

### poly-eval

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 736.02 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 1.17 ms | 1.59x | 1.6x |
| `polkavm64_recompiler_no_gas` | no | 1.22 ms | 1.66x | 1.7x |
| `polkavm64_recompiler_sync_gas` | yes | 1.25 ms | 1.70x | 1.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.26 ms | 1.71x | 1.7x |
| `polkavm64_recompiler_async_gas` | yes | 1.30 ms | 1.76x | 1.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.31 ms | 1.77x | 1.8x |
| `wasmtime_winch` | no | 3.15 ms | 4.27x | 4.3x |
| `wasmtime_cranelift` | no | 7.13 ms | 9.68x | 9.7x |
| `wasmer_singlepass` | no | 9.29 ms | 12.62x | 12.6x |
| `polkavm64_interpreter` | no | 9.88 ms | 13.42x | 13.4x |
| `wasmtime_cranelift_fuel` | yes | 10.44 ms | 14.19x | 14.2x |
| `nub_interp` | yes | 18.03 ms | 24.49x | 24.5x |

### poseidon2-perm

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 624.04 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 1.23 ms | 1.97x | 2.0x |
| `polkavm64_recompiler_no_gas` | no | 1.42 ms | 2.28x | 2.3x |
| `polkavm64_recompiler_sync_gas` | yes | 1.44 ms | 2.30x | 2.3x |
| `polkavm64_recompiler_async_gas` | yes | 1.44 ms | 2.31x | 2.3x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.47 ms | 2.35x | 2.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.47 ms | 2.35x | 2.4x |
| `wasmtime_winch` | no | 3.65 ms | 5.85x | 5.9x |
| `wasmtime_cranelift` | no | 3.91 ms | 6.27x | 6.3x |
| `wasmtime_cranelift_fuel` | yes | 4.42 ms | 7.08x | 7.1x |
| `wasmer_singlepass` | no | 12.59 ms | 20.18x | 20.2x |
| `polkavm64_interpreter` | no | 25.10 ms | 40.23x | 40.2x |
| `nub_interp` | yes | 35.30 ms | 56.57x | 56.6x |

### prime-sieve

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_recompiler_no_gas` | no | 125.69 µs | 1.00x | 0.8x |
| `native` | no | 158.78 µs | 1.26x | 1.0x |
| `polkavm64_recompiler_async_gas` | yes | 223.00 µs | 1.77x | 1.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 227.15 µs | 1.81x | 1.4x |
| `polkavm64_recompiler_sync_gas` | yes | 228.62 µs | 1.82x | 1.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 233.21 µs | 1.86x | 1.5x |
| `nub_jit` | yes | 364.31 µs | 2.90x | 2.3x |
| `wasmtime_winch` | no | 550.52 µs | 4.38x | 3.5x |
| `wasmtime_cranelift` | no | 643.80 µs | 5.12x | 4.1x |
| `wasmtime_cranelift_fuel` | yes | 1.03 ms | 8.21x | 6.5x |
| `wasmer_singlepass` | no | 1.75 ms | 13.96x | 11.0x |
| `polkavm64_interpreter` | no | 2.16 ms | 17.20x | 13.6x |
| `nub_interp` | yes | 7.56 ms | 60.15x | 47.6x |

## compilation

Turning the program into executable form. Engine construction and file loading are excluded (a once-per-process cost, and the harness's own I/O). `native` is absent: the OS loader already did it.

**`nub_jit` measures publishing here, not codegen** — and publishing is *not* part of the bench target above. nub keeps its object store *inside* the sandbox, so this is the cost of shipping a blob across the VM boundary, decoding it, content-hashing it and materializing its data image. It is dominated by hashing and scales with blob size, not code size. `nub_jit_compile` is the codegen-only figure.

### blake2b

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 19.37 µs | 1.00x | - |
| `polkavm64_recompiler_sync_gas` | yes | 19.89 µs | 1.03x | - |
| `polkavm64_recompiler_async_gas` | yes | 19.99 µs | 1.03x | - |
| `polkavm64_recompiler_no_gas` | no | 20.41 µs | 1.05x | - |
| `nub_jit_compile` | yes | 40.69 µs | 2.10x | - |
| `nub_jit` | yes | 72.05 µs | 3.72x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 101.90 µs | 5.26x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 102.28 µs | 5.28x | - |
| `wasmtime_winch` | no | 434.41 µs | 22.43x | - |
| `wasmer_singlepass` | no | 1.13 ms | 58.44x | - |
| `wasmtime_cranelift` | no | 3.30 ms | 170.26x | - |
| `wasmtime_cranelift_fuel` | yes | 3.39 ms | 174.76x | - |

### ecrecover

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 203.89 µs | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 260.98 µs | 1.28x | - |
| `polkavm64_recompiler_sync_gas` | yes | 262.60 µs | 1.29x | - |
| `polkavm64_recompiler_async_gas` | yes | 264.85 µs | 1.30x | - |
| `nub_jit` | yes | 640.67 µs | 3.14x | - |
| `nub_jit_compile` | yes | 725.13 µs | 3.56x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.37 ms | 6.74x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 1.38 ms | 6.75x | - |
| `wasmer_singlepass` | no | 3.26 ms | 16.00x | - |
| `wasmtime_winch` | no | 5.27 ms | 25.86x | - |
| `wasmtime_cranelift` | no | 37.56 ms | 184.20x | - |
| `wasmtime_cranelift_fuel` | yes | 46.33 ms | 227.23x | - |

### ed25519

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 87.28 µs | 1.00x | - |
| `polkavm64_recompiler_async_gas` | yes | 113.43 µs | 1.30x | - |
| `polkavm64_recompiler_no_gas` | no | 114.82 µs | 1.32x | - |
| `polkavm64_recompiler_sync_gas` | yes | 114.84 µs | 1.32x | - |
| `nub_jit` | yes | 306.06 µs | 3.51x | - |
| `nub_jit_compile` | yes | 336.90 µs | 3.86x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 541.26 µs | 6.20x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 543.69 µs | 6.23x | - |
| `wasmtime_winch` | no | 2.80 ms | 32.08x | - |
| `wasmer_singlepass` | no | 3.95 ms | 45.23x | - |
| `wasmtime_cranelift` | no | 24.06 ms | 275.68x | - |
| `wasmtime_cranelift_fuel` | yes | 30.42 ms | 348.56x | - |

### fri-fold-tree

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 10.93 µs | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 13.49 µs | 1.23x | - |
| `polkavm64_recompiler_sync_gas` | yes | 13.90 µs | 1.27x | - |
| `polkavm64_recompiler_async_gas` | yes | 23.24 µs | 2.13x | - |
| `nub_jit_compile` | yes | 29.56 µs | 2.71x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 56.82 µs | 5.20x | - |
| `nub_jit` | yes | 82.89 µs | 7.59x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 116.43 µs | 10.66x | - |
| `wasmer_singlepass` | no | 1.54 ms | 140.57x | - |
| `wasmtime_winch` | no | 1.68 ms | 153.94x | - |
| `wasmtime_cranelift` | no | 8.15 ms | 745.88x | - |
| `wasmtime_cranelift_fuel` | yes | 11.68 ms | 1068.68x | - |

### goldilocks-mul

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 351.0 ns | 1.00x | - |
| `polkavm64_recompiler_async_gas` | yes | 1.55 µs | 4.42x | - |
| `polkavm64_recompiler_no_gas` | no | 1.60 µs | 4.56x | - |
| `polkavm64_recompiler_sync_gas` | yes | 1.65 µs | 4.70x | - |
| `nub_jit_compile` | yes | 2.23 µs | 6.36x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 3.25 µs | 9.27x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 3.36 µs | 9.58x | - |
| `nub_jit` | yes | 27.10 µs | 77.22x | - |
| `wasmtime_winch` | no | 208.00 µs | 592.61x | - |
| `wasmtime_cranelift` | no | 389.22 µs | 1108.90x | - |
| `wasmtime_cranelift_fuel` | yes | 510.94 µs | 1455.66x | - |
| `wasmer_singlepass` | no | 646.33 µs | 1841.40x | - |

### keccak

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 7.42 µs | 1.00x | - |
| `polkavm64_recompiler_async_gas` | yes | 7.93 µs | 1.07x | - |
| `polkavm64_recompiler_no_gas` | no | 8.04 µs | 1.08x | - |
| `polkavm64_recompiler_sync_gas` | yes | 8.33 µs | 1.12x | - |
| `nub_jit_compile` | yes | 20.42 µs | 2.75x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 34.75 µs | 4.68x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 34.88 µs | 4.70x | - |
| `nub_jit` | yes | 82.32 µs | 11.09x | - |
| `wasmtime_winch` | no | 787.38 µs | 106.09x | - |
| `wasmer_singlepass` | no | 821.30 µs | 110.66x | - |
| `wasmtime_cranelift` | no | 2.16 ms | 291.68x | - |
| `wasmtime_cranelift_fuel` | yes | 2.89 ms | 389.32x | - |

### mini-verifier

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 9.79 µs | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 11.43 µs | 1.17x | - |
| `polkavm64_recompiler_sync_gas` | yes | 11.68 µs | 1.19x | - |
| `polkavm64_recompiler_async_gas` | yes | 11.78 µs | 1.20x | - |
| `nub_jit_compile` | yes | 24.84 µs | 2.54x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 53.34 µs | 5.45x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 55.16 µs | 5.63x | - |
| `nub_jit` | yes | 60.08 µs | 6.13x | - |
| `wasmtime_winch` | no | 565.14 µs | 57.70x | - |
| `wasmer_singlepass` | no | 952.97 µs | 97.29x | - |
| `wasmtime_cranelift` | no | 2.46 ms | 251.39x | - |
| `wasmtime_cranelift_fuel` | yes | 2.99 ms | 305.40x | - |

### poly-eval

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 1.88 µs | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 2.94 µs | 1.56x | - |
| `polkavm64_recompiler_sync_gas` | yes | 3.10 µs | 1.65x | - |
| `polkavm64_recompiler_async_gas` | yes | 3.31 µs | 1.76x | - |
| `nub_jit_compile` | yes | 6.45 µs | 3.43x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 11.39 µs | 6.06x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 11.50 µs | 6.12x | - |
| `nub_jit` | yes | 36.15 µs | 19.24x | - |
| `wasmer_singlepass` | no | 1.29 ms | 685.39x | - |
| `wasmtime_winch` | no | 1.34 ms | 712.59x | - |
| `wasmtime_cranelift` | no | 5.53 ms | 2940.81x | - |
| `wasmtime_cranelift_fuel` | yes | 8.63 ms | 4594.39x | - |

### poseidon2-perm

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_recompiler_async_gas` | yes | 8.20 µs | 1.00x | - |
| `polkavm64_interpreter` | no | 8.23 µs | 1.00x | - |
| `polkavm64_recompiler_sync_gas` | yes | 8.76 µs | 1.07x | - |
| `polkavm64_recompiler_no_gas` | no | 16.89 µs | 2.06x | - |
| `nub_jit_compile` | yes | 20.56 µs | 2.51x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 39.02 µs | 4.76x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 39.31 µs | 4.80x | - |
| `nub_jit` | yes | 52.65 µs | 6.42x | - |
| `wasmtime_winch` | no | 489.32 µs | 59.70x | - |
| `wasmer_singlepass` | no | 917.06 µs | 111.88x | - |
| `wasmtime_cranelift` | no | 2.00 ms | 244.15x | - |
| `wasmtime_cranelift_fuel` | yes | 2.44 ms | 297.52x | - |

### prime-sieve

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `polkavm64_interpreter` | no | 1.89 µs | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 4.68 µs | 2.47x | - |
| `polkavm64_recompiler_async_gas` | yes | 4.71 µs | 2.49x | - |
| `polkavm64_recompiler_sync_gas` | yes | 4.74 µs | 2.50x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 7.05 µs | 3.72x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 7.08 µs | 3.74x | - |
| `nub_jit_compile` | yes | 14.21 µs | 7.50x | - |
| `wasmtime_winch` | no | 338.43 µs | 178.78x | - |
| `wasmtime_cranelift` | no | 503.57 µs | 266.02x | - |
| `nub_jit` | yes | 524.27 µs | 276.95x | - |
| `wasmer_singlepass` | no | 676.70 µs | 357.47x | - |
| `wasmtime_cranelift_fuel` | yes | 831.93 µs | 439.48x | - |

## invoke

Cold invocation with compilation excluded: a fresh instance every sample. Where an engine's *instantiation* strategy shows up. Compare against `runtime` for the same row to see what a cold start costs it.

### blake2b

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 712.0 ns | 1.00x | 1.0x |
| `wasmtime_cranelift_fuel` | yes | 2.54 µs | 3.56x | 3.6x |
| `wasmtime_cranelift` | no | 2.68 µs | 3.77x | 3.8x |
| `wasmtime_winch` | no | 3.30 µs | 4.63x | 4.6x |
| `polkavm64_recompiler_no_gas` | no | 7.20 µs | 10.11x | 10.1x |
| `polkavm64_recompiler_async_gas` | yes | 8.15 µs | 11.45x | 11.4x |
| `polkavm64_recompiler_sync_gas` | yes | 8.22 µs | 11.54x | 11.5x |
| `nub_jit` | yes | 8.39 µs | 11.78x | 11.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 8.52 µs | 11.97x | 12.0x |
| `polkavm64_recompiler_sync_gas_full` | yes | 8.58 µs | 12.05x | 12.0x |
| `wasmer_singlepass` | no | 12.06 µs | 16.95x | 16.9x |
| `polkavm64_interpreter` | no | 103.38 µs | 145.20x | 145.2x |
| `nub_interp` | yes | 160.82 µs | 225.87x | 225.9x |

### ecrecover

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 101.49 µs | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 266.55 µs | 2.63x | 2.6x |
| `wasmtime_cranelift_fuel` | yes | 273.20 µs | 2.69x | 2.7x |
| `polkavm64_recompiler_no_gas` | no | 339.39 µs | 3.34x | 3.3x |
| `polkavm64_recompiler_sync_gas` | yes | 353.76 µs | 3.49x | 3.5x |
| `nub_jit` | yes | 387.97 µs | 3.82x | 3.8x |
| `wasmtime_winch` | no | 406.07 µs | 4.00x | 4.0x |
| `polkavm64_recompiler_async_gas_full` | yes | 453.23 µs | 4.47x | 4.5x |
| `polkavm64_recompiler_async_gas` | yes | 454.34 µs | 4.48x | 4.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 467.27 µs | 4.60x | 4.6x |
| `wasmer_singlepass` | no | 1.35 ms | 13.26x | 13.3x |
| `polkavm64_interpreter` | no | 13.01 ms | 128.15x | 128.1x |
| `nub_interp` | yes | 28.04 ms | 276.32x | 276.3x |

### ed25519

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 76.39 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 90.00 µs | 1.18x | 1.2x |
| `polkavm64_recompiler_async_gas_full` | yes | 100.00 µs | 1.31x | 1.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 100.06 µs | 1.31x | 1.3x |
| `polkavm64_recompiler_async_gas` | yes | 101.14 µs | 1.32x | 1.3x |
| `polkavm64_recompiler_sync_gas` | yes | 101.18 µs | 1.32x | 1.3x |
| `nub_jit` | yes | 154.53 µs | 2.02x | 2.0x |
| `wasmtime_cranelift` | no | 201.68 µs | 2.64x | 2.6x |
| `wasmtime_cranelift_fuel` | yes | 246.69 µs | 3.23x | 3.2x |
| `wasmtime_winch` | no | 358.76 µs | 4.70x | 4.7x |
| `wasmer_singlepass` | no | 1.36 ms | 17.83x | 17.8x |
| `polkavm64_interpreter` | no | 1.85 ms | 24.24x | 24.2x |
| `nub_interp` | yes | 5.21 ms | 68.25x | 68.2x |

### fri-fold-tree

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 468.53 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 469.68 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_async_gas` | yes | 563.70 µs | 1.20x | 1.2x |
| `polkavm64_recompiler_no_gas` | no | 565.52 µs | 1.21x | 1.2x |
| `polkavm64_recompiler_sync_gas_full` | yes | 566.60 µs | 1.21x | 1.2x |
| `polkavm64_recompiler_async_gas_full` | yes | 568.09 µs | 1.21x | 1.2x |
| `polkavm64_recompiler_sync_gas` | yes | 569.69 µs | 1.22x | 1.2x |
| `wasmtime_cranelift` | no | 768.97 µs | 1.64x | 1.6x |
| `wasmtime_cranelift_fuel` | yes | 794.62 µs | 1.70x | 1.7x |
| `wasmtime_winch` | no | 1.26 ms | 2.69x | 2.7x |
| `wasmer_singlepass` | no | 5.23 ms | 11.17x | 11.2x |
| `polkavm64_interpreter` | no | 12.00 ms | 25.61x | 25.6x |
| `nub_interp` | yes | 13.61 ms | 29.04x | 29.0x |

### goldilocks-mul

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `nub_jit` | yes | 319.67 µs | 1.00x | 0.9x |
| `native` | no | 346.31 µs | 1.08x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 348.45 µs | 1.09x | 1.0x |
| `polkavm64_recompiler_async_gas` | yes | 384.94 µs | 1.20x | 1.1x |
| `polkavm64_recompiler_async_gas_full` | yes | 385.08 µs | 1.20x | 1.1x |
| `polkavm64_recompiler_sync_gas_full` | yes | 385.11 µs | 1.20x | 1.1x |
| `polkavm64_recompiler_sync_gas` | yes | 385.17 µs | 1.20x | 1.1x |
| `wasmtime_cranelift_fuel` | yes | 520.62 µs | 1.63x | 1.5x |
| `wasmtime_cranelift` | no | 537.11 µs | 1.68x | 1.6x |
| `wasmtime_winch` | no | 555.77 µs | 1.74x | 1.6x |
| `wasmer_singlepass` | no | 1.58 ms | 4.95x | 4.6x |
| `polkavm64_interpreter` | no | 2.44 ms | 7.63x | 7.0x |
| `nub_interp` | yes | 4.19 ms | 13.12x | 12.1x |

### keccak

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 1.75 µs | 1.00x | 1.0x |
| `wasmtime_cranelift_fuel` | yes | 4.55 µs | 2.59x | 2.6x |
| `wasmtime_cranelift` | no | 4.55 µs | 2.60x | 2.6x |
| `wasmtime_winch` | no | 5.07 µs | 2.89x | 2.9x |
| `wasmer_singlepass` | no | 5.94 µs | 3.39x | 3.4x |
| `nub_jit` | yes | 7.24 µs | 4.13x | 4.1x |
| `polkavm64_recompiler_no_gas` | no | 10.03 µs | 5.72x | 5.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 10.83 µs | 6.18x | 6.2x |
| `polkavm64_recompiler_sync_gas_full` | yes | 10.85 µs | 6.19x | 6.2x |
| `polkavm64_recompiler_sync_gas` | yes | 10.90 µs | 6.22x | 6.2x |
| `polkavm64_recompiler_async_gas` | yes | 10.90 µs | 6.22x | 6.2x |
| `polkavm64_interpreter` | no | 114.10 µs | 65.09x | 65.1x |
| `nub_interp` | yes | 258.90 µs | 147.69x | 147.7x |

### mini-verifier

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 246.74 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 485.18 µs | 1.97x | 2.0x |
| `polkavm64_recompiler_async_gas_full` | yes | 581.46 µs | 2.36x | 2.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 582.62 µs | 2.36x | 2.4x |
| `polkavm64_recompiler_no_gas` | no | 583.83 µs | 2.37x | 2.4x |
| `polkavm64_recompiler_async_gas` | yes | 585.08 µs | 2.37x | 2.4x |
| `polkavm64_recompiler_sync_gas` | yes | 587.49 µs | 2.38x | 2.4x |
| `wasmtime_cranelift` | no | 789.30 µs | 3.20x | 3.2x |
| `wasmtime_cranelift_fuel` | yes | 815.06 µs | 3.30x | 3.3x |
| `wasmtime_winch` | no | 1.31 ms | 5.32x | 5.3x |
| `wasmer_singlepass` | no | 4.34 ms | 17.58x | 17.6x |
| `polkavm64_interpreter` | no | 10.86 ms | 44.02x | 44.0x |
| `nub_interp` | yes | 14.18 ms | 57.47x | 57.5x |

### poly-eval

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 687.97 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 1.21 ms | 1.76x | 1.8x |
| `polkavm64_recompiler_sync_gas` | yes | 1.23 ms | 1.79x | 1.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.24 ms | 1.80x | 1.8x |
| `polkavm64_recompiler_async_gas` | yes | 1.28 ms | 1.86x | 1.9x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.29 ms | 1.88x | 1.9x |
| `wasmtime_cranelift_fuel` | yes | 1.53 ms | 2.22x | 2.2x |
| `wasmtime_cranelift` | no | 1.58 ms | 2.29x | 2.3x |
| `nub_jit` | yes | 1.63 ms | 2.37x | 2.4x |
| `wasmtime_winch` | no | 1.73 ms | 2.52x | 2.5x |
| `wasmer_singlepass` | no | 6.00 ms | 8.72x | 8.7x |
| `polkavm64_interpreter` | no | 9.37 ms | 13.62x | 13.6x |
| `nub_interp` | yes | 17.86 ms | 25.96x | 26.0x |

### poseidon2-perm

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 603.50 µs | 1.00x | 1.0x |
| `nub_jit` | yes | 1.21 ms | 2.00x | 2.0x |
| `polkavm64_recompiler_no_gas` | no | 1.40 ms | 2.32x | 2.3x |
| `polkavm64_recompiler_async_gas` | yes | 1.41 ms | 2.33x | 2.3x |
| `polkavm64_recompiler_sync_gas` | yes | 1.41 ms | 2.34x | 2.3x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.41 ms | 2.34x | 2.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.42 ms | 2.35x | 2.3x |
| `wasmtime_cranelift` | no | 1.96 ms | 3.24x | 3.2x |
| `wasmtime_cranelift_fuel` | yes | 2.00 ms | 3.31x | 3.3x |
| `wasmtime_winch` | no | 3.01 ms | 4.99x | 5.0x |
| `wasmer_singlepass` | no | 10.65 ms | 17.64x | 17.6x |
| `polkavm64_interpreter` | no | 24.85 ms | 41.18x | 41.2x |
| `nub_interp` | yes | 35.80 ms | 59.32x | 59.3x |

### prime-sieve

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 57.28 µs | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 96.17 µs | 1.68x | 1.7x |
| `polkavm64_recompiler_no_gas` | no | 114.08 µs | 1.99x | 2.0x |
| `wasmer_singlepass` | no | 133.72 µs | 2.33x | 2.3x |
| `wasmtime_cranelift_fuel` | yes | 166.11 µs | 2.90x | 2.9x |
| `wasmtime_winch` | no | 172.68 µs | 3.01x | 3.0x |
| `polkavm64_recompiler_async_gas_full` | yes | 212.82 µs | 3.72x | 3.7x |
| `polkavm64_recompiler_sync_gas` | yes | 215.38 µs | 3.76x | 3.8x |
| `polkavm64_recompiler_async_gas` | yes | 227.19 µs | 3.97x | 4.0x |
| `polkavm64_recompiler_sync_gas_full` | yes | 228.77 µs | 3.99x | 4.0x |
| `nub_jit` | yes | 285.75 µs | 4.99x | 5.0x |
| `polkavm64_interpreter` | no | 2.15 ms | 37.59x | 37.6x |
| `nub_interp` | yes | 7.46 ms | 130.29x | 130.3x |

## runtime

Steady-state execution: one instance, invoked repeatedly. How fast the engine *executes*, with instantiation excluded.

Rows are absent where a program cannot be re-run in one instance (the three guests with a never-freeing bump arena).

**† — this row still contains per-invocation setup.** nub's invocation model builds a fresh frame and address space on every call by design, so there is no warm state to hoist out. Its figure is therefore *not* comparable to a row that reuses one warm instance; compare it against those rows' `invoke` figures instead, which also pay instantiation.

### blake2b

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 700.0 ns | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 791.0 ns | 1.13x | 1.1x |
| `wasmtime_cranelift_fuel` | yes | 822.0 ns | 1.17x | 1.2x |
| `wasmtime_winch` | no | 1.26 µs | 1.80x | 1.8x |
| `polkavm64_recompiler_no_gas` | no | 1.84 µs | 2.63x | 2.6x |
| `polkavm64_recompiler_sync_gas_full` | yes | 2.39 µs | 3.42x | 3.4x |
| `polkavm64_recompiler_sync_gas` | yes | 2.42 µs | 3.46x | 3.5x |
| `polkavm64_recompiler_async_gas_full` | yes | 2.51 µs | 3.58x | 3.6x |
| `polkavm64_recompiler_async_gas` | yes | 2.52 µs | 3.59x | 3.6x |
| `wasmer_singlepass` | no | 5.03 µs | 7.19x | 7.2x |
| `nub_jit` † | yes | 5.16 µs | 7.37x | 7.4x |
| `polkavm64_interpreter` | no | 50.46 µs | 72.09x | 72.1x |
| `nub_interp` | yes | 158.73 µs | 226.75x | 226.8x |

### ecrecover

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 101.15 µs | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 259.53 µs | 2.57x | 2.6x |
| `wasmtime_cranelift_fuel` | yes | 266.73 µs | 2.64x | 2.6x |
| `wasmtime_winch` | no | 396.71 µs | 3.92x | 3.9x |
| `polkavm64_recompiler_no_gas` | no | 397.38 µs | 3.93x | 3.9x |
| `nub_jit` † | yes | 399.51 µs | 3.95x | 3.9x |
| `polkavm64_recompiler_async_gas` | yes | 442.20 µs | 4.37x | 4.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 444.07 µs | 4.39x | 4.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 457.58 µs | 4.52x | 4.5x |
| `polkavm64_recompiler_sync_gas` | yes | 458.38 µs | 4.53x | 4.5x |
| `wasmer_singlepass` | no | 833.69 µs | 8.24x | 8.2x |
| `polkavm64_interpreter` | no | 12.25 ms | 121.10x | 121.1x |
| `nub_interp` | yes | 27.35 ms | 270.43x | 270.4x |

### ed25519

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 32.65 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 80.78 µs | 2.47x | 2.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 91.00 µs | 2.79x | 2.8x |
| `polkavm64_recompiler_async_gas` | yes | 91.34 µs | 2.80x | 2.8x |
| `polkavm64_recompiler_sync_gas` | yes | 91.38 µs | 2.80x | 2.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 91.43 µs | 2.80x | 2.8x |
| `nub_jit` † | yes | 153.79 µs | 4.71x | 4.7x |
| `wasmtime_cranelift` | no | 196.41 µs | 6.02x | 6.0x |
| `wasmtime_cranelift_fuel` | yes | 240.21 µs | 7.36x | 7.4x |
| `wasmtime_winch` | no | 351.01 µs | 10.75x | 10.8x |
| `wasmer_singlepass` | no | 987.21 µs | 30.23x | 30.2x |
| `polkavm64_interpreter` | no | 1.62 ms | 49.71x | 49.7x |
| `nub_interp` | yes | 4.98 ms | 152.57x | 152.6x |

### fri-fold-tree

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 226.57 µs | 1.00x | 1.0x |
| `nub_jit` † | yes | 470.04 µs | 2.07x | 2.1x |
| `wasmtime_cranelift` | no | 750.51 µs | 3.31x | 3.3x |
| `wasmtime_cranelift_fuel` | yes | 774.13 µs | 3.42x | 3.4x |
| `wasmtime_winch` | no | 1.26 ms | 5.55x | 5.5x |
| `wasmer_singlepass` | no | 3.68 ms | 16.25x | 16.3x |

### goldilocks-mul

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 202.31 µs | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 346.83 µs | 1.71x | 1.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 383.39 µs | 1.90x | 1.9x |
| `polkavm64_recompiler_async_gas` | yes | 383.42 µs | 1.90x | 1.9x |
| `polkavm64_recompiler_sync_gas` | yes | 383.46 µs | 1.90x | 1.9x |
| `polkavm64_recompiler_sync_gas_full` | yes | 392.21 µs | 1.94x | 1.9x |
| `nub_jit` † | yes | 473.89 µs | 2.34x | 2.3x |
| `wasmtime_cranelift_fuel` | yes | 518.24 µs | 2.56x | 2.6x |
| `wasmtime_cranelift` | no | 534.91 µs | 2.64x | 2.6x |
| `wasmtime_winch` | no | 545.23 µs | 2.69x | 2.7x |
| `wasmer_singlepass` | no | 1.51 ms | 7.47x | 7.5x |
| `polkavm64_interpreter` | no | 2.41 ms | 11.90x | 11.9x |
| `nub_interp` | yes | 4.07 ms | 20.10x | 20.1x |

### keccak

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 1.68 µs | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 2.25 µs | 1.34x | 1.3x |
| `wasmtime_cranelift_fuel` | yes | 2.36 µs | 1.41x | 1.4x |
| `wasmtime_winch` | no | 3.14 µs | 1.87x | 1.9x |
| `polkavm64_recompiler_no_gas` | no | 3.16 µs | 1.88x | 1.9x |
| `wasmer_singlepass` | no | 3.80 µs | 2.26x | 2.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 3.92 µs | 2.34x | 2.3x |
| `polkavm64_recompiler_sync_gas` | yes | 3.93 µs | 2.34x | 2.3x |
| `polkavm64_recompiler_async_gas` | yes | 3.94 µs | 2.35x | 2.3x |
| `polkavm64_recompiler_async_gas_full` | yes | 3.95 µs | 2.36x | 2.4x |
| `nub_jit` † | yes | 7.02 µs | 4.19x | 4.2x |
| `polkavm64_interpreter` | no | 84.59 µs | 50.44x | 50.4x |
| `nub_interp` | yes | 241.96 µs | 144.28x | 144.3x |

### mini-verifier

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 234.45 µs | 1.00x | 1.0x |
| `nub_jit` † | yes | 486.82 µs | 2.08x | 2.1x |
| `polkavm64_recompiler_no_gas` | no | 576.24 µs | 2.46x | 2.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 578.11 µs | 2.47x | 2.5x |
| `polkavm64_recompiler_async_gas_full` | yes | 578.19 µs | 2.47x | 2.5x |
| `polkavm64_recompiler_async_gas` | yes | 578.24 µs | 2.47x | 2.5x |
| `polkavm64_recompiler_sync_gas` | yes | 578.65 µs | 2.47x | 2.5x |
| `wasmtime_cranelift` | no | 785.12 µs | 3.35x | 3.3x |
| `wasmtime_cranelift_fuel` | yes | 814.64 µs | 3.47x | 3.5x |
| `wasmtime_winch` | no | 1.35 ms | 5.75x | 5.8x |
| `wasmer_singlepass` | no | 4.04 ms | 17.25x | 17.2x |
| `polkavm64_interpreter` | no | 10.82 ms | 46.13x | 46.1x |
| `nub_interp` | yes | 13.93 ms | 59.40x | 59.4x |

### poly-eval

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 681.25 µs | 1.00x | 1.0x |
| `nub_jit` † | yes | 1.13 ms | 1.66x | 1.7x |
| `wasmtime_cranelift_fuel` | yes | 1.49 ms | 2.18x | 2.2x |
| `wasmtime_cranelift` | no | 1.56 ms | 2.29x | 2.3x |
| `wasmtime_winch` | no | 1.65 ms | 2.42x | 2.4x |
| `wasmer_singlepass` | no | 5.03 ms | 7.39x | 7.4x |

### poseidon2-perm

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `native` | no | 576.30 µs | 1.00x | 1.0x |
| `nub_jit` † | yes | 1.20 ms | 2.07x | 2.1x |
| `polkavm64_recompiler_no_gas` | no | 1.39 ms | 2.41x | 2.4x |
| `polkavm64_recompiler_sync_gas` | yes | 1.40 ms | 2.43x | 2.4x |
| `polkavm64_recompiler_async_gas` | yes | 1.40 ms | 2.43x | 2.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.40 ms | 2.43x | 2.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.40 ms | 2.44x | 2.4x |
| `wasmtime_cranelift` | no | 1.93 ms | 3.35x | 3.4x |
| `wasmtime_cranelift_fuel` | yes | 1.97 ms | 3.42x | 3.4x |
| `wasmtime_winch` | no | 3.22 ms | 5.59x | 5.6x |
| `wasmer_singlepass` | no | 9.99 ms | 17.33x | 17.3x |
| `polkavm64_interpreter` | no | 24.80 ms | 43.03x | 43.0x |
| `nub_interp` | yes | 35.58 ms | 61.73x | 61.7x |

### prime-sieve

| Engine | Metered | Time | vs fastest | vs native |
|---|---|--:|--:|--:|
| `wasmtime_cranelift` | no | 77.16 µs | 1.00x | 0.8x |
| `polkavm64_recompiler_no_gas` | no | 89.92 µs | 1.17x | 0.9x |
| `native` | no | 97.00 µs | 1.26x | 1.0x |
| `wasmer_singlepass` | no | 128.53 µs | 1.67x | 1.3x |
| `wasmtime_cranelift_fuel` | yes | 147.24 µs | 1.91x | 1.5x |
| `wasmtime_winch` | no | 151.75 µs | 1.97x | 1.6x |
| `polkavm64_recompiler_async_gas_full` | yes | 190.42 µs | 2.47x | 2.0x |
| `polkavm64_recompiler_async_gas` | yes | 190.44 µs | 2.47x | 2.0x |
| `polkavm64_recompiler_sync_gas` | yes | 195.55 µs | 2.53x | 2.0x |
| `polkavm64_recompiler_sync_gas_full` | yes | 195.60 µs | 2.54x | 2.0x |
| `nub_jit` † | yes | 283.89 µs | 3.68x | 2.9x |
| `polkavm64_interpreter` | no | 2.15 ms | 27.88x | 22.2x |
| `nub_interp` | yes | 7.49 ms | 97.08x | 77.2x |
