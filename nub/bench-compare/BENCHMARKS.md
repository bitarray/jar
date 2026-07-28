# nub benchmark comparison

## Cold recompile + execute, metered JIT engines

The bench target. Each sample starts with no compiled code and ends with the program having run — the cost a VM pays when a work-package arrives, is turned into native code, and executed once. Metering on.

Storage is deliberately excluded. Getting a blob *into* an engine's object store is dominated by hashing and belongs to a different subsystem than the recompiler; for nub that step is measured separately under `compilation`.

Only cost models comparable to nub's appear here. PolkaVM's default `Simple` model is a flat per-instruction cost and is much cheaper to evaluate than nub's pipeline simulation, so the `*_full` rows (`CacheModel::L2Hit`, whose `memory_access_cost: 25` is exactly nub's `MEM_CYCLES_BASE`) are the like-for-like comparison. Full tables for every engine and every measurement kind follow below.

A cell carries a `±` only when its confidence interval is wider than 2% of the median. Where that happens the cell is a range, not a number, and two engines inside each other's interval are not separable by this measurement.

| Program | `nub_jit` | `polkavm64_recompiler_sync_gas_full` | `polkavm64_recompiler_async_gas_full` | `wasmtime_cranelift_fuel` |
|---|--:|--:|--:|--:|
| blake2b | **63.38 µs** (1.00x) | 116.46 µs (1.84x) | 117.56 µs (1.85x) | 3.45 ms (54.47x) |
| ecrecover | **1.17 ms** (1.00x) | 1.84 ms (1.57x) | 1.83 ms (1.57x) | 43.99 ms (37.73x) |
| prime-sieve | **224.81 µs** (1.00x) | 233.22 µs (1.04x) | 229.32 µs (1.02x) | 1.03 ms (4.58x) |
| mini-verifier | **533.84 µs** (1.00x) | 653.05 µs (1.22x) | 653.06 µs (1.22x) | 3.80 ms (7.11x) |
| keccak | **42.88 µs** (1.00x) | 58.92 µs (1.37x) | 58.52 µs (1.36x) | 2.90 ms (67.62x) |
| fri-fold-tree | **536.58 µs** (1.00x) | 635.05 µs (1.18x) | 640.51 µs (1.19x) | 12.22 ms (22.78x) |
| ed25519 | **496.08 µs** (1.00x) | 651.24 µs (1.31x) | 657.46 µs (1.33x) | 29.85 ms (60.17x) |
| goldilocks-mul | **354.72 µs** (1.00x) | 396.51 µs (1.12x) | 376.00 µs (1.06x) | 1.02 ms (2.87x) |
| poly-eval | **1.13 ms** (1.00x) | 1.22 ms (1.08x) | 1.28 ms (1.13x) | 10.03 ms (8.84x) |
| poseidon2-perm | **1.22 ms** (1.00x) | 1.41 ms (1.16x) | 1.45 ms (1.19x) | 4.31 ms (3.54x) |

Bold = fastest for that program; the multiple is versus it.

### Where that time goes

The same rows with **compilation excluded** — a fresh instance per sample, then execute. Every engine pays instantiation here, so this is like-for-like even for nub, which rebuilds its frame on every call and therefore has no warm state to hoist out.

The bracketed figure is the difference against the table above: what the recompile costs that engine.

| Program | `nub_jit` | `polkavm64_recompiler_sync_gas_full` | `polkavm64_recompiler_async_gas_full` | `wasmtime_cranelift_fuel` |
|---|--:|--:|--:|--:|
| blake2b | 4.55 µs (+58.83 µs recompile) | 9.41 µs (+107.05 µs recompile) | 9.37 µs (+108.19 µs recompile) | 5.50 µs (+3.45 ms recompile) |
| ecrecover | 366.67 µs (+799.26 µs recompile) | 333.25 µs (+1.50 ms recompile) | 333.71 µs (+1.50 ms recompile) | 270.97 µs (+43.72 ms recompile) |
| prime-sieve | 178.70 µs (+46.11 µs recompile) | 200.87 µs (+32.35 µs recompile) | 199.84 µs (+29.48 µs recompile) | 166.44 µs (+863.01 µs recompile) |
| mini-verifier | 465.80 µs (+68.04 µs recompile) | 513.86 µs (+139.19 µs recompile) | 512.66 µs (+140.39 µs recompile) | 799.75 µs (+3.00 ms recompile) |
| keccak | 6.45 µs (+36.43 µs recompile) | 12.28 µs (+46.64 µs recompile) | 12.60 µs (+45.92 µs recompile) | 7.66 µs (+2.89 ms recompile) |
| fri-fold-tree | 451.60 µs (+84.98 µs recompile) | 498.60 µs (+136.45 µs recompile) | 500.64 µs (+139.86 µs recompile) | 771.91 µs (+11.45 ms recompile) |
| ed25519 | 89.99 µs (+406.09 µs recompile) | 100.86 µs (+550.38 µs recompile) | 81.87 µs (+575.59 µs recompile) | 240.79 µs (+29.61 ms recompile) |
| goldilocks-mul | 306.85 µs (+47.87 µs recompile) | 348.86 µs (+47.64 µs recompile) | 365.56 µs (+10.44 µs recompile) | 512.93 µs (+506.37 µs recompile) |
| poly-eval | 1.08 ms (+51.00 µs recompile) | 1.19 ms (+33.79 µs recompile) | 1.27 ms (+11.04 µs recompile) | 1.49 ms (+8.53 ms recompile) |
| poseidon2-perm | 1.15 ms (+63.06 µs recompile) | 1.26 ms (+157.41 µs recompile) | 1.24 ms (+201.23 µs recompile) | 1.94 ms (+2.37 ms recompile) |

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

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 15.42 µs | ±2.3% | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 39.42 µs | ±1.6% | 2.56x | 2.6x |
| `polkavm64_recompiler_async_gas` | yes | 40.54 µs | ±0.8% | 2.63x | 2.6x |
| `polkavm64_recompiler_sync_gas` | yes | 40.55 µs | ±1.2% | 2.63x | 2.6x |
| `nub_jit` | yes | 63.38 µs | ±0.2% | 4.11x | 4.1x |
| `polkavm64_recompiler_sync_gas_full` | yes | 116.46 µs | ±1.5% | 7.55x | 7.6x |
| `polkavm64_recompiler_async_gas_full` | yes | 117.56 µs | ±0.8% | 7.63x | 7.6x |
| `polkavm64_interpreter` | no | 127.04 µs | ±0.3% | 8.24x | 8.2x |
| `nub_interp` | yes | 231.88 µs | ±0.9% | 15.04x | 15.0x |
| `wasmtime_winch` | no | 438.54 µs | ±0.6% | 28.45x | 28.4x |
| `wasmer_singlepass` | no | 2.19 ms | ±1.1% | 142.28x | 142.3x |
| `wasmtime_cranelift` | no | 3.26 ms | ±0.4% | 211.41x | 211.4x |
| `wasmtime_cranelift_fuel` | yes | 3.45 ms | ±0.6% | 223.95x | 224.0x |

### ecrecover

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 110.02 µs | ±0.7% | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 672.41 µs | ±0.4% | 6.11x | 6.1x |
| `polkavm64_recompiler_async_gas` | yes | 705.13 µs | ±1.1% | 6.41x | 6.4x |
| `polkavm64_recompiler_sync_gas` | yes | 734.25 µs | ±0.4% | 6.67x | 6.7x |
| `nub_jit` | yes | 1.17 ms | ±0.4% | 10.60x | 10.6x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.83 ms | ±0.2% | 16.67x | 16.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.84 ms | ±0.6% | 16.68x | 16.7x |
| `wasmtime_winch` | no | 5.37 ms | ±0.5% | 48.81x | 48.8x |
| `wasmer_singlepass` | no | 7.57 ms | ±1.6% | 68.83x | 68.8x |
| `polkavm64_interpreter` | no | 12.35 ms | ±0.7% | 112.26x | 112.3x |
| `nub_interp` | yes | 27.39 ms | ±0.8% | 248.98x | 249.0x |
| `wasmtime_cranelift` | no | 36.16 ms | ±0.5% | 328.65x | 328.7x |
| `wasmtime_cranelift_fuel` | yes | 43.99 ms | ±0.6% | 399.80x | 399.8x |

### ed25519

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 46.20 µs | ±0.4% | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 209.50 µs | ±0.5% | 4.54x | 4.5x |
| `polkavm64_recompiler_async_gas` | yes | 220.75 µs | ±0.5% | 4.78x | 4.8x |
| `polkavm64_recompiler_sync_gas` | yes | 222.28 µs | ±0.6% | 4.81x | 4.8x |
| `nub_jit` | yes | 496.08 µs | ±0.4% | 10.74x | 10.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 651.24 µs | ±0.3% | 14.10x | 14.1x |
| `polkavm64_recompiler_async_gas_full` | yes | 657.46 µs | ±0.3% | 14.23x | 14.2x |
| `polkavm64_interpreter` | no | 1.81 ms | ±0.9% | 39.23x | 39.2x |
| `wasmtime_winch` | no | 3.12 ms | ±0.4% | 67.59x | 67.6x |
| `nub_interp` | yes | 5.25 ms | ±0.6% | 113.66x | 113.7x |
| `wasmer_singlepass` | no | 9.36 ms | ±1.7% | 202.53x | 202.5x |
| `wasmtime_cranelift` | no | 23.93 ms | ±1.0% | 518.02x | 518.0x |
| `wasmtime_cranelift_fuel` | yes | 29.85 ms | ±0.4% | 646.10x | 646.1x |

### fri-fold-tree

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 233.89 µs | ±0.9% | 1.00x | 1.0x |
| `nub_jit` | yes | 536.58 µs | ±0.3% | 2.29x | 2.3x |
| `polkavm64_recompiler_async_gas` | yes | 594.55 µs | ±0.2% | 2.54x | 2.5x |
| `polkavm64_recompiler_no_gas` | no | 598.25 µs | ±0.1% | 2.56x | 2.6x |
| `polkavm64_recompiler_sync_gas` | yes | 598.67 µs | ±0.3% | 2.56x | 2.6x |
| `polkavm64_recompiler_sync_gas_full` | yes | 635.05 µs | ±0.5% | 2.72x | 2.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 640.51 µs | ±0.1% | 2.74x | 2.7x |
| `wasmtime_winch` | no | 2.94 ms | ±0.6% | 12.55x | 12.6x |
| `wasmer_singlepass` | no | 7.79 ms | ±1.1% | 33.29x | 33.3x |
| `wasmtime_cranelift` | no | 8.68 ms | ±0.2% | 37.13x | 37.1x |
| `polkavm64_interpreter` | no | 9.02 ms | ±0.5% | 38.56x | 38.6x |
| `wasmtime_cranelift_fuel` | yes | 12.22 ms | ±0.7% | 52.26x | 52.3x |
| `nub_interp` | yes | 13.59 ms | ±0.8% | 58.09x | 58.1x |

### goldilocks-mul

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 210.41 µs | ±0.6% | 1.00x | 1.0x |
| `nub_jit` | yes | 354.72 µs | ±0.4% | 1.69x | 1.7x |
| `polkavm64_recompiler_no_gas` | no | 358.15 µs | ±0.0% | 1.70x | 1.7x |
| `polkavm64_recompiler_async_gas` | yes | 374.20 µs | ±0.1% | 1.78x | 1.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 376.00 µs | ±0.3% | 1.79x | 1.8x |
| `polkavm64_recompiler_sync_gas` | yes | 394.53 µs | ±0.0% | 1.88x | 1.9x |
| `polkavm64_recompiler_sync_gas_full` | yes | 396.51 µs | ±0.1% | 1.88x | 1.9x |
| `wasmtime_winch` | no | 771.14 µs | ±0.5% | 3.66x | 3.7x |
| `wasmtime_cranelift` | no | 907.49 µs | ±0.4% | 4.31x | 4.3x |
| `wasmtime_cranelift_fuel` | yes | 1.02 ms | ±0.3% | 4.84x | 4.8x |
| `polkavm64_interpreter` | no | 2.07 ms | ±0.5% | 9.84x | 9.8x |
| `wasmer_singlepass` | no | 2.94 ms | ±1.3% | 13.98x | 14.0x |
| `nub_interp` | yes | 3.98 ms | ±0.3% | 18.90x | 18.9x |

### keccak

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 15.94 µs | ±0.6% | 1.00x | 1.0x |
| `polkavm64_recompiler_sync_gas` | yes | 32.35 µs | ±0.5% | 2.03x | 2.0x |
| `polkavm64_recompiler_no_gas` | no | 32.56 µs | ±1.3% | 2.04x | 2.0x |
| `polkavm64_recompiler_async_gas` | yes | 33.73 µs | ±1.0% | 2.12x | 2.1x |
| `nub_jit` | yes | 42.88 µs | ±0.2% | 2.69x | 2.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 58.52 µs | ±0.8% | 3.67x | 3.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 58.92 µs | ±0.6% | 3.70x | 3.7x |
| `polkavm64_interpreter` | no | 99.71 µs | ±0.4% | 6.25x | 6.3x |
| `nub_interp` | yes | 277.46 µs | ±0.7% | 17.40x | 17.4x |
| `wasmtime_winch` | no | 797.19 µs | ±0.5% | 50.01x | 50.0x |
| `wasmer_singlepass` | no | 1.72 ms | ±0.9% | 108.07x | 108.1x |
| `wasmtime_cranelift` | no | 2.14 ms | ±0.3% | 134.36x | 134.4x |
| `wasmtime_cranelift_fuel` | yes | 2.90 ms | ±0.7% | 181.88x | 181.9x |

### mini-verifier

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 243.17 µs | ±0.7% | 1.00x | 1.0x |
| `nub_jit` | yes | 533.84 µs | ±0.2% | 2.20x | 2.2x |
| `polkavm64_recompiler_async_gas` | yes | 601.23 µs | ±0.3% | 2.47x | 2.5x |
| `polkavm64_recompiler_no_gas` | no | 606.04 µs | ±0.2% | 2.49x | 2.5x |
| `polkavm64_recompiler_sync_gas` | yes | 609.31 µs | ±0.3% | 2.51x | 2.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 653.05 µs | ±0.1% | 2.69x | 2.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 653.06 µs | ±0.1% | 2.69x | 2.7x |
| `wasmtime_winch` | no | 1.91 ms | ±0.4% | 7.87x | 7.9x |
| `wasmtime_cranelift` | no | 3.21 ms | ±0.3% | 13.18x | 13.2x |
| `wasmtime_cranelift_fuel` | yes | 3.80 ms | ±0.5% | 15.61x | 15.6x |
| `wasmer_singlepass` | no | 6.46 ms | ±2.9% | 26.55x | 26.6x |
| `polkavm64_interpreter` | no | 9.81 ms | ±1.4% | 40.36x | 40.4x |
| `nub_interp` | yes | 14.06 ms | ±1.4% | 57.80x | 57.8x |

### poly-eval

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 682.54 µs | ±0.8% | 1.00x | 1.0x |
| `nub_jit` | yes | 1.13 ms | ±0.3% | 1.66x | 1.7x |
| `polkavm64_recompiler_sync_gas` | yes | 1.15 ms | ±0.1% | 1.69x | 1.7x |
| `polkavm64_recompiler_async_gas` | yes | 1.21 ms | ±0.5% | 1.78x | 1.8x |
| `polkavm64_recompiler_no_gas` | no | 1.22 ms | ±0.0% | 1.79x | 1.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.22 ms | ±1.1% | 1.79x | 1.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.28 ms | ±0.5% | 1.87x | 1.9x |
| `wasmtime_winch` | no | 3.03 ms | ±0.6% | 4.45x | 4.4x |
| `wasmtime_cranelift` | no | 6.90 ms | ±0.2% | 10.11x | 10.1x |
| `polkavm64_interpreter` | no | 8.06 ms | ±0.6% | 11.81x | 11.8x |
| `wasmer_singlepass` | no | 8.72 ms | ±1.4% | 12.77x | 12.8x |
| `wasmtime_cranelift_fuel` | yes | 10.03 ms | ±0.5% | 14.69x | 14.7x |
| `nub_interp` | yes | 17.58 ms | ±0.4% | 25.76x | 25.8x |

### poseidon2-perm

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 563.68 µs | ±0.6% | 1.00x | 1.0x |
| `nub_jit` | yes | 1.22 ms | ±1.5% | 2.16x | 2.2x |
| `polkavm64_recompiler_no_gas` | no | 1.36 ms | ±0.4% | 2.42x | 2.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.41 ms | ±0.8% | 2.51x | 2.5x |
| `polkavm64_recompiler_sync_gas` | yes | 1.44 ms | ±0.0% | 2.55x | 2.6x |
| `polkavm64_recompiler_async_gas` | yes | 1.44 ms | ±0.0% | 2.56x | 2.6x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.45 ms | ±0.3% | 2.57x | 2.6x |
| `wasmtime_winch` | no | 3.58 ms | ±0.6% | 6.35x | 6.3x |
| `wasmtime_cranelift` | no | 3.92 ms | ±0.5% | 6.95x | 6.9x |
| `wasmtime_cranelift_fuel` | yes | 4.31 ms | ±0.5% | 7.64x | 7.6x |
| `wasmer_singlepass` | no | 12.76 ms | ±1.3% | 22.64x | 22.6x |
| `polkavm64_interpreter` | no | 21.91 ms | ±0.8% | 38.87x | 38.9x |
| `nub_interp` | yes | 35.91 ms | ±0.8% | 63.71x | 63.7x |

### prime-sieve

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 88.97 µs | ±0.5% | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 126.75 µs | ±0.2% | 1.42x | 1.4x |
| `polkavm64_recompiler_async_gas` | yes | 220.70 µs | ±0.5% | 2.48x | 2.5x |
| `nub_jit` | yes | 224.81 µs | ±0.5% | 2.53x | 2.5x |
| `polkavm64_recompiler_sync_gas` | yes | 227.80 µs | ±1.9% | 2.56x | 2.6x |
| `polkavm64_recompiler_async_gas_full` | yes | 229.32 µs | ±1.4% | 2.58x | 2.6x |
| `polkavm64_recompiler_sync_gas_full` | yes | 233.22 µs | ±0.7% | 2.62x | 2.6x |
| `wasmtime_winch` | no | 538.75 µs | ±0.4% | 6.06x | 6.1x |
| `wasmtime_cranelift` | no | 647.74 µs | ±0.7% | 7.28x | 7.3x |
| `wasmtime_cranelift_fuel` | yes | 1.03 ms | ±0.7% | 11.57x | 11.6x |
| `wasmer_singlepass` | no | 1.55 ms | ±1.7% | 17.41x | 17.4x |
| `polkavm64_interpreter` | no | 2.08 ms | ±0.7% | 23.33x | 23.3x |
| `nub_interp` | yes | 7.33 ms | ±0.9% | 82.42x | 82.4x |

## compilation

Turning the program into executable form. Engine construction and file loading are excluded (a once-per-process cost, and the harness's own I/O). `native` is absent: the OS loader already did it.

**`nub_jit` measures publishing here, not codegen** — and publishing is *not* part of the bench target above. nub keeps its object store *inside* the sandbox, so this is the cost of shipping a blob across the VM boundary, decoding it, content-hashing it and materializing its data image. It is dominated by hashing and scales with blob size, not code size. `nub_jit_compile` is the codegen-only figure.

### blake2b

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `polkavm64_interpreter` | no | 17.73 µs | ±0.7% | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 18.69 µs | ±0.5% | 1.05x | - |
| `polkavm64_recompiler_sync_gas` | yes | 18.72 µs | ±0.5% | 1.06x | - |
| `polkavm64_recompiler_async_gas` | yes | 18.77 µs | ±0.7% | 1.06x | - |
| `nub_jit_compile` | yes | 42.99 µs | ±0.4% | 2.43x | - |
| `nub_jit` | yes | 64.23 µs | ±0.4% | 3.62x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 97.37 µs | ±0.4% | 5.49x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 98.13 µs | ±0.4% | 5.54x | - |
| `wasmtime_winch` | no | 423.57 µs | ±0.7% | 23.90x | - |
| `wasmer_singlepass` | no | 1.07 ms | ±1.0% | 60.24x | - |
| `wasmtime_cranelift` | no | 3.26 ms | ±0.5% | 183.76x | - |
| `wasmtime_cranelift_fuel` | yes | 3.45 ms | ±0.4% | 194.53x | - |

### ecrecover

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `polkavm64_interpreter` | no | 194.37 µs | ±0.4% | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 251.95 µs | ±0.3% | 1.30x | - |
| `polkavm64_recompiler_sync_gas` | yes | 263.15 µs | ±0.7% | 1.35x | - |
| `polkavm64_recompiler_async_gas` | yes | 264.58 µs | ±0.5% | 1.36x | - |
| `nub_jit` | yes | 612.95 µs | ±0.7% | 3.15x | - |
| `nub_jit_compile` | yes | 863.23 µs | ±0.4% | 4.44x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 1.34 ms | ±0.5% | 6.89x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.35 ms | ±0.6% | 6.96x | - |
| `wasmer_singlepass` | no | 3.62 ms | ±1.1% | 18.63x | - |
| `wasmtime_winch` | no | 4.89 ms | ±0.6% | 25.17x | - |
| `wasmtime_cranelift` | no | 35.17 ms | ±0.7% | 180.96x | - |
| `wasmtime_cranelift_fuel` | yes | 43.73 ms | ±0.3% | 224.97x | - |

### ed25519

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `polkavm64_interpreter` | no | 82.30 µs | ±0.5% | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 110.74 µs | ±0.4% | 1.35x | - |
| `polkavm64_recompiler_async_gas` | yes | 111.68 µs | ±0.4% | 1.36x | - |
| `polkavm64_recompiler_sync_gas` | yes | 112.85 µs | ±0.8% | 1.37x | - |
| `nub_jit` | yes | 277.45 µs | ±0.2% | 3.37x | - |
| `nub_jit_compile` | yes | 355.71 µs | ±0.2% | 4.32x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 522.36 µs | ±0.4% | 6.35x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 529.25 µs | ±0.5% | 6.43x | - |
| `wasmtime_winch` | no | 2.81 ms | ±0.4% | 34.11x | - |
| `wasmer_singlepass` | no | 4.84 ms | ±0.9% | 58.80x | - |
| `wasmtime_cranelift` | no | 23.75 ms | ±0.4% | 288.62x | - |
| `wasmtime_cranelift_fuel` | yes | 29.86 ms | ±0.3% | 362.87x | - |

### fri-fold-tree

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `polkavm64_interpreter` | no | 9.90 µs | ±0.4% | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 11.09 µs | ±0.8% | 1.12x | - |
| `polkavm64_recompiler_sync_gas` | yes | 11.36 µs | ±0.9% | 1.15x | - |
| `polkavm64_recompiler_async_gas` | yes | 11.68 µs | ±0.4% | 1.18x | - |
| `nub_jit_compile` | yes | 26.64 µs | ±0.7% | 2.69x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 53.83 µs | ±0.3% | 5.44x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 54.34 µs | ±0.3% | 5.49x | - |
| `nub_jit` | yes | 70.18 µs | ±0.6% | 7.09x | - |
| `wasmer_singlepass` | no | 1.49 ms | ±0.9% | 150.09x | - |
| `wasmtime_winch` | no | 1.65 ms | ±0.3% | 167.14x | - |
| `wasmtime_cranelift` | no | 8.10 ms | ±0.4% | 818.37x | - |
| `wasmtime_cranelift_fuel` | yes | 11.50 ms | ±0.3% | 1161.45x | - |

### goldilocks-mul

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `polkavm64_interpreter` | no | 350.2 ns | ±0.7% | 1.00x | - |
| `nub_jit_compile` | yes | 1.06 µs | ±0.2% | 3.01x | - |
| `polkavm64_recompiler_no_gas` | no | 1.52 µs | ±0.6% | 4.33x | - |
| `polkavm64_recompiler_sync_gas` | yes | 1.55 µs | ±0.3% | 4.41x | - |
| `polkavm64_recompiler_async_gas` | yes | 1.58 µs | ±0.5% | 4.50x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 3.19 µs | ±0.5% | 9.11x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 3.20 µs | ±0.5% | 9.12x | - |
| `nub_jit` | yes | 23.90 µs | ±0.6% | 68.23x | - |
| `wasmtime_winch` | no | 205.22 µs | ±0.7% | 586.01x | - |
| `wasmtime_cranelift` | no | 367.33 µs | ±0.8% | 1048.90x | - |
| `wasmtime_cranelift_fuel` | yes | 490.23 µs | ±0.7% | 1399.86x | - |
| `wasmer_singlepass` | no | 651.59 µs | ±2.5% | 1860.63x | - |

### keccak

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `polkavm64_interpreter` | no | 6.65 µs | ±0.6% | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 7.37 µs | ±0.6% | 1.11x | - |
| `polkavm64_recompiler_async_gas` | yes | 7.52 µs | ±0.4% | 1.13x | - |
| `polkavm64_recompiler_sync_gas` | yes | 7.52 µs | ±0.2% | 1.13x | - |
| `nub_jit_compile` | yes | 9.28 µs | ±0.5% | 1.40x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 33.29 µs | ±0.1% | 5.00x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 33.46 µs | ±0.5% | 5.03x | - |
| `nub_jit` | yes | 34.55 µs | ±0.2% | 5.20x | - |
| `wasmtime_winch` | no | 764.93 µs | ±0.6% | 115.02x | - |
| `wasmer_singlepass` | no | 828.53 µs | ±1.3% | 124.58x | - |
| `wasmtime_cranelift` | no | 2.13 ms | ±0.6% | 320.06x | - |
| `wasmtime_cranelift_fuel` | yes | 2.83 ms | ±0.5% | 426.09x | - |

### mini-verifier

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `polkavm64_interpreter` | no | 9.39 µs | ±0.5% | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 10.08 µs | ±0.5% | 1.07x | - |
| `polkavm64_recompiler_sync_gas` | yes | 10.32 µs | ±0.4% | 1.10x | - |
| `polkavm64_recompiler_async_gas` | yes | 10.40 µs | ±0.6% | 1.11x | - |
| `nub_jit_compile` | yes | 26.72 µs | ±0.4% | 2.84x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 50.50 µs | ±0.4% | 5.38x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 51.02 µs | ±0.4% | 5.43x | - |
| `nub_jit` | yes | 53.40 µs | ±0.3% | 5.68x | - |
| `wasmtime_winch` | no | 561.95 µs | ±0.6% | 59.82x | - |
| `wasmer_singlepass` | no | 926.06 µs | ±1.3% | 98.57x | - |
| `wasmtime_cranelift` | no | 2.44 ms | ±0.7% | 259.75x | - |
| `wasmtime_cranelift_fuel` | yes | 3.00 ms | ±0.5% | 319.55x | - |

### poly-eval

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `polkavm64_interpreter` | no | 1.72 µs | ±0.6% | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 3.00 µs | ±0.9% | 1.75x | - |
| `polkavm64_recompiler_async_gas` | yes | 3.06 µs | ±0.3% | 1.79x | - |
| `polkavm64_recompiler_sync_gas` | yes | 3.10 µs | ±0.3% | 1.81x | - |
| `nub_jit_compile` | yes | 8.34 µs | ±0.5% | 4.86x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 11.01 µs | ±0.5% | 6.42x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 11.11 µs | ±0.7% | 6.48x | - |
| `nub_jit` | yes | 31.60 µs | ±0.4% | 18.43x | - |
| `wasmtime_winch` | no | 1.29 ms | ±0.5% | 749.39x | - |
| `wasmer_singlepass` | no | 1.40 ms | ±1.0% | 814.00x | - |
| `wasmtime_cranelift` | no | 5.34 ms | ±0.3% | 3112.50x | - |
| `wasmtime_cranelift_fuel` | yes | 8.37 ms | ±0.4% | 4879.57x | - |

### poseidon2-perm

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `polkavm64_interpreter` | no | 7.49 µs | ±0.9% | 1.00x | - |
| `polkavm64_recompiler_sync_gas` | yes | 8.04 µs | ±0.3% | 1.07x | - |
| `polkavm64_recompiler_no_gas` | no | 8.10 µs | ±0.6% | 1.08x | - |
| `polkavm64_recompiler_async_gas` | yes | 8.29 µs | ±0.6% | 1.11x | - |
| `nub_jit_compile` | yes | 22.21 µs | ±0.3% | 2.97x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 37.24 µs | ±0.5% | 4.97x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 37.47 µs | ±0.5% | 5.00x | - |
| `nub_jit` | yes | 47.49 µs | ±0.3% | 6.34x | - |
| `wasmtime_winch` | no | 468.52 µs | ±0.6% | 62.55x | - |
| `wasmer_singlepass` | no | 914.23 µs | ±2.4% | 122.06x | - |
| `wasmtime_cranelift` | no | 1.98 ms | ±0.5% | 265.01x | - |
| `wasmtime_cranelift_fuel` | yes | 2.44 ms | ±0.4% | 325.81x | - |

### prime-sieve

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `polkavm64_interpreter` | no | 1.81 µs | ±0.6% | 1.00x | - |
| `nub_jit_compile` | yes | 3.43 µs | ±0.5% | 1.90x | - |
| `polkavm64_recompiler_no_gas` | no | 4.72 µs | ±0.5% | 2.61x | - |
| `polkavm64_recompiler_sync_gas` | yes | 4.80 µs | ±1.0% | 2.65x | - |
| `polkavm64_recompiler_async_gas` | yes | 4.81 µs | ±0.8% | 2.66x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 6.96 µs | ±0.5% | 3.85x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 7.03 µs | ±0.8% | 3.89x | - |
| `wasmtime_winch` | no | 323.19 µs | ±0.6% | 178.91x | - |
| `wasmtime_cranelift` | no | 484.64 µs | ±0.8% | 268.28x | - |
| `nub_jit` | yes | 485.97 µs | ±0.4% | 269.02x | - |
| `wasmer_singlepass` | no | 725.79 µs | ±1.9% | 401.78x | - |
| `wasmtime_cranelift_fuel` | yes | 800.52 µs | ±0.5% | 443.14x | - |

## invoke

Cold invocation with compilation excluded: a fresh instance every sample. Where an engine's *instantiation* strategy shows up. Compare against `runtime` for the same row to see what a cold start costs it.

### blake2b

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 632.8 ns | ±0.3% | 1.00x | 1.0x |
| `nub_jit` | yes | 4.55 µs | ±0.3% | 7.20x | 7.2x |
| `wasmtime_cranelift` | no | 5.46 µs | ±0.7% | 8.64x | 8.6x |
| `wasmtime_cranelift_fuel` | yes | 5.50 µs | ±1.0% | 8.70x | 8.7x |
| `wasmtime_winch` | no | 6.02 µs | ±0.5% | 9.51x | 9.5x |
| `polkavm64_recompiler_no_gas` | no | 8.83 µs | ±0.5% | 13.95x | 13.9x |
| `polkavm64_recompiler_async_gas_full` | yes | 9.37 µs | ±1.0% | 14.81x | 14.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 9.41 µs | ±0.9% | 14.87x | 14.9x |
| `polkavm64_recompiler_async_gas` | yes | 9.65 µs | ±1.3% | 15.25x | 15.2x |
| `polkavm64_recompiler_sync_gas` | yes | 9.79 µs | ±1.0% | 15.47x | 15.5x |
| `wasmer_singlepass` | no | 45.08 µs | ±4.2% | 71.24x | 71.2x |
| `polkavm64_interpreter` | no | 103.17 µs | ±1.1% | 163.04x | 163.0x |
| `nub_interp` | yes | 152.07 µs | ±1.2% | 240.31x | 240.3x |

### ecrecover

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 91.28 µs | ±0.1% | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 258.28 µs | ±0.5% | 2.83x | 2.8x |
| `wasmtime_cranelift_fuel` | yes | 270.97 µs | ±0.5% | 2.97x | 3.0x |
| `polkavm64_recompiler_no_gas` | no | 319.06 µs | ±0.1% | 3.50x | 3.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 333.25 µs | ±0.1% | 3.65x | 3.7x |
| `polkavm64_recompiler_async_gas` | yes | 333.40 µs | ±0.1% | 3.65x | 3.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 333.71 µs | ±0.1% | 3.66x | 3.7x |
| `polkavm64_recompiler_sync_gas` | yes | 333.86 µs | ±0.1% | 3.66x | 3.7x |
| `nub_jit` | yes | 366.67 µs | ±0.2% | 4.02x | 4.0x |
| `wasmtime_winch` | no | 386.51 µs | ±0.5% | 4.23x | 4.2x |
| `wasmer_singlepass` | no | 1.14 ms | ±2.8% | 12.52x | 12.5x |
| `polkavm64_interpreter` | no | 12.14 ms | ±0.6% | 132.95x | 132.9x |
| `nub_interp` | yes | 26.51 ms | ±0.9% | 290.48x | 290.5x |

### ed25519

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 29.35 µs | ±0.6% | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 74.26 µs | ±0.2% | 2.53x | 2.5x |
| `polkavm64_recompiler_async_gas_full` | yes | 81.87 µs | ±0.1% | 2.79x | 2.8x |
| `polkavm64_recompiler_async_gas` | yes | 81.96 µs | ±0.2% | 2.79x | 2.8x |
| `polkavm64_recompiler_sync_gas` | yes | 82.37 µs | ±0.1% | 2.81x | 2.8x |
| `nub_jit` | yes | 89.99 µs | ±0.2% | 3.07x | 3.1x |
| `polkavm64_recompiler_sync_gas_full` | yes | 100.86 µs | ±0.1% | 3.44x | 3.4x |
| `wasmtime_cranelift` | no | 196.13 µs | ±0.9% | 6.68x | 6.7x |
| `wasmtime_cranelift_fuel` | yes | 240.79 µs | ±0.4% | 8.20x | 8.2x |
| `wasmtime_winch` | no | 348.38 µs | ±0.5% | 11.87x | 11.9x |
| `wasmer_singlepass` | no | 1.29 ms | ±1.5% | 43.90x | 43.9x |
| `polkavm64_interpreter` | no | 1.76 ms | ±0.3% | 60.03x | 60.0x |
| `nub_interp` | yes | 4.91 ms | ±0.7% | 167.20x | 167.2x |

### fri-fold-tree

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 220.96 µs | ±0.3% | 1.00x | 1.0x |
| `nub_jit` | yes | 451.60 µs | ±0.4% | 2.04x | 2.0x |
| `polkavm64_recompiler_async_gas` | yes | 498.03 µs | ±0.1% | 2.25x | 2.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 498.60 µs | ±0.1% | 2.26x | 2.3x |
| `polkavm64_recompiler_no_gas` | no | 498.91 µs | ±0.1% | 2.26x | 2.3x |
| `polkavm64_recompiler_async_gas_full` | yes | 500.64 µs | ±0.1% | 2.27x | 2.3x |
| `polkavm64_recompiler_sync_gas` | yes | 500.75 µs | ±0.3% | 2.27x | 2.3x |
| `wasmtime_cranelift` | no | 751.15 µs | ±0.6% | 3.40x | 3.4x |
| `wasmtime_cranelift_fuel` | yes | 771.91 µs | ±0.3% | 3.49x | 3.5x |
| `wasmtime_winch` | no | 1.26 ms | ±0.5% | 5.69x | 5.7x |
| `wasmer_singlepass` | no | 4.62 ms | ±1.2% | 20.90x | 20.9x |
| `polkavm64_interpreter` | no | 8.90 ms | ±0.8% | 40.26x | 40.3x |
| `nub_interp` | yes | 13.48 ms | ±1.1% | 60.99x | 61.0x |

### goldilocks-mul

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 197.02 µs | ±0.7% | 1.00x | 1.0x |
| `nub_jit` | yes | 306.85 µs | ±0.3% | 1.56x | 1.6x |
| `polkavm64_recompiler_no_gas` | no | 331.72 µs | ±0.1% | 1.68x | 1.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 348.86 µs | ±0.0% | 1.77x | 1.8x |
| `polkavm64_recompiler_sync_gas` | yes | 349.02 µs | ±0.1% | 1.77x | 1.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 365.56 µs | ±0.1% | 1.86x | 1.9x |
| `polkavm64_recompiler_async_gas` | yes | 365.66 µs | ±0.1% | 1.86x | 1.9x |
| `wasmtime_cranelift_fuel` | yes | 512.93 µs | ±0.8% | 2.60x | 2.6x |
| `wasmtime_cranelift` | no | 519.76 µs | ±0.5% | 2.64x | 2.6x |
| `wasmtime_winch` | no | 548.89 µs | ±0.7% | 2.79x | 2.8x |
| `wasmer_singlepass` | no | 1.64 ms | ±1.1% | 8.32x | 8.3x |
| `polkavm64_interpreter` | no | 2.07 ms | ±0.8% | 10.49x | 10.5x |
| `nub_interp` | yes | 3.92 ms | ±0.9% | 19.90x | 19.9x |

### keccak

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 1.63 µs | ±0.5% | 1.00x | 1.0x |
| `nub_jit` | yes | 6.45 µs | ±0.2% | 3.96x | 4.0x |
| `wasmtime_cranelift` | no | 7.52 µs | ±1.0% | 4.62x | 4.6x |
| `wasmtime_cranelift_fuel` | yes | 7.66 µs | ±0.8% | 4.71x | 4.7x |
| `wasmtime_winch` | no | 8.20 µs | ±0.7% | 5.03x | 5.0x |
| `polkavm64_recompiler_no_gas` | no | 10.16 µs | ±8.1% | 6.24x | 6.2x |
| `polkavm64_recompiler_async_gas` | yes | 10.49 µs | ±2.9% | 6.45x | 6.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 12.28 µs | ±1.0% | 7.54x | 7.5x |
| `polkavm64_recompiler_sync_gas` | yes | 12.41 µs | ±1.7% | 7.62x | 7.6x |
| `polkavm64_recompiler_async_gas_full` | yes | 12.60 µs | ±1.1% | 7.74x | 7.7x |
| `wasmer_singlepass` | no | 27.91 µs | ±2.8% | 17.14x | 17.1x |
| `polkavm64_interpreter` | no | 91.09 µs | ±0.8% | 55.94x | 55.9x |
| `nub_interp` | yes | 236.59 µs | ±0.8% | 145.31x | 145.3x |

### mini-verifier

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 224.18 µs | ±0.4% | 1.00x | 1.0x |
| `nub_jit` | yes | 465.80 µs | ±0.4% | 2.08x | 2.1x |
| `polkavm64_recompiler_no_gas` | no | 512.13 µs | ±0.1% | 2.28x | 2.3x |
| `polkavm64_recompiler_async_gas_full` | yes | 512.66 µs | ±0.1% | 2.29x | 2.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 513.86 µs | ±0.1% | 2.29x | 2.3x |
| `polkavm64_recompiler_sync_gas` | yes | 584.37 µs | ±0.0% | 2.61x | 2.6x |
| `polkavm64_recompiler_async_gas` | yes | 584.55 µs | ±0.0% | 2.61x | 2.6x |
| `wasmtime_cranelift` | no | 767.06 µs | ±0.6% | 3.42x | 3.4x |
| `wasmtime_cranelift_fuel` | yes | 799.75 µs | ±0.6% | 3.57x | 3.6x |
| `wasmtime_winch` | no | 1.27 ms | ±0.3% | 5.67x | 5.7x |
| `wasmer_singlepass` | no | 4.38 ms | ±1.3% | 19.56x | 19.6x |
| `polkavm64_interpreter` | no | 9.65 ms | ±0.6% | 43.03x | 43.0x |
| `nub_interp` | yes | 14.07 ms | ±0.6% | 62.77x | 62.8x |

### poly-eval

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 652.51 µs | ±0.3% | 1.00x | 1.0x |
| `nub_jit` | yes | 1.08 ms | ±0.2% | 1.66x | 1.7x |
| `polkavm64_recompiler_no_gas` | no | 1.18 ms | ±0.5% | 1.82x | 1.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.19 ms | ±0.8% | 1.82x | 1.8x |
| `polkavm64_recompiler_async_gas` | yes | 1.21 ms | ±1.4% | 1.86x | 1.9x |
| `polkavm64_recompiler_sync_gas` | yes | 1.22 ms | ±0.4% | 1.87x | 1.9x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.27 ms | ±0.2% | 1.94x | 1.9x |
| `wasmtime_cranelift_fuel` | yes | 1.49 ms | ±0.4% | 2.29x | 2.3x |
| `wasmtime_cranelift` | no | 1.54 ms | ±0.3% | 2.35x | 2.4x |
| `wasmtime_winch` | no | 1.70 ms | ±0.5% | 2.61x | 2.6x |
| `wasmer_singlepass` | no | 5.70 ms | ±1.0% | 8.74x | 8.7x |
| `polkavm64_interpreter` | no | 8.03 ms | ±0.8% | 12.30x | 12.3x |
| `nub_interp` | yes | 17.41 ms | ±0.6% | 26.69x | 26.7x |

### poseidon2-perm

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 547.82 µs | ±0.5% | 1.00x | 1.0x |
| `nub_jit` | yes | 1.15 ms | ±0.2% | 2.10x | 2.1x |
| `polkavm64_recompiler_no_gas` | no | 1.24 ms | ±0.1% | 2.27x | 2.3x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.24 ms | ±0.1% | 2.27x | 2.3x |
| `polkavm64_recompiler_async_gas` | yes | 1.25 ms | ±0.2% | 2.27x | 2.3x |
| `polkavm64_recompiler_sync_gas` | yes | 1.25 ms | ±0.0% | 2.29x | 2.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.26 ms | ±0.2% | 2.29x | 2.3x |
| `wasmtime_cranelift` | no | 1.87 ms | ±0.5% | 3.42x | 3.4x |
| `wasmtime_cranelift_fuel` | yes | 1.94 ms | ±0.3% | 3.53x | 3.5x |
| `wasmtime_winch` | no | 3.26 ms | ±0.4% | 5.95x | 6.0x |
| `wasmer_singlepass` | no | 10.62 ms | ±0.2% | 19.38x | 19.4x |
| `polkavm64_interpreter` | no | 22.19 ms | ±0.9% | 40.50x | 40.5x |
| `nub_interp` | yes | 36.16 ms | ±0.2% | 66.00x | 66.0x |

### prime-sieve

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 54.77 µs | ±0.3% | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 112.84 µs | ±0.2% | 2.06x | 2.1x |
| `wasmtime_cranelift` | no | 115.48 µs | ±0.8% | 2.11x | 2.1x |
| `wasmer_singlepass` | no | 159.18 µs | ±2.1% | 2.91x | 2.9x |
| `wasmtime_cranelift_fuel` | yes | 166.44 µs | ±0.3% | 3.04x | 3.0x |
| `wasmtime_winch` | no | 171.25 µs | ±0.5% | 3.13x | 3.1x |
| `nub_jit` | yes | 178.70 µs | ±0.6% | 3.26x | 3.3x |
| `polkavm64_recompiler_async_gas_full` | yes | 199.84 µs | ±0.1% | 3.65x | 3.6x |
| `polkavm64_recompiler_async_gas` | yes | 200.15 µs | ±0.1% | 3.65x | 3.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 200.87 µs | ±0.1% | 3.67x | 3.7x |
| `polkavm64_recompiler_sync_gas` | yes | 216.14 µs | ±0.0% | 3.95x | 3.9x |
| `polkavm64_interpreter` | no | 2.07 ms | ±0.7% | 37.75x | 37.7x |
| `nub_interp` | yes | 7.31 ms | ±1.0% | 133.46x | 133.5x |

## runtime

Steady-state execution: one instance, invoked repeatedly. How fast the engine *executes*, with instantiation excluded.

Rows are absent where a program cannot be re-run in one instance (the three guests with a never-freeing bump arena).

**† — this row still contains per-invocation setup.** nub's invocation model builds a fresh frame and address space on every call by design, so there is no warm state to hoist out. Its figure is therefore *not* comparable to a row that reuses one warm instance; compare it against those rows' `invoke` figures instead, which also pay instantiation.

### blake2b

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 624.3 ns | ±0.5% | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 751.1 ns | ±0.3% | 1.20x | 1.2x |
| `wasmtime_cranelift_fuel` | yes | 781.1 ns | ±0.5% | 1.25x | 1.3x |
| `wasmtime_winch` | no | 1.21 µs | ±0.5% | 1.94x | 1.9x |
| `polkavm64_recompiler_no_gas` | no | 1.41 µs | ±0.2% | 2.25x | 2.3x |
| `polkavm64_recompiler_async_gas_full` | yes | 2.13 µs | ±0.3% | 3.41x | 3.4x |
| `polkavm64_recompiler_async_gas` | yes | 2.20 µs | ±0.3% | 3.53x | 3.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 2.43 µs | ±0.3% | 3.89x | 3.9x |
| `polkavm64_recompiler_sync_gas` | yes | 2.50 µs | ±0.0% | 4.01x | 4.0x |
| `nub_jit` † | yes | 4.54 µs | ±0.3% | 7.28x | 7.3x |
| `wasmer_singlepass` | no | 4.68 µs | ±0.9% | 7.50x | 7.5x |
| `polkavm64_interpreter` | no | 40.07 µs | ±0.7% | 64.18x | 64.2x |
| `nub_interp` | yes | 138.84 µs | ±0.7% | 222.39x | 222.4x |

### ecrecover

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 93.15 µs | ±0.5% | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 248.56 µs | ±0.3% | 2.67x | 2.7x |
| `wasmtime_cranelift_fuel` | yes | 261.53 µs | ±0.4% | 2.81x | 2.8x |
| `polkavm64_recompiler_no_gas` | no | 308.29 µs | ±0.1% | 3.31x | 3.3x |
| `polkavm64_recompiler_sync_gas` | yes | 320.54 µs | ±0.1% | 3.44x | 3.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 323.33 µs | ±0.1% | 3.47x | 3.5x |
| `polkavm64_recompiler_async_gas` | yes | 323.45 µs | ±0.1% | 3.47x | 3.5x |
| `nub_jit` † | yes | 369.12 µs | ±0.4% | 3.96x | 4.0x |
| `wasmtime_winch` | no | 379.85 µs | ±0.6% | 4.08x | 4.1x |
| `polkavm64_recompiler_sync_gas_full` | yes | 461.33 µs | ±0.0% | 4.95x | 5.0x |
| `wasmer_singlepass` | no | 748.07 µs | ±0.4% | 8.03x | 8.0x |
| `polkavm64_interpreter` | no | 11.41 ms | ±0.7% | 122.49x | 122.5x |
| `nub_interp` | yes | 26.65 ms | ±1.2% | 286.14x | 286.1x |

### ed25519

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 29.50 µs | ±0.5% | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 65.65 µs | ±0.1% | 2.23x | 2.2x |
| `polkavm64_recompiler_async_gas_full` | yes | 73.48 µs | ±0.1% | 2.49x | 2.5x |
| `polkavm64_recompiler_async_gas` | yes | 73.66 µs | ±0.2% | 2.50x | 2.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 73.83 µs | ±0.1% | 2.50x | 2.5x |
| `polkavm64_recompiler_sync_gas` | yes | 73.91 µs | ±0.2% | 2.51x | 2.5x |
| `nub_jit` † | yes | 89.37 µs | ±0.3% | 3.03x | 3.0x |
| `wasmtime_cranelift` | no | 189.07 µs | ±0.3% | 6.41x | 6.4x |
| `wasmtime_cranelift_fuel` | yes | 232.99 µs | ±0.4% | 7.90x | 7.9x |
| `wasmtime_winch` | no | 341.09 µs | ±0.6% | 11.56x | 11.6x |
| `wasmer_singlepass` | no | 893.54 µs | ±0.3% | 30.29x | 30.3x |
| `polkavm64_interpreter` | no | 1.46 ms | ±1.0% | 49.47x | 49.5x |
| `nub_interp` | yes | 4.82 ms | ±0.7% | 163.25x | 163.3x |

### fri-fold-tree

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 219.38 µs | ±0.5% | 1.00x | 1.0x |
| `nub_jit` † | yes | 454.22 µs | ±0.5% | 2.07x | 2.1x |
| `wasmtime_cranelift` | no | 722.91 µs | ±0.4% | 3.30x | 3.3x |
| `wasmtime_cranelift_fuel` | yes | 752.82 µs | ±0.4% | 3.43x | 3.4x |
| `wasmtime_winch` | no | 1.19 ms | ±0.7% | 5.44x | 5.4x |
| `wasmer_singlepass` | no | 3.58 ms | ±0.6% | 16.30x | 16.3x |

### goldilocks-mul

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 196.35 µs | ±0.6% | 1.00x | 1.0x |
| `nub_jit` † | yes | 312.95 µs | ±0.3% | 1.59x | 1.6x |
| `polkavm64_recompiler_no_gas` | no | 330.54 µs | ±0.2% | 1.68x | 1.7x |
| `polkavm64_recompiler_sync_gas` | yes | 346.15 µs | ±0.1% | 1.76x | 1.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 346.50 µs | ±0.1% | 1.76x | 1.8x |
| `polkavm64_recompiler_async_gas` | yes | 358.19 µs | ±0.2% | 1.82x | 1.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 358.92 µs | ±0.1% | 1.83x | 1.8x |
| `wasmtime_cranelift_fuel` | yes | 509.51 µs | ±0.7% | 2.59x | 2.6x |
| `wasmtime_cranelift` | no | 512.78 µs | ±0.6% | 2.61x | 2.6x |
| `wasmtime_winch` | no | 528.81 µs | ±0.5% | 2.69x | 2.7x |
| `wasmer_singlepass` | no | 1.43 ms | ±0.5% | 7.27x | 7.3x |
| `polkavm64_interpreter` | no | 2.08 ms | ±0.8% | 10.58x | 10.6x |
| `nub_interp` | yes | 3.99 ms | ±0.8% | 20.30x | 20.3x |

### keccak

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 1.62 µs | ±0.4% | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 2.16 µs | ±0.3% | 1.33x | 1.3x |
| `wasmtime_cranelift_fuel` | yes | 2.24 µs | ±0.3% | 1.38x | 1.4x |
| `polkavm64_recompiler_no_gas` | no | 2.38 µs | ±0.3% | 1.47x | 1.5x |
| `wasmtime_winch` | no | 2.62 µs | ±0.7% | 1.62x | 1.6x |
| `wasmer_singlepass` | no | 3.41 µs | ±0.5% | 2.11x | 2.1x |
| `polkavm64_recompiler_sync_gas` | yes | 3.49 µs | ±0.2% | 2.16x | 2.2x |
| `polkavm64_recompiler_async_gas_full` | yes | 3.51 µs | ±0.3% | 2.17x | 2.2x |
| `polkavm64_recompiler_sync_gas_full` | yes | 3.54 µs | ±0.3% | 2.19x | 2.2x |
| `polkavm64_recompiler_async_gas` | yes | 3.55 µs | ±0.2% | 2.19x | 2.2x |
| `nub_jit` † | yes | 6.55 µs | ±0.4% | 4.05x | 4.0x |
| `polkavm64_interpreter` | no | 71.64 µs | ±0.5% | 44.25x | 44.2x |
| `nub_interp` | yes | 230.32 µs | ±1.2% | 142.25x | 142.3x |

### mini-verifier

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 228.68 µs | ±0.5% | 1.00x | 1.0x |
| `nub_jit` † | yes | 470.01 µs | ±0.6% | 2.06x | 2.1x |
| `polkavm64_recompiler_async_gas_full` | yes | 507.32 µs | ±0.1% | 2.22x | 2.2x |
| `polkavm64_recompiler_sync_gas_full` | yes | 507.52 µs | ±0.1% | 2.22x | 2.2x |
| `polkavm64_recompiler_no_gas` | no | 507.53 µs | ±0.1% | 2.22x | 2.2x |
| `polkavm64_recompiler_async_gas` | yes | 507.58 µs | ±0.1% | 2.22x | 2.2x |
| `polkavm64_recompiler_sync_gas` | yes | 578.45 µs | ±0.0% | 2.53x | 2.5x |
| `wasmtime_cranelift` | no | 767.20 µs | ±0.4% | 3.35x | 3.4x |
| `wasmtime_cranelift_fuel` | yes | 789.91 µs | ±0.4% | 3.45x | 3.5x |
| `wasmtime_winch` | no | 1.23 ms | ±0.5% | 5.36x | 5.4x |
| `wasmer_singlepass` | no | 3.95 ms | ±0.5% | 17.27x | 17.3x |
| `polkavm64_interpreter` | no | 9.65 ms | ±0.4% | 42.19x | 42.2x |
| `nub_interp` | yes | 14.03 ms | ±1.0% | 61.35x | 61.3x |

### poly-eval

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 664.86 µs | ±0.6% | 1.00x | 1.0x |
| `nub_jit` † | yes | 1.09 ms | ±0.7% | 1.64x | 1.6x |
| `wasmtime_cranelift_fuel` | yes | 1.47 ms | ±0.4% | 2.21x | 2.2x |
| `wasmtime_cranelift` | no | 1.51 ms | ±0.5% | 2.28x | 2.3x |
| `wasmtime_winch` | no | 1.66 ms | ±0.6% | 2.50x | 2.5x |
| `wasmer_singlepass` | no | 4.89 ms | ±0.6% | 7.36x | 7.4x |

### poseidon2-perm

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 560.49 µs | ±0.4% | 1.00x | 1.0x |
| `nub_jit` † | yes | 1.18 ms | ±0.4% | 2.10x | 2.1x |
| `polkavm64_recompiler_no_gas` | no | 1.24 ms | ±0.1% | 2.22x | 2.2x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.24 ms | ±0.1% | 2.22x | 2.2x |
| `polkavm64_recompiler_async_gas` | yes | 1.25 ms | ±0.1% | 2.22x | 2.2x |
| `polkavm64_recompiler_sync_gas` | yes | 1.25 ms | ±0.1% | 2.23x | 2.2x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.25 ms | ±0.1% | 2.23x | 2.2x |
| `wasmtime_cranelift` | no | 1.86 ms | ±0.3% | 3.32x | 3.3x |
| `wasmtime_cranelift_fuel` | yes | 1.92 ms | ±0.4% | 3.43x | 3.4x |
| `wasmtime_winch` | no | 3.27 ms | ±0.6% | 5.83x | 5.8x |
| `wasmer_singlepass` | no | 9.79 ms | ±0.4% | 17.47x | 17.5x |
| `polkavm64_interpreter` | no | 22.16 ms | ±0.5% | 39.54x | 39.5x |
| `nub_interp` | yes | 36.34 ms | ±1.1% | 64.83x | 64.8x |

### prime-sieve

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 54.60 µs | ±0.2% | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 76.20 µs | ±1.0% | 1.40x | 1.4x |
| `polkavm64_recompiler_no_gas` | no | 85.06 µs | ±3.1% | 1.56x | 1.6x |
| `wasmer_singlepass` | no | 118.11 µs | ±0.4% | 2.16x | 2.2x |
| `wasmtime_cranelift_fuel` | yes | 142.21 µs | ±0.5% | 2.60x | 2.6x |
| `wasmtime_winch` | no | 146.64 µs | ±0.6% | 2.69x | 2.7x |
| `nub_jit` † | yes | 176.48 µs | ±0.4% | 3.23x | 3.2x |
| `polkavm64_recompiler_async_gas` | yes | 184.22 µs | ±0.1% | 3.37x | 3.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 184.55 µs | ±0.1% | 3.38x | 3.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 184.58 µs | ±0.1% | 3.38x | 3.4x |
| `polkavm64_recompiler_sync_gas` | yes | 185.14 µs | ±0.3% | 3.39x | 3.4x |
| `polkavm64_interpreter` | no | 2.07 ms | ±0.7% | 37.89x | 37.9x |
| `nub_interp` | yes | 7.20 ms | ±0.4% | 131.88x | 131.9x |
