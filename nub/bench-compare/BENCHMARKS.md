# nub benchmark comparison

## Cold recompile + execute, metered JIT engines

The bench target. Each sample starts with no compiled code and ends with the program having run — the cost a VM pays when a work-package arrives, is turned into native code, and executed once. Metering on.

Storage is deliberately excluded. Getting a blob *into* an engine's object store is dominated by hashing and belongs to a different subsystem than the recompiler; for nub that step is measured separately under `compilation`.

Only cost models comparable to nub's appear here. PolkaVM's default `Simple` model is a flat per-instruction cost and is much cheaper to evaluate than nub's pipeline simulation, so the `*_full` rows (`CacheModel::L2Hit`, whose `memory_access_cost: 25` is exactly nub's `MEM_CYCLES_BASE`) are the like-for-like comparison. Full tables for every engine and every measurement kind follow below.

A cell carries a `±` only when its confidence interval is wider than 2% of the median. Where that happens the cell is a range, not a number, and two engines inside each other's interval are not separable by this measurement.

| Program | `nub_jit` | `polkavm64_recompiler_sync_gas_full` | `polkavm64_recompiler_async_gas_full` | `wasmtime_cranelift_fuel` |
|---|--:|--:|--:|--:|
| fri-fold-tree | **532.82 µs** (1.00x) | 628.51 µs (1.18x) | 612.55 µs (1.15x) | 12.24 ms (22.97x) |
| ecrecover | **1.19 ms** (1.00x) | 1.85 ms (1.55x) | 1.83 ms (1.54x) | 44.56 ms (37.39x) |
| ed25519 | **500.20 µs** (1.00x) | 650.68 µs (1.30x) | 650.67 µs (1.30x) | 30.01 ms (59.99x) |
| blake2b | **64.79 µs** (1.00x) | 115.93 µs (1.79x) | 116.60 µs (1.80x) | 3.49 ms (53.91x) |
| prime-sieve | 228.91 µs (1.03x) | 234.41 µs (1.05x) | **222.35 µs** (1.00x) | 1.02 ms (4.59x) |
| mini-verifier | **542.58 µs** (1.00x) | 653.22 µs (1.20x) | 652.81 µs (1.20x) | 3.85 ms (7.09x) |
| poly-eval | **1.13 ms** (1.00x) | 1.26 ms (1.12x) | 1.31 ms (1.16x) | 9.97 ms (8.83x) |
| poseidon2-perm | **1.18 ms** (1.00x) | 1.43 ms (1.21x) | 1.43 ms (1.21x) | 4.40 ms (3.73x) |
| keccak | **43.22 µs** (1.00x) | 58.55 µs (1.35x) | 58.94 µs (1.36x) | 2.90 ms (66.99x) |
| goldilocks-mul | **353.01 µs** (1.00x) | 389.67 µs (1.10x) | 389.41 µs ±3% (1.10x) | 1.02 ms (2.88x) |

Bold = fastest for that program; the multiple is versus it.

### Where that time goes

The same rows with **compilation excluded** — a fresh instance per sample, then execute. Every engine pays instantiation here, so this is like-for-like even for nub, which rebuilds its frame on every call and therefore has no warm state to hoist out.

The bracketed figure is the difference against the table above: what the recompile costs that engine.

| Program | `nub_jit` | `polkavm64_recompiler_sync_gas_full` | `polkavm64_recompiler_async_gas_full` | `wasmtime_cranelift_fuel` |
|---|--:|--:|--:|--:|
| fri-fold-tree | 452.27 µs (+80.55 µs recompile) | 500.71 µs (+127.80 µs recompile) | 498.88 µs (+113.68 µs recompile) | 773.91 µs (+11.47 ms recompile) |
| ecrecover | 370.80 µs (+820.84 µs recompile) | 333.74 µs (+1.52 ms recompile) | 334.04 µs (+1.50 ms recompile) | 270.38 µs (+44.29 ms recompile) |
| ed25519 | 91.63 µs (+408.57 µs recompile) | 82.77 µs (+567.91 µs recompile) | 81.99 µs (+568.68 µs recompile) | 242.71 µs (+29.77 ms recompile) |
| blake2b | 4.65 µs (+60.14 µs recompile) | 8.91 µs (+107.03 µs recompile) | 9.69 µs (+106.90 µs recompile) | 5.57 µs (+3.49 ms recompile) |
| prime-sieve | 180.14 µs (+48.77 µs recompile) | 216.61 µs (+17.80 µs recompile) | 199.67 µs (+22.68 µs recompile) | 166.04 µs (+854.32 µs recompile) |
| mini-verifier | 475.52 µs (+67.06 µs recompile) | 513.60 µs (+139.62 µs recompile) | 512.98 µs (+139.83 µs recompile) | 785.81 µs (+3.06 ms recompile) |
| poly-eval | 1.10 ms (+27.69 µs recompile) | 1.21 ms (+47.98 µs recompile) | 1.20 ms (+109.16 µs recompile) | 1.48 ms (+8.49 ms recompile) |
| poseidon2-perm | 1.15 ms (+27.83 µs recompile) | 1.25 ms (+173.39 µs recompile) | 1.25 ms (+180.76 µs recompile) | 1.94 ms (+2.46 ms recompile) |
| keccak | 6.50 µs (+36.72 µs recompile) | 12.08 µs (+46.47 µs recompile) | 12.64 µs (+46.31 µs recompile) | 7.81 µs (+2.89 ms recompile) |
| goldilocks-mul | 309.79 µs (+43.22 µs recompile) | 349.68 µs (+39.99 µs recompile) | 366.12 µs (+23.29 µs recompile) | 505.44 µs (+511.61 µs recompile) |


## Artifact size

How big the program is, which for a chain VM is the other half of the story — it is what gets gossiped, stored and paid for.

**Raw code excludes the data regions**, and that is the figure to read. Several kernels carry large initialized data that swamps everything else: `prime-sieve` is 214 bytes of nub code inside a 158,338-byte blob, 0.1% of it. Comparing whole blobs there compares static lookup tables, not code generators.

The code figure is `code` for nub, `code + jump table + bitmask` for PolkaVM, and `Code + Type + Function + Table + Element + Global` for wasm. PolkaVM's two extras and wasm's aux sections are code information held *outside* the instruction stream — instruction boundaries, indirect-branch targets, function signatures — all of which RV64EMC encodes inline. The breakdown tables below show every component so the definition can be checked rather than taken on trust; note it is deliberately broader than upstream PolkaVM's own disassembler, which labels only `code` as "code size".

`native` is absent: a host `.so` is a different kind of object — ELF program headers, relocations, a dynamic symbol table, and whatever of `std` got linked in — not a bigger or smaller one.

**The whole-blob table is not built from identical sources**, and the raw-code table is the fairer one for that reason too. pvm2 builds the kernel crate's own binary, so it carries nub's guest runtime — the entry trampoline, the endpoint table, the bump arena. The other three build the thin wrapper in `guests/`, which calls into the same kernel as a library. That is each format's honest artifact, since the nub-rt endpoint binary *is* the PVM2 ABI, but it means the data regions are not measuring the same thing and nub is carrying runtime the others are not.

**No compression is involved anywhere.** Trailing-zero trimming in nub and PolkaVM is BSS elision, exactly what ELF does with `p_filesz < p_memsz`, and wasm data segments carry no trailing zeros either. The varint/LEB128 encoding in PolkaVM and wasm is instruction encoding, not a container compressor: it cannot be disabled, and it is precisely the axis these formats trade on.

### Raw code

| Program | `pvm2` | `polkavm64` | `wasm32` |
|---|--:|--:|--:|
| prime-sieve | 214 (1.27x) | **168** (1.00x) | 318 (1.89x) |
| ed25519 | **41,442** (1.00x) | 53,632 (1.29x) | 60,116 (1.45x) |
| keccak | **1,884** (1.00x) | 4,551 (2.42x) | 2,760 (1.46x) |
| blake2b | 6,980 (1.07x) | 12,453 (1.90x) | **6,552** (1.00x) |
| ecrecover | 96,170 (1.16x) | 130,599 (1.57x) | **83,023** (1.00x) |
| goldilocks-mul | 162 (1.17x) | **138** (1.00x) | 346 (2.51x) |
| poseidon2-perm | **3,404** (1.00x) | 4,625 (1.36x) | 5,183 (1.52x) |
| mini-verifier | **4,282** (1.00x) | 6,276 (1.47x) | 6,659 (1.56x) |
| poly-eval | **824** (1.00x) | 996 (1.21x) | 10,885 (13.21x) |
| fri-fold-tree | **4,192** (1.00x) | 6,252 (1.49x) | 17,178 (4.10x) |

Bold = smallest for that program; the multiple is versus it.

### Whole blob

| Program | `pvm2` | `polkavm64` | `wasm32` |
|---|--:|--:|--:|
| prime-sieve | 158,338 (1.58x) | **100,210** (1.00x) | 100,402 (1.00x) |
| ed25519 | 91,558 (1.65x) | **55,427** (1.00x) | 62,833 (1.13x) |
| keccak | 9,193 (2.87x) | 4,783 (1.49x) | **3,204** (1.00x) |
| blake2b | 19,153 (2.89x) | 12,489 (1.89x) | **6,621** (1.00x) |
| ecrecover | 198,576 (2.32x) | 131,074 (1.53x) | **85,416** (1.00x) |
| goldilocks-mul | 5,415 (31.30x) | **173** (1.00x) | 415 (2.40x) |
| poseidon2-perm | 13,225 (2.47x) | **5,353** (1.00x) | 5,953 (1.11x) |
| mini-verifier | 15,447 (2.10x) | **7,364** (1.00x) | 7,429 (1.01x) |
| poly-eval | 6,733 (6.51x) | **1,034** (1.00x) | 11,257 (10.89x) |
| fri-fold-tree | 14,821 (2.12x) | **6,982** (1.00x) | 18,559 (2.66x) |

Bold = smallest for that program; the multiple is versus it.

### Breakdown

Every row sums to the file size.

#### `pvm2`

| Program | header | endpoints | code | ro | rw | = code | file |
|---|--:|--:|--:|--:|--:|--:|--:|
| prime-sieve | 40 | 84 | 214 | 0 | 158,000 | **214** | 158,338 |
| ed25519 | 40 | 84 | 41,442 | 2,279 | 47,713 | **41,442** | 91,558 |
| keccak | 40 | 84 | 1,884 | 592 | 6,593 | **1,884** | 9,193 |
| blake2b | 40 | 84 | 6,980 | 472 | 11,577 | **6,980** | 19,153 |
| ecrecover | 40 | 84 | 96,170 | 993 | 101,289 | **96,170** | 198,576 |
| goldilocks-mul | 40 | 84 | 162 | 416 | 4,713 | **162** | 5,415 |
| poseidon2-perm | 40 | 84 | 3,404 | 1,088 | 8,609 | **3,404** | 13,225 |
| mini-verifier | 40 | 84 | 4,282 | 1,328 | 9,713 | **4,282** | 15,447 |
| poly-eval | 40 | 84 | 824 | 424 | 5,361 | **824** | 6,733 |
| fri-fold-tree | 40 | 84 | 4,192 | 1,104 | 9,401 | **4,192** | 14,821 |

#### `polkavm64`

| Program | code | jump table | bitmask | §6 framing | ro | rw | exports | memory cfg | other | container | = code | file |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| prime-sieve | 148 | 1 | 19 | 4 | 0 | 100,000 | 6 | 7 | 0 | 25 | **168** | 100,210 |
| ed25519 | 47,383 | 326 | 5,923 | 6 | 1,752 | 0 | 6 | 6 | 0 | 25 | **53,632** | 55,427 |
| keccak | 4,029 | 18 | 504 | 4 | 192 | 0 | 6 | 6 | 0 | 24 | **4,551** | 4,783 |
| blake2b | 11,048 | 24 | 1,381 | 4 | 0 | 0 | 6 | 5 | 0 | 21 | **12,453** | 12,489 |
| ecrecover | 114,413 | 1,884 | 14,302 | 6 | 432 | 0 | 6 | 6 | 0 | 25 | **130,599** | 131,074 |
| goldilocks-mul | 122 | 0 | 16 | 3 | 0 | 0 | 6 | 5 | 0 | 21 | **138** | 173 |
| poseidon2-perm | 4,110 | 1 | 514 | 4 | 688 | 0 | 6 | 6 | 0 | 24 | **4,625** | 5,353 |
| mini-verifier | 5,546 | 36 | 694 | 4 | 1,048 | 0 | 6 | 6 | 0 | 24 | **6,276** | 7,364 |
| poly-eval | 874 | 12 | 110 | 4 | 0 | 0 | 6 | 7 | 0 | 21 | **996** | 1,034 |
| fri-fold-tree | 5,539 | 20 | 693 | 4 | 688 | 0 | 6 | 8 | 0 | 24 | **6,252** | 6,982 |

#### `wasm32`

| Program | code(10) | type(1) | function(3) | table(4) | element(9) | global(6) | data(11) | custom(0) | other | container | = code | file |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| prime-sieve | 281 | 5 | 2 | 5 | 0 | 25 | 100,011 | 0 | 46 | 27 | **318** | 100,402 |
| ed25519 | 59,988 | 64 | 25 | 5 | 9 | 25 | 2,642 | 0 | 46 | 29 | **60,116** | 62,833 |
| keccak | 2,680 | 30 | 12 | 5 | 8 | 25 | 370 | 0 | 46 | 28 | **2,760** | 3,204 |
| blake2b | 6,508 | 11 | 3 | 5 | 0 | 25 | 0 | 0 | 46 | 23 | **6,552** | 6,621 |
| ecrecover | 82,819 | 73 | 69 | 5 | 32 | 25 | 2,318 | 0 | 46 | 29 | **83,023** | 85,416 |
| goldilocks-mul | 300 | 13 | 3 | 5 | 0 | 25 | 0 | 0 | 46 | 23 | **346** | 415 |
| poseidon2-perm | 5,137 | 13 | 3 | 5 | 0 | 25 | 698 | 0 | 46 | 26 | **5,183** | 5,953 |
| mini-verifier | 6,608 | 17 | 4 | 5 | 0 | 25 | 698 | 0 | 46 | 26 | **6,659** | 7,429 |
| poly-eval | 10,769 | 51 | 27 | 5 | 8 | 25 | 298 | 0 | 46 | 28 | **10,885** | 11,257 |
| fri-fold-tree | 17,044 | 64 | 31 | 5 | 9 | 25 | 1,306 | 0 | 46 | 29 | **17,178** | 18,559 |
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
| `native` | no | 15.05 µs | ±0.5% | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 39.44 µs | ±0.8% | 2.62x | 2.6x |
| `polkavm64_recompiler_async_gas` | yes | 40.42 µs | ±0.6% | 2.69x | 2.7x |
| `polkavm64_recompiler_sync_gas` | yes | 40.57 µs | ±0.7% | 2.70x | 2.7x |
| `nub_jit` | yes | 64.79 µs | ±0.4% | 4.31x | 4.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 115.93 µs | ±0.5% | 7.70x | 7.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 116.60 µs | ±0.5% | 7.75x | 7.7x |
| `polkavm64_interpreter` | no | 122.79 µs | ±0.7% | 8.16x | 8.2x |
| `nub_interp` | yes | 234.50 µs | ±0.9% | 15.58x | 15.6x |
| `wasmtime_winch` | no | 434.04 µs | ±0.5% | 28.84x | 28.8x |
| `wasmer_singlepass` | no | 1.97 ms | ±1.5% | 130.98x | 131.0x |
| `wasmtime_cranelift` | no | 3.32 ms | ±0.4% | 220.36x | 220.4x |
| `wasmtime_cranelift_fuel` | yes | 3.49 ms | ±0.4% | 232.15x | 232.1x |

### ecrecover

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 110.09 µs | ±0.3% | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 674.37 µs | ±0.5% | 6.13x | 6.1x |
| `polkavm64_recompiler_async_gas` | yes | 709.74 µs | ±0.4% | 6.45x | 6.4x |
| `polkavm64_recompiler_sync_gas` | yes | 720.27 µs | ±0.5% | 6.54x | 6.5x |
| `nub_jit` | yes | 1.19 ms | ±0.5% | 10.82x | 10.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.83 ms | ±0.3% | 16.63x | 16.6x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.85 ms | ±0.3% | 16.80x | 16.8x |
| `wasmtime_winch` | no | 5.35 ms | ±0.2% | 48.56x | 48.6x |
| `wasmer_singlepass` | no | 7.38 ms | ±2.0% | 67.00x | 67.0x |
| `polkavm64_interpreter` | no | 12.46 ms | ±0.5% | 113.21x | 113.2x |
| `nub_interp` | yes | 27.34 ms | ±0.5% | 248.37x | 248.4x |
| `wasmtime_cranelift` | no | 35.29 ms | ±0.3% | 320.54x | 320.5x |
| `wasmtime_cranelift_fuel` | yes | 44.56 ms | ±0.6% | 404.73x | 404.7x |

### ed25519

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 46.08 µs | ±0.4% | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 210.92 µs | ±0.2% | 4.58x | 4.6x |
| `polkavm64_recompiler_sync_gas` | yes | 221.62 µs | ±0.7% | 4.81x | 4.8x |
| `polkavm64_recompiler_async_gas` | yes | 223.77 µs | ±0.3% | 4.86x | 4.9x |
| `nub_jit` | yes | 500.20 µs | ±0.3% | 10.86x | 10.9x |
| `polkavm64_recompiler_async_gas_full` | yes | 650.67 µs | ±1.1% | 14.12x | 14.1x |
| `polkavm64_recompiler_sync_gas_full` | yes | 650.68 µs | ±0.7% | 14.12x | 14.1x |
| `polkavm64_interpreter` | no | 1.83 ms | ±0.7% | 39.66x | 39.7x |
| `wasmtime_winch` | no | 3.15 ms | ±0.6% | 68.46x | 68.5x |
| `nub_interp` | yes | 5.35 ms | ±0.2% | 116.08x | 116.1x |
| `wasmer_singlepass` | no | 7.74 ms | ±1.6% | 167.94x | 167.9x |
| `wasmtime_cranelift` | no | 23.88 ms | ±0.6% | 518.29x | 518.3x |
| `wasmtime_cranelift_fuel` | yes | 30.01 ms | ±0.4% | 651.28x | 651.3x |

### fri-fold-tree

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 234.60 µs | ±0.4% | 1.00x | 1.0x |
| `nub_jit` | yes | 532.82 µs | ±0.3% | 2.27x | 2.3x |
| `polkavm64_recompiler_sync_gas` | yes | 592.62 µs | ±0.4% | 2.53x | 2.5x |
| `polkavm64_recompiler_async_gas` | yes | 597.00 µs | ±0.4% | 2.54x | 2.5x |
| `polkavm64_recompiler_no_gas` | no | 598.61 µs | ±0.0% | 2.55x | 2.6x |
| `polkavm64_recompiler_async_gas_full` | yes | 612.55 µs | ±0.2% | 2.61x | 2.6x |
| `polkavm64_recompiler_sync_gas_full` | yes | 628.51 µs | ±1.4% | 2.68x | 2.7x |
| `wasmtime_winch` | no | 2.90 ms | ±0.4% | 12.38x | 12.4x |
| `wasmer_singlepass` | no | 7.46 ms | ±1.5% | 31.82x | 31.8x |
| `wasmtime_cranelift` | no | 8.73 ms | ±0.5% | 37.19x | 37.2x |
| `polkavm64_interpreter` | no | 9.07 ms | ±0.6% | 38.67x | 38.7x |
| `wasmtime_cranelift_fuel` | yes | 12.24 ms | ±0.6% | 52.17x | 52.2x |
| `nub_interp` | yes | 13.12 ms | ±0.6% | 55.95x | 55.9x |

### goldilocks-mul

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 214.47 µs | ±0.4% | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 340.10 µs | ±0.2% | 1.59x | 1.6x |
| `nub_jit` | yes | 353.01 µs | ±0.3% | 1.65x | 1.6x |
| `polkavm64_recompiler_async_gas` | yes | 370.92 µs | ±0.1% | 1.73x | 1.7x |
| `polkavm64_recompiler_sync_gas` | yes | 384.91 µs | ±1.0% | 1.79x | 1.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 389.41 µs | ±2.7% | 1.82x | 1.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 389.67 µs | ±0.5% | 1.82x | 1.8x |
| `wasmtime_winch` | no | 770.10 µs | ±0.9% | 3.59x | 3.6x |
| `wasmtime_cranelift` | no | 897.49 µs | ±0.6% | 4.18x | 4.2x |
| `wasmtime_cranelift_fuel` | yes | 1.02 ms | ±0.5% | 4.74x | 4.7x |
| `polkavm64_interpreter` | no | 2.07 ms | ±0.7% | 9.65x | 9.7x |
| `wasmer_singlepass` | no | 2.90 ms | ±1.4% | 13.53x | 13.5x |
| `nub_interp` | yes | 3.92 ms | ±0.6% | 18.26x | 18.3x |

### keccak

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 16.31 µs | ±0.7% | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 32.97 µs | ±1.1% | 2.02x | 2.0x |
| `polkavm64_recompiler_async_gas` | yes | 34.03 µs | ±1.2% | 2.09x | 2.1x |
| `polkavm64_recompiler_sync_gas` | yes | 34.32 µs | ±0.8% | 2.10x | 2.1x |
| `nub_jit` | yes | 43.22 µs | ±0.5% | 2.65x | 2.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 58.55 µs | ±0.9% | 3.59x | 3.6x |
| `polkavm64_recompiler_async_gas_full` | yes | 58.94 µs | ±1.1% | 3.61x | 3.6x |
| `polkavm64_interpreter` | no | 100.07 µs | ±1.0% | 6.14x | 6.1x |
| `nub_interp` | yes | 277.97 µs | ±0.6% | 17.04x | 17.0x |
| `wasmtime_winch` | no | 814.13 µs | ±0.5% | 49.92x | 49.9x |
| `wasmer_singlepass` | no | 1.65 ms | ±1.0% | 100.92x | 100.9x |
| `wasmtime_cranelift` | no | 2.19 ms | ±0.5% | 134.54x | 134.5x |
| `wasmtime_cranelift_fuel` | yes | 2.90 ms | ±0.5% | 177.52x | 177.5x |

### mini-verifier

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 244.06 µs | ±0.5% | 1.00x | 1.0x |
| `nub_jit` | yes | 542.58 µs | ±0.6% | 2.22x | 2.2x |
| `polkavm64_recompiler_no_gas` | no | 603.23 µs | ±0.1% | 2.47x | 2.5x |
| `polkavm64_recompiler_sync_gas` | yes | 606.33 µs | ±1.0% | 2.48x | 2.5x |
| `polkavm64_recompiler_async_gas` | yes | 612.13 µs | ±0.0% | 2.51x | 2.5x |
| `polkavm64_recompiler_async_gas_full` | yes | 652.81 µs | ±0.1% | 2.67x | 2.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 653.22 µs | ±0.0% | 2.68x | 2.7x |
| `wasmtime_winch` | no | 1.86 ms | ±0.6% | 7.60x | 7.6x |
| `wasmtime_cranelift` | no | 3.27 ms | ±0.6% | 13.39x | 13.4x |
| `wasmtime_cranelift_fuel` | yes | 3.85 ms | ±0.4% | 15.77x | 15.8x |
| `wasmer_singlepass` | no | 6.26 ms | ±0.9% | 25.66x | 25.7x |
| `polkavm64_interpreter` | no | 9.64 ms | ±0.8% | 39.49x | 39.5x |
| `nub_interp` | yes | 13.61 ms | ±1.1% | 55.78x | 55.8x |

### poly-eval

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 679.29 µs | ±0.5% | 1.00x | 1.0x |
| `nub_jit` | yes | 1.13 ms | ±0.4% | 1.66x | 1.7x |
| `polkavm64_recompiler_async_gas` | yes | 1.21 ms | ±0.4% | 1.78x | 1.8x |
| `polkavm64_recompiler_sync_gas` | yes | 1.22 ms | ±0.7% | 1.80x | 1.8x |
| `polkavm64_recompiler_no_gas` | no | 1.23 ms | ±0.2% | 1.81x | 1.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.26 ms | ±0.0% | 1.85x | 1.9x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.31 ms | ±0.0% | 1.92x | 1.9x |
| `wasmtime_winch` | no | 3.02 ms | ±0.5% | 4.45x | 4.5x |
| `wasmtime_cranelift` | no | 7.03 ms | ±0.5% | 10.35x | 10.4x |
| `polkavm64_interpreter` | no | 8.13 ms | ±0.7% | 11.96x | 12.0x |
| `wasmer_singlepass` | no | 8.64 ms | ±1.5% | 12.71x | 12.7x |
| `wasmtime_cranelift_fuel` | yes | 9.97 ms | ±0.5% | 14.68x | 14.7x |
| `nub_interp` | yes | 17.35 ms | ±0.6% | 25.55x | 25.5x |

### poseidon2-perm

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 574.05 µs | ±0.4% | 1.00x | 1.0x |
| `nub_jit` | yes | 1.18 ms | ±0.3% | 2.06x | 2.1x |
| `polkavm64_recompiler_no_gas` | no | 1.40 ms | ±0.5% | 2.44x | 2.4x |
| `polkavm64_recompiler_async_gas` | yes | 1.40 ms | ±0.6% | 2.44x | 2.4x |
| `polkavm64_recompiler_sync_gas` | yes | 1.40 ms | ±0.7% | 2.44x | 2.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.43 ms | ±0.4% | 2.48x | 2.5x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.43 ms | ±0.4% | 2.48x | 2.5x |
| `wasmtime_winch` | no | 3.59 ms | ±0.2% | 6.25x | 6.2x |
| `wasmtime_cranelift` | no | 3.93 ms | ±0.4% | 6.85x | 6.9x |
| `wasmtime_cranelift_fuel` | yes | 4.40 ms | ±0.5% | 7.67x | 7.7x |
| `wasmer_singlepass` | no | 12.44 ms | ±0.4% | 21.67x | 21.7x |
| `polkavm64_interpreter` | no | 22.28 ms | ±1.3% | 38.82x | 38.8x |
| `nub_interp` | yes | 35.07 ms | ±0.9% | 61.10x | 61.1x |

### prime-sieve

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 90.05 µs | ±0.3% | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 126.49 µs | ±0.1% | 1.40x | 1.4x |
| `polkavm64_recompiler_async_gas` | yes | 222.23 µs | ±0.5% | 2.47x | 2.5x |
| `polkavm64_recompiler_async_gas_full` | yes | 222.35 µs | ±0.8% | 2.47x | 2.5x |
| `nub_jit` | yes | 228.91 µs | ±0.7% | 2.54x | 2.5x |
| `polkavm64_recompiler_sync_gas` | yes | 228.98 µs | ±0.1% | 2.54x | 2.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 234.41 µs | ±0.1% | 2.60x | 2.6x |
| `wasmtime_winch` | no | 550.11 µs | ±0.6% | 6.11x | 6.1x |
| `wasmtime_cranelift` | no | 641.84 µs | ±0.3% | 7.13x | 7.1x |
| `wasmtime_cranelift_fuel` | yes | 1.02 ms | ±0.4% | 11.33x | 11.3x |
| `wasmer_singlepass` | no | 1.55 ms | ±2.0% | 17.24x | 17.2x |
| `polkavm64_interpreter` | no | 2.12 ms | ±0.4% | 23.59x | 23.6x |
| `nub_interp` | yes | 8.17 ms | ±0.7% | 90.75x | 90.7x |

## compilation

Turning the program into executable form. Engine construction and file loading are excluded (a once-per-process cost, and the harness's own I/O). `native` is absent: the OS loader already did it.

**`nub_jit` measures publishing here, not codegen** — and publishing is *not* part of the bench target above. nub keeps its object store *inside* the sandbox, so this is the cost of shipping a blob across the VM boundary, decoding it, content-hashing it and materializing its data image. It is dominated by hashing and scales with blob size, not code size. `nub_jit_compile` is the codegen-only figure.

### blake2b

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `polkavm64_interpreter` | no | 17.91 µs | ±0.6% | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 18.99 µs | ±0.7% | 1.06x | - |
| `polkavm64_recompiler_sync_gas` | yes | 19.03 µs | ±0.6% | 1.06x | - |
| `polkavm64_recompiler_async_gas` | yes | 19.08 µs | ±0.7% | 1.07x | - |
| `nub_jit_compile` | yes | 45.45 µs | ±0.4% | 2.54x | - |
| `nub_jit` | yes | 64.76 µs | ±0.4% | 3.62x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 98.13 µs | ±0.5% | 5.48x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 98.61 µs | ±0.4% | 5.51x | - |
| `wasmtime_winch` | no | 424.11 µs | ±0.4% | 23.68x | - |
| `wasmer_singlepass` | no | 917.18 µs | ±1.8% | 51.21x | - |
| `wasmtime_cranelift` | no | 3.24 ms | ±0.5% | 180.86x | - |
| `wasmtime_cranelift_fuel` | yes | 3.46 ms | ±0.4% | 193.29x | - |

### ecrecover

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `polkavm64_interpreter` | no | 194.97 µs | ±0.6% | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 251.82 µs | ±0.4% | 1.29x | - |
| `polkavm64_recompiler_sync_gas` | yes | 259.04 µs | ±0.6% | 1.33x | - |
| `polkavm64_recompiler_async_gas` | yes | 262.52 µs | ±0.4% | 1.35x | - |
| `nub_jit` | yes | 615.64 µs | ±0.5% | 3.16x | - |
| `nub_jit_compile` | yes | 778.72 µs | ±0.6% | 3.99x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.35 ms | ±0.4% | 6.93x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 1.36 ms | ±0.5% | 6.99x | - |
| `wasmer_singlepass` | no | 3.16 ms | ±1.2% | 16.23x | - |
| `wasmtime_winch` | no | 4.86 ms | ±0.6% | 24.91x | - |
| `wasmtime_cranelift` | no | 35.73 ms | ±0.4% | 183.25x | - |
| `wasmtime_cranelift_fuel` | yes | 44.19 ms | ±0.3% | 226.65x | - |

### ed25519

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `polkavm64_interpreter` | no | 82.71 µs | ±0.7% | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 112.82 µs | ±0.4% | 1.36x | - |
| `polkavm64_recompiler_sync_gas` | yes | 113.74 µs | ±0.4% | 1.38x | - |
| `polkavm64_recompiler_async_gas` | yes | 115.01 µs | ±0.3% | 1.39x | - |
| `nub_jit` | yes | 286.36 µs | ±0.8% | 3.46x | - |
| `nub_jit_compile` | yes | 361.35 µs | ±0.6% | 4.37x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 523.97 µs | ±0.5% | 6.34x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 529.98 µs | ±0.7% | 6.41x | - |
| `wasmtime_winch` | no | 2.73 ms | ±0.8% | 32.99x | - |
| `wasmer_singlepass` | no | 3.29 ms | ±1.0% | 39.73x | - |
| `wasmtime_cranelift` | no | 23.98 ms | ±0.5% | 289.89x | - |
| `wasmtime_cranelift_fuel` | yes | 29.50 ms | ±0.4% | 356.68x | - |

### fri-fold-tree

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `polkavm64_interpreter` | no | 9.73 µs | ±0.8% | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 10.65 µs | ±0.5% | 1.09x | - |
| `polkavm64_recompiler_async_gas` | yes | 10.73 µs | ±0.6% | 1.10x | - |
| `polkavm64_recompiler_sync_gas` | yes | 10.77 µs | ±0.6% | 1.11x | - |
| `nub_jit_compile` | yes | 26.49 µs | ±0.9% | 2.72x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 53.84 µs | ±0.3% | 5.53x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 53.94 µs | ±0.2% | 5.54x | - |
| `nub_jit` | yes | 72.89 µs | ±0.6% | 7.49x | - |
| `wasmer_singlepass` | no | 1.40 ms | ±0.9% | 144.34x | - |
| `wasmtime_winch` | no | 1.62 ms | ±0.7% | 166.89x | - |
| `wasmtime_cranelift` | no | 8.13 ms | ±0.2% | 835.21x | - |
| `wasmtime_cranelift_fuel` | yes | 11.57 ms | ±0.5% | 1189.17x | - |

### goldilocks-mul

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `polkavm64_interpreter` | no | 354.3 ns | ±0.5% | 1.00x | - |
| `nub_jit_compile` | yes | 1.28 µs | ±0.5% | 3.61x | - |
| `polkavm64_recompiler_no_gas` | no | 1.54 µs | ±0.6% | 4.35x | - |
| `polkavm64_recompiler_sync_gas` | yes | 1.57 µs | ±0.4% | 4.44x | - |
| `polkavm64_recompiler_async_gas` | yes | 1.58 µs | ±0.5% | 4.47x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 3.18 µs | ±0.4% | 8.98x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 3.20 µs | ±0.4% | 9.02x | - |
| `nub_jit` | yes | 24.44 µs | ±0.5% | 68.99x | - |
| `wasmtime_winch` | no | 207.67 µs | ±0.2% | 586.18x | - |
| `wasmtime_cranelift` | no | 369.10 µs | ±0.6% | 1041.83x | - |
| `wasmtime_cranelift_fuel` | yes | 496.00 µs | ±0.4% | 1400.03x | - |
| `wasmer_singlepass` | no | 642.29 µs | ±1.5% | 1812.96x | - |

### keccak

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `polkavm64_interpreter` | no | 6.76 µs | ±0.3% | 1.00x | - |
| `polkavm64_recompiler_sync_gas` | yes | 7.61 µs | ±0.5% | 1.13x | - |
| `polkavm64_recompiler_no_gas` | no | 7.69 µs | ±0.6% | 1.14x | - |
| `polkavm64_recompiler_async_gas` | yes | 7.75 µs | ±0.3% | 1.15x | - |
| `nub_jit_compile` | yes | 9.52 µs | ±0.4% | 1.41x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 33.48 µs | ±0.6% | 4.95x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 34.11 µs | ±0.5% | 5.05x | - |
| `nub_jit` | yes | 35.84 µs | ±0.5% | 5.30x | - |
| `wasmtime_winch` | no | 760.40 µs | ±0.4% | 112.50x | - |
| `wasmer_singlepass` | no | 804.30 µs | ±1.4% | 118.99x | - |
| `wasmtime_cranelift` | no | 2.15 ms | ±0.2% | 318.76x | - |
| `wasmtime_cranelift_fuel` | yes | 2.86 ms | ±0.6% | 423.04x | - |

### mini-verifier

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `polkavm64_interpreter` | no | 9.56 µs | ±0.6% | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 9.75 µs | ±0.4% | 1.02x | - |
| `polkavm64_recompiler_async_gas` | yes | 9.81 µs | ±0.5% | 1.03x | - |
| `polkavm64_recompiler_sync_gas` | yes | 10.51 µs | ±0.8% | 1.10x | - |
| `nub_jit_compile` | yes | 26.72 µs | ±0.6% | 2.79x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 51.25 µs | ±0.4% | 5.36x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 51.34 µs | ±0.4% | 5.37x | - |
| `nub_jit` | yes | 54.76 µs | ±0.6% | 5.73x | - |
| `wasmtime_winch` | no | 563.08 µs | ±0.4% | 58.88x | - |
| `wasmer_singlepass` | no | 899.45 µs | ±1.5% | 94.06x | - |
| `wasmtime_cranelift` | no | 2.48 ms | ±0.5% | 259.79x | - |
| `wasmtime_cranelift_fuel` | yes | 3.02 ms | ±0.3% | 315.56x | - |

### poly-eval

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `polkavm64_interpreter` | no | 1.72 µs | ±0.6% | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 3.06 µs | ±0.5% | 1.78x | - |
| `polkavm64_recompiler_async_gas` | yes | 3.17 µs | ±0.5% | 1.85x | - |
| `polkavm64_recompiler_sync_gas` | yes | 3.23 µs | ±0.7% | 1.88x | - |
| `nub_jit_compile` | yes | 9.53 µs | ±0.3% | 5.55x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 11.18 µs | ±0.8% | 6.51x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 11.28 µs | ±0.3% | 6.57x | - |
| `nub_jit` | yes | 32.73 µs | ±0.8% | 19.07x | - |
| `wasmtime_winch` | no | 1.30 ms | ±0.2% | 758.40x | - |
| `wasmer_singlepass` | no | 1.33 ms | ±0.8% | 777.80x | - |
| `wasmtime_cranelift` | no | 5.47 ms | ±0.4% | 3189.79x | - |
| `wasmtime_cranelift_fuel` | yes | 8.54 ms | ±0.2% | 4976.08x | - |

### poseidon2-perm

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `polkavm64_interpreter` | no | 7.56 µs | ±0.3% | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 7.77 µs | ±0.5% | 1.03x | - |
| `polkavm64_recompiler_async_gas` | yes | 7.79 µs | ±0.3% | 1.03x | - |
| `polkavm64_recompiler_sync_gas` | yes | 7.91 µs | ±0.5% | 1.05x | - |
| `nub_jit_compile` | yes | 22.91 µs | ±0.3% | 3.03x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 37.41 µs | ±0.5% | 4.95x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 37.49 µs | ±0.4% | 4.96x | - |
| `nub_jit` | yes | 47.68 µs | ±0.8% | 6.30x | - |
| `wasmtime_winch` | no | 469.90 µs | ±0.9% | 62.12x | - |
| `wasmer_singlepass` | no | 869.38 µs | ±1.1% | 114.94x | - |
| `wasmtime_cranelift` | no | 2.00 ms | ±0.4% | 264.56x | - |
| `wasmtime_cranelift_fuel` | yes | 2.43 ms | ±0.5% | 321.61x | - |

### prime-sieve

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `polkavm64_interpreter` | no | 1.84 µs | ±0.4% | 1.00x | - |
| `nub_jit_compile` | yes | 3.70 µs | ±0.6% | 2.02x | - |
| `polkavm64_recompiler_no_gas` | no | 4.69 µs | ±0.3% | 2.56x | - |
| `polkavm64_recompiler_sync_gas` | yes | 4.79 µs | ±0.4% | 2.61x | - |
| `polkavm64_recompiler_async_gas` | yes | 4.80 µs | ±0.4% | 2.61x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 6.94 µs | ±0.6% | 3.78x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 7.07 µs | ±0.6% | 3.85x | - |
| `wasmtime_winch` | no | 327.84 µs | ±0.6% | 178.58x | - |
| `nub_jit` | yes | 489.48 µs | ±0.7% | 266.63x | - |
| `wasmtime_cranelift` | no | 489.57 µs | ±0.4% | 266.68x | - |
| `wasmer_singlepass` | no | 697.57 µs | ±1.6% | 379.99x | - |
| `wasmtime_cranelift_fuel` | yes | 818.07 µs | ±0.5% | 445.63x | - |

## invoke

Cold invocation with compilation excluded: a fresh instance every sample. Where an engine's *instantiation* strategy shows up. Compare against `runtime` for the same row to see what a cold start costs it.

### blake2b

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 640.2 ns | ±0.3% | 1.00x | 1.0x |
| `nub_jit` | yes | 4.65 µs | ±0.4% | 7.26x | 7.3x |
| `wasmtime_cranelift_fuel` | yes | 5.57 µs | ±1.0% | 8.71x | 8.7x |
| `wasmtime_cranelift` | no | 5.62 µs | ±1.0% | 8.77x | 8.8x |
| `wasmtime_winch` | no | 6.17 µs | ±0.8% | 9.65x | 9.6x |
| `polkavm64_recompiler_sync_gas` | yes | 8.63 µs | ±1.7% | 13.49x | 13.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 8.91 µs | ±1.2% | 13.91x | 13.9x |
| `polkavm64_recompiler_no_gas` | no | 8.95 µs | ±1.0% | 13.98x | 14.0x |
| `polkavm64_recompiler_async_gas` | yes | 9.65 µs | ±1.1% | 15.07x | 15.1x |
| `polkavm64_recompiler_async_gas_full` | yes | 9.69 µs | ±1.5% | 15.14x | 15.1x |
| `wasmer_singlepass` | no | 45.42 µs | ±3.6% | 70.95x | 70.9x |
| `polkavm64_interpreter` | no | 98.42 µs | ±0.7% | 153.75x | 153.7x |
| `nub_interp` | yes | 152.54 µs | ±1.1% | 238.28x | 238.3x |

### ecrecover

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 92.65 µs | ±0.7% | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 260.07 µs | ±0.3% | 2.81x | 2.8x |
| `wasmtime_cranelift_fuel` | yes | 270.38 µs | ±0.5% | 2.92x | 2.9x |
| `polkavm64_recompiler_no_gas` | no | 319.48 µs | ±0.1% | 3.45x | 3.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 333.74 µs | ±0.1% | 3.60x | 3.6x |
| `polkavm64_recompiler_async_gas_full` | yes | 334.04 µs | ±0.2% | 3.61x | 3.6x |
| `polkavm64_recompiler_sync_gas` | yes | 334.41 µs | ±0.2% | 3.61x | 3.6x |
| `nub_jit` | yes | 370.80 µs | ±0.4% | 4.00x | 4.0x |
| `wasmtime_winch` | no | 416.98 µs | ±0.4% | 4.50x | 4.5x |
| `polkavm64_recompiler_async_gas` | yes | 451.73 µs | ±0.1% | 4.88x | 4.9x |
| `wasmer_singlepass` | no | 1.18 ms | ±3.2% | 12.74x | 12.7x |
| `polkavm64_interpreter` | no | 12.18 ms | ±0.3% | 131.41x | 131.4x |
| `nub_interp` | yes | 26.59 ms | ±0.5% | 287.00x | 287.0x |

### ed25519

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 29.54 µs | ±0.6% | 1.00x | 1.0x |
| `polkavm64_recompiler_async_gas_full` | yes | 81.99 µs | ±0.3% | 2.78x | 2.8x |
| `polkavm64_recompiler_async_gas` | yes | 82.05 µs | ±0.2% | 2.78x | 2.8x |
| `polkavm64_recompiler_sync_gas` | yes | 82.38 µs | ±0.3% | 2.79x | 2.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 82.77 µs | ±0.3% | 2.80x | 2.8x |
| `polkavm64_recompiler_no_gas` | no | 90.54 µs | ±8.9% | 3.06x | 3.1x |
| `nub_jit` | yes | 91.63 µs | ±0.7% | 3.10x | 3.1x |
| `wasmtime_cranelift` | no | 199.08 µs | ±0.5% | 6.74x | 6.7x |
| `wasmtime_cranelift_fuel` | yes | 242.71 µs | ±0.3% | 8.22x | 8.2x |
| `wasmtime_winch` | no | 351.42 µs | ±0.9% | 11.90x | 11.9x |
| `wasmer_singlepass` | no | 1.29 ms | ±1.7% | 43.57x | 43.6x |
| `polkavm64_interpreter` | no | 1.77 ms | ±0.8% | 59.86x | 59.9x |
| `nub_interp` | yes | 4.87 ms | ±0.3% | 164.86x | 164.9x |

### fri-fold-tree

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 221.62 µs | ±0.5% | 1.00x | 1.0x |
| `nub_jit` | yes | 452.27 µs | ±0.5% | 2.04x | 2.0x |
| `polkavm64_recompiler_no_gas` | no | 498.08 µs | ±0.1% | 2.25x | 2.2x |
| `polkavm64_recompiler_async_gas` | yes | 498.30 µs | ±0.1% | 2.25x | 2.2x |
| `polkavm64_recompiler_sync_gas` | yes | 498.78 µs | ±0.1% | 2.25x | 2.3x |
| `polkavm64_recompiler_async_gas_full` | yes | 498.88 µs | ±0.1% | 2.25x | 2.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 500.71 µs | ±0.2% | 2.26x | 2.3x |
| `wasmtime_cranelift` | no | 736.81 µs | ±0.8% | 3.32x | 3.3x |
| `wasmtime_cranelift_fuel` | yes | 773.91 µs | ±0.5% | 3.49x | 3.5x |
| `wasmtime_winch` | no | 1.26 ms | ±0.5% | 5.67x | 5.7x |
| `wasmer_singlepass` | no | 4.63 ms | ±1.8% | 20.88x | 20.9x |
| `polkavm64_interpreter` | no | 8.88 ms | ±0.6% | 40.05x | 40.1x |
| `nub_interp` | yes | 13.02 ms | ±0.6% | 58.76x | 58.8x |

### goldilocks-mul

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 194.13 µs | ±0.4% | 1.00x | 1.0x |
| `nub_jit` | yes | 309.79 µs | ±0.3% | 1.60x | 1.6x |
| `polkavm64_recompiler_sync_gas_full` | yes | 349.68 µs | ±0.2% | 1.80x | 1.8x |
| `polkavm64_recompiler_no_gas` | no | 350.66 µs | ±0.0% | 1.81x | 1.8x |
| `polkavm64_recompiler_async_gas` | yes | 365.41 µs | ±0.1% | 1.88x | 1.9x |
| `polkavm64_recompiler_async_gas_full` | yes | 366.12 µs | ±0.2% | 1.89x | 1.9x |
| `polkavm64_recompiler_sync_gas` | yes | 373.54 µs | ±0.8% | 1.92x | 1.9x |
| `wasmtime_cranelift_fuel` | yes | 505.44 µs | ±0.6% | 2.60x | 2.6x |
| `wasmtime_cranelift` | no | 522.30 µs | ±0.5% | 2.69x | 2.7x |
| `wasmtime_winch` | no | 538.98 µs | ±0.7% | 2.78x | 2.8x |
| `wasmer_singlepass` | no | 1.62 ms | ±1.1% | 8.35x | 8.4x |
| `polkavm64_interpreter` | no | 2.09 ms | ±0.6% | 10.75x | 10.7x |
| `nub_interp` | yes | 3.95 ms | ±0.6% | 20.36x | 20.4x |

### keccak

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 1.63 µs | ±0.4% | 1.00x | 1.0x |
| `nub_jit` | yes | 6.50 µs | ±0.4% | 3.99x | 4.0x |
| `wasmtime_cranelift` | no | 7.60 µs | ±1.2% | 4.67x | 4.7x |
| `wasmtime_cranelift_fuel` | yes | 7.81 µs | ±0.7% | 4.80x | 4.8x |
| `wasmtime_winch` | no | 8.43 µs | ±0.8% | 5.18x | 5.2x |
| `polkavm64_recompiler_sync_gas` | yes | 10.98 µs | ±1.2% | 6.74x | 6.7x |
| `polkavm64_recompiler_no_gas` | no | 11.60 µs | ±1.5% | 7.12x | 7.1x |
| `polkavm64_recompiler_sync_gas_full` | yes | 12.08 µs | ±2.4% | 7.42x | 7.4x |
| `polkavm64_recompiler_async_gas` | yes | 12.63 µs | ±1.1% | 7.76x | 7.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 12.64 µs | ±1.0% | 7.76x | 7.8x |
| `wasmer_singlepass` | no | 27.65 µs | ±2.0% | 16.98x | 17.0x |
| `polkavm64_interpreter` | no | 90.40 µs | ±1.2% | 55.53x | 55.5x |
| `nub_interp` | yes | 235.81 µs | ±0.6% | 144.85x | 144.8x |

### mini-verifier

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 225.82 µs | ±0.7% | 1.00x | 1.0x |
| `nub_jit` | yes | 475.52 µs | ±0.5% | 2.11x | 2.1x |
| `polkavm64_recompiler_sync_gas` | yes | 512.33 µs | ±0.1% | 2.27x | 2.3x |
| `polkavm64_recompiler_async_gas_full` | yes | 512.98 µs | ±0.1% | 2.27x | 2.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 513.60 µs | ±0.2% | 2.27x | 2.3x |
| `polkavm64_recompiler_async_gas` | yes | 517.48 µs | ±0.5% | 2.29x | 2.3x |
| `polkavm64_recompiler_no_gas` | no | 582.47 µs | ±0.0% | 2.58x | 2.6x |
| `wasmtime_cranelift` | no | 766.30 µs | ±0.5% | 3.39x | 3.4x |
| `wasmtime_cranelift_fuel` | yes | 785.81 µs | ±0.5% | 3.48x | 3.5x |
| `wasmtime_winch` | no | 1.30 ms | ±0.4% | 5.77x | 5.8x |
| `wasmer_singlepass` | no | 4.38 ms | ±0.6% | 19.38x | 19.4x |
| `polkavm64_interpreter` | no | 9.55 ms | ±0.7% | 42.28x | 42.3x |
| `nub_interp` | yes | 13.52 ms | ±0.6% | 59.89x | 59.9x |

### poly-eval

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 652.67 µs | ±0.3% | 1.00x | 1.0x |
| `nub_jit` | yes | 1.10 ms | ±0.6% | 1.69x | 1.7x |
| `polkavm64_recompiler_no_gas` | no | 1.19 ms | ±0.6% | 1.82x | 1.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.20 ms | ±0.2% | 1.83x | 1.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.21 ms | ±0.4% | 1.86x | 1.9x |
| `polkavm64_recompiler_sync_gas` | yes | 1.22 ms | ±0.3% | 1.87x | 1.9x |
| `polkavm64_recompiler_async_gas` | yes | 1.24 ms | ±0.6% | 1.91x | 1.9x |
| `wasmtime_cranelift_fuel` | yes | 1.48 ms | ±1.0% | 2.27x | 2.3x |
| `wasmtime_cranelift` | no | 1.50 ms | ±0.5% | 2.30x | 2.3x |
| `wasmtime_winch` | no | 1.73 ms | ±0.6% | 2.65x | 2.6x |
| `wasmer_singlepass` | no | 6.08 ms | ±1.1% | 9.31x | 9.3x |
| `polkavm64_interpreter` | no | 8.09 ms | ±0.9% | 12.40x | 12.4x |
| `nub_interp` | yes | 17.40 ms | ±0.9% | 26.65x | 26.7x |

### poseidon2-perm

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 548.84 µs | ±0.2% | 1.00x | 1.0x |
| `nub_jit` | yes | 1.15 ms | ±0.4% | 2.10x | 2.1x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.25 ms | ±0.1% | 2.27x | 2.3x |
| `polkavm64_recompiler_async_gas` | yes | 1.25 ms | ±0.1% | 2.27x | 2.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.25 ms | ±0.1% | 2.28x | 2.3x |
| `polkavm64_recompiler_sync_gas` | yes | 1.25 ms | ±0.1% | 2.28x | 2.3x |
| `polkavm64_recompiler_no_gas` | no | 1.26 ms | ±0.4% | 2.29x | 2.3x |
| `wasmtime_cranelift` | no | 1.88 ms | ±0.8% | 3.42x | 3.4x |
| `wasmtime_cranelift_fuel` | yes | 1.94 ms | ±0.4% | 3.54x | 3.5x |
| `wasmtime_winch` | no | 3.09 ms | ±0.6% | 5.63x | 5.6x |
| `wasmer_singlepass` | no | 10.62 ms | ±0.3% | 19.35x | 19.3x |
| `polkavm64_interpreter` | no | 22.19 ms | ±0.7% | 40.44x | 40.4x |
| `nub_interp` | yes | 34.80 ms | ±0.8% | 63.40x | 63.4x |

### prime-sieve

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 55.60 µs | ±0.6% | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 114.02 µs | ±0.1% | 2.05x | 2.1x |
| `wasmtime_cranelift` | no | 115.06 µs | ±0.6% | 2.07x | 2.1x |
| `wasmer_singlepass` | no | 159.06 µs | ±2.7% | 2.86x | 2.9x |
| `wasmtime_cranelift_fuel` | yes | 166.04 µs | ±0.6% | 2.99x | 3.0x |
| `wasmtime_winch` | no | 169.32 µs | ±0.5% | 3.05x | 3.0x |
| `nub_jit` | yes | 180.14 µs | ±0.5% | 3.24x | 3.2x |
| `polkavm64_recompiler_async_gas_full` | yes | 199.67 µs | ±0.1% | 3.59x | 3.6x |
| `polkavm64_recompiler_async_gas` | yes | 199.73 µs | ±0.1% | 3.59x | 3.6x |
| `polkavm64_recompiler_sync_gas` | yes | 201.11 µs | ±0.1% | 3.62x | 3.6x |
| `polkavm64_recompiler_sync_gas_full` | yes | 216.61 µs | ±0.1% | 3.90x | 3.9x |
| `polkavm64_interpreter` | no | 2.09 ms | ±0.4% | 37.58x | 37.6x |
| `nub_interp` | yes | 8.02 ms | ±0.7% | 144.27x | 144.3x |

## runtime

Steady-state execution: one instance, invoked repeatedly. How fast the engine *executes*, with instantiation excluded.

Rows are absent where a program cannot be re-run in one instance (the three guests with a never-freeing bump arena).

**† — this row still contains per-invocation setup.** nub's invocation model builds a fresh frame and address space on every call by design, so there is no warm state to hoist out. Its figure is therefore *not* comparable to a row that reuses one warm instance; compare it against those rows' `invoke` figures instead, which also pay instantiation.

### blake2b

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 628.9 ns | ±0.9% | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 764.4 ns | ±0.5% | 1.22x | 1.2x |
| `wasmtime_cranelift_fuel` | yes | 790.2 ns | ±0.6% | 1.26x | 1.3x |
| `wasmtime_winch` | no | 1.22 µs | ±0.7% | 1.94x | 1.9x |
| `polkavm64_recompiler_no_gas` | no | 1.41 µs | ±0.4% | 2.24x | 2.2x |
| `polkavm64_recompiler_async_gas_full` | yes | 2.11 µs | ±0.3% | 3.35x | 3.3x |
| `polkavm64_recompiler_sync_gas` | yes | 2.20 µs | ±0.4% | 3.50x | 3.5x |
| `polkavm64_recompiler_async_gas` | yes | 2.34 µs | ±0.5% | 3.73x | 3.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 2.37 µs | ±0.3% | 3.77x | 3.8x |
| `nub_jit` † | yes | 4.56 µs | ±0.5% | 7.26x | 7.3x |
| `wasmer_singlepass` | no | 4.69 µs | ±0.3% | 7.45x | 7.5x |
| `polkavm64_interpreter` | no | 40.43 µs | ±0.7% | 64.29x | 64.3x |
| `nub_interp` | yes | 140.80 µs | ±0.7% | 223.90x | 223.9x |

### ecrecover

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 91.67 µs | ±0.3% | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 252.03 µs | ±0.4% | 2.75x | 2.7x |
| `wasmtime_cranelift_fuel` | yes | 259.77 µs | ±0.4% | 2.83x | 2.8x |
| `polkavm64_recompiler_no_gas` | no | 308.40 µs | ±0.1% | 3.36x | 3.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 320.02 µs | ±0.1% | 3.49x | 3.5x |
| `polkavm64_recompiler_sync_gas` | yes | 320.29 µs | ±0.2% | 3.49x | 3.5x |
| `polkavm64_recompiler_async_gas_full` | yes | 323.06 µs | ±0.1% | 3.52x | 3.5x |
| `polkavm64_recompiler_async_gas` | yes | 323.45 µs | ±0.2% | 3.53x | 3.5x |
| `nub_jit` † | yes | 368.45 µs | ±0.6% | 4.02x | 4.0x |
| `wasmtime_winch` | no | 394.13 µs | ±0.4% | 4.30x | 4.3x |
| `wasmer_singlepass` | no | 762.30 µs | ±0.7% | 8.32x | 8.3x |
| `polkavm64_interpreter` | no | 11.40 ms | ±1.6% | 124.35x | 124.3x |
| `nub_interp` | yes | 26.32 ms | ±0.7% | 287.10x | 287.1x |

### ed25519

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 29.75 µs | ±0.8% | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 65.67 µs | ±0.1% | 2.21x | 2.2x |
| `polkavm64_recompiler_async_gas_full` | yes | 73.76 µs | ±0.1% | 2.48x | 2.5x |
| `polkavm64_recompiler_sync_gas` | yes | 73.88 µs | ±0.1% | 2.48x | 2.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 73.91 µs | ±0.2% | 2.48x | 2.5x |
| `nub_jit` † | yes | 90.61 µs | ±0.7% | 3.05x | 3.0x |
| `polkavm64_recompiler_async_gas` | yes | 91.59 µs | ±0.0% | 3.08x | 3.1x |
| `wasmtime_cranelift` | no | 192.16 µs | ±0.5% | 6.46x | 6.5x |
| `wasmtime_cranelift_fuel` | yes | 232.29 µs | ±0.3% | 7.81x | 7.8x |
| `wasmtime_winch` | no | 340.82 µs | ±0.4% | 11.46x | 11.5x |
| `wasmer_singlepass` | no | 906.42 µs | ±0.3% | 30.47x | 30.5x |
| `polkavm64_interpreter` | no | 1.43 ms | ±0.9% | 48.18x | 48.2x |
| `nub_interp` | yes | 4.80 ms | ±0.8% | 161.38x | 161.4x |

### fri-fold-tree

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 222.21 µs | ±0.4% | 1.00x | 1.0x |
| `nub_jit` † | yes | 456.30 µs | ±0.4% | 2.05x | 2.1x |
| `wasmtime_cranelift` | no | 721.32 µs | ±0.5% | 3.25x | 3.2x |
| `wasmtime_cranelift_fuel` | yes | 748.69 µs | ±0.4% | 3.37x | 3.4x |
| `wasmtime_winch` | no | 1.25 ms | ±0.5% | 5.64x | 5.6x |
| `wasmer_singlepass` | no | 3.61 ms | ±0.3% | 16.26x | 16.3x |

### goldilocks-mul

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 194.84 µs | ±0.5% | 1.00x | 1.0x |
| `nub_jit` † | yes | 307.84 µs | ±0.4% | 1.58x | 1.6x |
| `polkavm64_recompiler_no_gas` | no | 329.01 µs | ±0.1% | 1.69x | 1.7x |
| `polkavm64_recompiler_sync_gas` | yes | 346.00 µs | ±0.1% | 1.78x | 1.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 346.13 µs | ±0.1% | 1.78x | 1.8x |
| `polkavm64_recompiler_async_gas` | yes | 358.34 µs | ±0.1% | 1.84x | 1.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 360.58 µs | ±0.1% | 1.85x | 1.9x |
| `wasmtime_cranelift` | no | 510.14 µs | ±0.5% | 2.62x | 2.6x |
| `wasmtime_cranelift_fuel` | yes | 512.45 µs | ±0.4% | 2.63x | 2.6x |
| `wasmtime_winch` | no | 529.88 µs | ±0.7% | 2.72x | 2.7x |
| `wasmer_singlepass` | no | 1.42 ms | ±0.6% | 7.30x | 7.3x |
| `polkavm64_interpreter` | no | 2.08 ms | ±0.8% | 10.66x | 10.7x |
| `nub_interp` | yes | 3.91 ms | ±0.5% | 20.05x | 20.0x |

### keccak

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 1.61 µs | ±0.6% | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 2.19 µs | ±0.5% | 1.36x | 1.4x |
| `wasmtime_cranelift_fuel` | yes | 2.28 µs | ±0.5% | 1.42x | 1.4x |
| `polkavm64_recompiler_no_gas` | no | 2.37 µs | ±0.2% | 1.48x | 1.5x |
| `wasmtime_winch` | no | 2.70 µs | ±0.4% | 1.68x | 1.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 3.36 µs | ±0.2% | 2.09x | 2.1x |
| `polkavm64_recompiler_sync_gas_full` | yes | 3.39 µs | ±0.3% | 2.10x | 2.1x |
| `wasmer_singlepass` | no | 3.45 µs | ±0.4% | 2.14x | 2.1x |
| `polkavm64_recompiler_sync_gas` | yes | 3.52 µs | ±0.2% | 2.18x | 2.2x |
| `polkavm64_recompiler_async_gas` | yes | 3.53 µs | ±0.2% | 2.19x | 2.2x |
| `nub_jit` † | yes | 6.66 µs | ±0.4% | 4.14x | 4.1x |
| `polkavm64_interpreter` | no | 70.68 µs | ±1.3% | 43.91x | 43.9x |
| `nub_interp` | yes | 230.67 µs | ±0.8% | 143.32x | 143.3x |

### mini-verifier

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 230.80 µs | ±0.3% | 1.00x | 1.0x |
| `nub_jit` † | yes | 467.07 µs | ±0.6% | 2.02x | 2.0x |
| `polkavm64_recompiler_async_gas_full` | yes | 507.94 µs | ±0.2% | 2.20x | 2.2x |
| `polkavm64_recompiler_async_gas` | yes | 508.43 µs | ±0.2% | 2.20x | 2.2x |
| `polkavm64_recompiler_sync_gas` | yes | 509.12 µs | ±0.3% | 2.21x | 2.2x |
| `polkavm64_recompiler_no_gas` | no | 509.14 µs | ±0.3% | 2.21x | 2.2x |
| `polkavm64_recompiler_sync_gas_full` | yes | 509.55 µs | ±0.3% | 2.21x | 2.2x |
| `wasmtime_cranelift` | no | 764.94 µs | ±0.6% | 3.31x | 3.3x |
| `wasmtime_cranelift_fuel` | yes | 794.11 µs | ±0.4% | 3.44x | 3.4x |
| `wasmtime_winch` | no | 1.32 ms | ±0.5% | 5.72x | 5.7x |
| `wasmer_singlepass` | no | 3.95 ms | ±0.5% | 17.11x | 17.1x |
| `polkavm64_interpreter` | no | 9.62 ms | ±0.7% | 41.67x | 41.7x |
| `nub_interp` | yes | 13.66 ms | ±0.4% | 59.18x | 59.2x |

### poly-eval

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 659.94 µs | ±0.4% | 1.00x | 1.0x |
| `nub_jit` † | yes | 1.10 ms | ±0.4% | 1.66x | 1.7x |
| `wasmtime_cranelift_fuel` | yes | 1.47 ms | ±0.4% | 2.23x | 2.2x |
| `wasmtime_cranelift` | no | 1.52 ms | ±0.4% | 2.30x | 2.3x |
| `wasmtime_winch` | no | 1.68 ms | ±0.7% | 2.55x | 2.6x |
| `wasmer_singlepass` | no | 4.93 ms | ±0.4% | 7.48x | 7.5x |

### poseidon2-perm

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 559.16 µs | ±0.4% | 1.00x | 1.0x |
| `nub_jit` † | yes | 1.18 ms | ±0.4% | 2.11x | 2.1x |
| `polkavm64_recompiler_no_gas` | no | 1.24 ms | ±0.2% | 2.22x | 2.2x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.24 ms | ±0.1% | 2.22x | 2.2x |
| `polkavm64_recompiler_async_gas` | yes | 1.24 ms | ±0.2% | 2.22x | 2.2x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.25 ms | ±0.1% | 2.23x | 2.2x |
| `polkavm64_recompiler_sync_gas` | yes | 1.40 ms | ±0.0% | 2.51x | 2.5x |
| `wasmtime_cranelift` | no | 1.88 ms | ±0.7% | 3.36x | 3.4x |
| `wasmtime_cranelift_fuel` | yes | 1.93 ms | ±0.4% | 3.45x | 3.5x |
| `wasmtime_winch` | no | 3.23 ms | ±0.8% | 5.78x | 5.8x |
| `wasmer_singlepass` | no | 9.91 ms | ±0.3% | 17.73x | 17.7x |
| `polkavm64_interpreter` | no | 22.23 ms | ±0.8% | 39.76x | 39.8x |
| `nub_interp` | yes | 34.58 ms | ±0.9% | 61.85x | 61.8x |

### prime-sieve

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 55.25 µs | ±0.6% | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 75.66 µs | ±0.6% | 1.37x | 1.4x |
| `polkavm64_recompiler_no_gas` | no | 88.63 µs | ±4.1% | 1.60x | 1.6x |
| `wasmer_singlepass` | no | 118.26 µs | ±0.7% | 2.14x | 2.1x |
| `wasmtime_cranelift_fuel` | yes | 140.50 µs | ±0.3% | 2.54x | 2.5x |
| `wasmtime_winch` | no | 147.46 µs | ±0.6% | 2.67x | 2.7x |
| `nub_jit` † | yes | 183.77 µs | ±0.9% | 3.33x | 3.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 184.79 µs | ±0.1% | 3.34x | 3.3x |
| `polkavm64_recompiler_async_gas` | yes | 184.86 µs | ±0.2% | 3.35x | 3.3x |
| `polkavm64_recompiler_async_gas_full` | yes | 185.11 µs | ±0.2% | 3.35x | 3.4x |
| `polkavm64_recompiler_sync_gas` | yes | 185.17 µs | ±0.1% | 3.35x | 3.4x |
| `polkavm64_interpreter` | no | 2.09 ms | ±0.6% | 37.85x | 37.9x |
| `nub_interp` | yes | 7.91 ms | ±0.7% | 143.21x | 143.2x |
