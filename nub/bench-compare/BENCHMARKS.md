# nub benchmark comparison

## Cold recompile + execute, metered JIT engines

The bench target. Each sample starts with no compiled code and ends with the program having run — the cost a VM pays when a work-package arrives, is turned into native code, and executed once. Metering on.

Storage is deliberately excluded. Getting a blob *into* an engine's object store is dominated by hashing and belongs to a different subsystem than the recompiler; for nub that step is measured separately under `compilation`.

Only cost models comparable to nub's appear here. PolkaVM's default `Simple` model is a flat per-instruction cost and is much cheaper to evaluate than nub's pipeline simulation, so the `*_full` rows (`CacheModel::L2Hit`, whose `memory_access_cost: 25` is exactly nub's `MEM_CYCLES_BASE`) are the like-for-like comparison. Full tables for every engine and every measurement kind follow below.

A cell carries a `±` only when its confidence interval is wider than 2% of the median. Where that happens the cell is a range, not a number, and two engines inside each other's interval are not separable by this measurement.

**`sbpf_jit` is not like-for-like on every row.** It is missing three kernels the sBPF platform cannot express, and on the five `gp`-backed ones it runs a different multiply, because LLVM's BPF backend has no widening multiply. Those cells measure a different program, not only a different VM — see *Reading the `sbpf_*` rows* below before drawing a conclusion from them.

| Program | `nub_jit` | `polkavm64_recompiler_sync_gas_full` | `polkavm64_recompiler_async_gas_full` | `wasmtime_cranelift_fuel` | `sbpf_jit` |
|---|--:|--:|--:|--:|--:|
| ecrecover | **1.19 ms** (1.00x) | 1.85 ms (1.55x) | 1.83 ms (1.53x) | 44.66 ms (37.42x) | - |
| mini-verifier | **544.68 µs** (1.00x) | 623.64 µs (1.14x) | 653.72 µs (1.20x) | 3.83 ms (7.04x) | 6.42 ms (11.79x) |
| poseidon2-perm | **1.18 ms** (1.00x) | 1.45 ms (1.23x) | 1.47 ms (1.25x) | 4.43 ms (3.76x) | 16.02 ms (13.60x) |
| keccak | **42.72 µs** (1.00x) | 59.35 µs (1.39x) | 58.51 µs (1.37x) | 2.91 ms (68.15x) | 234.89 µs (5.50x) |
| blake2b | **65.04 µs** (1.00x) | 117.69 µs (1.81x) | 118.27 µs (1.82x) | 3.48 ms (53.49x) | 183.84 µs (2.83x) |
| goldilocks-mul | **351.43 µs** (1.00x) | 359.42 µs (1.02x) | 378.53 µs (1.08x) | 1.02 ms (2.90x) | 677.80 µs (1.93x) |
| prime-sieve | **226.42 µs** (1.00x) | 231.43 µs (1.02x) | 228.66 µs (1.01x) | 1.04 ms (4.59x) | - |
| fri-fold-tree | **537.82 µs** (1.00x) | 634.55 µs (1.18x) | 631.34 µs (1.17x) | 12.25 ms (22.77x) | 5.99 ms (11.13x) |
| poly-eval | **1.14 ms** (1.00x) | 1.20 ms (1.05x) | 1.30 ms (1.14x) | 9.97 ms (8.72x) | 4.83 ms (4.22x) |
| ed25519 | **495.11 µs** (1.00x) | 658.03 µs (1.33x) | 647.25 µs (1.31x) | 29.88 ms (60.36x) | - |

Bold = fastest for that program; the multiple is versus it.

### Where that time goes

The same rows with **compilation excluded** — a fresh instance per sample, then execute. Every engine pays instantiation here, so this is like-for-like even for nub, which rebuilds its frame on every call and therefore has no warm state to hoist out.

The bracketed figure is the difference against the table above: what the recompile costs that engine.

| Program | `nub_jit` | `polkavm64_recompiler_sync_gas_full` | `polkavm64_recompiler_async_gas_full` | `wasmtime_cranelift_fuel` | `sbpf_jit` |
|---|--:|--:|--:|--:|--:|
| ecrecover | 371.21 µs (+822.35 µs recompile) | 334.94 µs (+1.52 ms recompile) | 443.00 µs (+1.39 ms recompile) | 273.14 µs (+44.39 ms recompile) | - |
| mini-verifier | 471.39 µs (+73.29 µs recompile) | 518.11 µs (+105.53 µs recompile) | 517.21 µs (+136.51 µs recompile) | 797.98 µs (+3.04 ms recompile) | 6.42 ms (+897.6 ns recompile) |
| poseidon2-perm | 1.17 ms (+9.29 µs recompile) | 1.25 ms (+198.70 µs recompile) | 1.25 ms (+219.29 µs recompile) | 1.95 ms (+2.48 ms recompile) | 16.03 ms (cold < invoke — unstable) |
| keccak | 6.56 µs (+36.16 µs recompile) | 12.89 µs (+46.46 µs recompile) | 12.86 µs (+45.65 µs recompile) | 7.73 µs (+2.90 ms recompile) | 176.60 µs (+58.29 µs recompile) |
| blake2b | 4.65 µs (+60.39 µs recompile) | 9.53 µs (+108.17 µs recompile) | 9.84 µs (+108.44 µs recompile) | 5.68 µs (+3.47 ms recompile) | 69.25 µs (+114.59 µs recompile) |
| goldilocks-mul | 307.39 µs (+44.04 µs recompile) | 349.92 µs (+9.50 µs recompile) | 365.30 µs (+13.23 µs recompile) | 511.79 µs (+509.12 µs recompile) | 632.05 µs (+45.76 µs recompile) |
| prime-sieve | 180.39 µs (+46.02 µs recompile) | 201.05 µs (+30.38 µs recompile) | 200.39 µs (+28.27 µs recompile) | 165.01 µs (+875.27 µs recompile) | - |
| fri-fold-tree | 458.05 µs (+79.77 µs recompile) | 500.19 µs (+134.37 µs recompile) | 500.81 µs (+130.53 µs recompile) | 775.47 µs (+11.47 ms recompile) | 5.81 ms (+181.87 µs recompile) |
| poly-eval | 1.11 ms (+35.63 µs recompile) | 1.14 ms (+59.35 µs recompile) | 1.21 ms (+95.71 µs recompile) | 1.49 ms (+8.47 ms recompile) | 4.70 ms (+122.57 µs recompile) |
| ed25519 | 93.31 µs (+401.79 µs recompile) | 82.78 µs (+575.25 µs recompile) | 99.53 µs (+547.72 µs recompile) | 244.43 µs (+29.64 ms recompile) | - |


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

### Reading the `sbpf_*` rows

**Seven of ten kernels.** `prime-sieve` needs a writable global, which the sBPF container cannot express; `ecrecover` needs ~3.8 KB of k256 lookup tables in one frame against a 4 KiB limit (which is why Solana ships `secp256k1_recover` as a syscall); `ed25519-compact`'s field arithmetic is 76 `u128` sites. All three are platform properties — Solana's own toolchain hits the same walls — not artifacts of how these were built.

**Five of the seven run a different multiply.** LLVM's BPF backend cannot lower a 64x64 widening multiply, so `gp::mul` has a `cfg(target_arch = "bpf")` arm reassembling the product from four 32x32 partials. It is proven bit-identical, so every engine agrees on the same value — but `goldilocks-mul`, `poseidon2-perm`, `mini-verifier`, `poly-eval` and `fri-fold-tree` are measuring a *different program* here, not just a different VM. Do not read those five as like-for-like.

Heap sizing (256 KiB, against Solana's on-chain 32 KiB default) is a harness choice so the workloads fit, in the same spirit as setting gas counters to maximum. Stack and frame limits are solana-sbpf's own defaults, because those are the ISA.


## cold

**The bench target.** Cold recompile + execute: each sample begins with no compiled code and ends with the program having run.

Storage is excluded. An eager engine compiles inside the clock; nub compiles lazily on first entry, so it publishes once up front (untimed) and its JIT cache is evicted before each sample (also untimed), leaving `run` to recompile. Both shapes measure the same thing against different designs.

### blake2b

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 15.24 µs | ±0.7% | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 39.94 µs | ±0.8% | 2.62x | 2.6x |
| `polkavm64_recompiler_async_gas` | yes | 40.73 µs | ±1.0% | 2.67x | 2.7x |
| `polkavm64_recompiler_sync_gas` | yes | 40.87 µs | ±0.3% | 2.68x | 2.7x |
| `nub_jit` | yes | 65.04 µs | ±0.6% | 4.27x | 4.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 117.69 µs | ±0.6% | 7.72x | 7.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 118.27 µs | ±0.6% | 7.76x | 7.8x |
| `polkavm64_interpreter` | no | 127.69 µs | ±0.5% | 8.38x | 8.4x |
| `sbpf_interpreter` | yes | 178.65 µs | ±0.7% | 11.72x | 11.7x |
| `sbpf_jit` | yes | 183.84 µs | ±0.5% | 12.06x | 12.1x |
| `nub_interp` | yes | 237.09 µs | ±1.1% | 15.55x | 15.6x |
| `wasmtime_winch` | no | 440.23 µs | ±0.5% | 28.88x | 28.9x |
| `wasmer_singlepass` | no | 1.94 ms | ±2.2% | 127.02x | 127.0x |
| `wasmtime_cranelift` | no | 3.29 ms | ±0.7% | 215.94x | 215.9x |
| `wasmtime_cranelift_fuel` | yes | 3.48 ms | ±0.3% | 228.22x | 228.2x |

### ecrecover

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 112.23 µs | ±0.4% | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 684.12 µs | ±0.1% | 6.10x | 6.1x |
| `polkavm64_recompiler_async_gas` | yes | 717.89 µs | ±0.3% | 6.40x | 6.4x |
| `polkavm64_recompiler_sync_gas` | yes | 738.48 µs | ±0.5% | 6.58x | 6.6x |
| `nub_jit` | yes | 1.19 ms | ±0.7% | 10.64x | 10.6x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.83 ms | ±0.2% | 16.31x | 16.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.85 ms | ±0.2% | 16.50x | 16.5x |
| `wasmtime_winch` | no | 5.35 ms | ±0.4% | 47.71x | 47.7x |
| `wasmer_singlepass` | no | 7.40 ms | ±1.2% | 65.95x | 66.0x |
| `polkavm64_interpreter` | no | 13.05 ms | ±0.7% | 116.24x | 116.2x |
| `nub_interp` | yes | 27.76 ms | ±0.7% | 247.32x | 247.3x |
| `wasmtime_cranelift` | no | 36.30 ms | ±0.4% | 323.49x | 323.5x |
| `wasmtime_cranelift_fuel` | yes | 44.66 ms | ±0.4% | 397.93x | 397.9x |

### ed25519

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 45.95 µs | ±0.4% | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 211.55 µs | ±0.2% | 4.60x | 4.6x |
| `polkavm64_recompiler_async_gas` | yes | 222.48 µs | ±0.6% | 4.84x | 4.8x |
| `polkavm64_recompiler_sync_gas` | yes | 224.81 µs | ±0.6% | 4.89x | 4.9x |
| `nub_jit` | yes | 495.11 µs | ±0.6% | 10.77x | 10.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 647.25 µs | ±0.8% | 14.09x | 14.1x |
| `polkavm64_recompiler_sync_gas_full` | yes | 658.03 µs | ±0.4% | 14.32x | 14.3x |
| `polkavm64_interpreter` | no | 2.06 ms | ±0.6% | 44.72x | 44.7x |
| `wasmtime_winch` | no | 3.17 ms | ±0.4% | 68.95x | 69.0x |
| `nub_interp` | yes | 5.30 ms | ±0.7% | 115.40x | 115.4x |
| `wasmer_singlepass` | no | 7.71 ms | ±1.3% | 167.84x | 167.8x |
| `wasmtime_cranelift` | no | 23.58 ms | ±0.6% | 513.23x | 513.2x |
| `wasmtime_cranelift_fuel` | yes | 29.88 ms | ±0.4% | 650.37x | 650.4x |

### fri-fold-tree

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 234.93 µs | ±0.4% | 1.00x | 1.0x |
| `nub_jit` | yes | 537.82 µs | ±0.5% | 2.29x | 2.3x |
| `polkavm64_recompiler_async_gas` | yes | 589.79 µs | ±0.5% | 2.51x | 2.5x |
| `polkavm64_recompiler_no_gas` | no | 598.09 µs | ±0.2% | 2.55x | 2.5x |
| `polkavm64_recompiler_sync_gas` | yes | 601.38 µs | ±0.1% | 2.56x | 2.6x |
| `polkavm64_recompiler_async_gas_full` | yes | 631.34 µs | ±0.4% | 2.69x | 2.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 634.55 µs | ±0.6% | 2.70x | 2.7x |
| `wasmtime_winch` | no | 2.93 ms | ±0.4% | 12.47x | 12.5x |
| `sbpf_jit` | yes | 5.99 ms | ±0.4% | 25.49x | 25.5x |
| `wasmer_singlepass` | no | 7.57 ms | ±1.3% | 32.23x | 32.2x |
| `wasmtime_cranelift` | no | 8.79 ms | ±1.0% | 37.42x | 37.4x |
| `polkavm64_interpreter` | no | 9.82 ms | ±0.6% | 41.79x | 41.8x |
| `wasmtime_cranelift_fuel` | yes | 12.25 ms | ±0.7% | 52.14x | 52.1x |
| `nub_interp` | yes | 13.93 ms | ±0.8% | 59.31x | 59.3x |
| `sbpf_interpreter` | yes | 28.26 ms | ±0.8% | 120.28x | 120.3x |

### goldilocks-mul

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 214.76 µs | ±0.6% | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 341.77 µs | ±0.2% | 1.59x | 1.6x |
| `nub_jit` | yes | 351.43 µs | ±0.6% | 1.64x | 1.6x |
| `polkavm64_recompiler_sync_gas_full` | yes | 359.42 µs | ±0.1% | 1.67x | 1.7x |
| `polkavm64_recompiler_async_gas` | yes | 372.15 µs | ±0.1% | 1.73x | 1.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 378.53 µs | ±0.4% | 1.76x | 1.8x |
| `polkavm64_recompiler_sync_gas` | yes | 394.66 µs | ±0.0% | 1.84x | 1.8x |
| `sbpf_jit` | yes | 677.80 µs | ±0.5% | 3.16x | 3.2x |
| `wasmtime_winch` | no | 766.67 µs | ±0.6% | 3.57x | 3.6x |
| `wasmtime_cranelift` | no | 911.86 µs | ±0.7% | 4.25x | 4.2x |
| `wasmtime_cranelift_fuel` | yes | 1.02 ms | ±0.5% | 4.75x | 4.8x |
| `polkavm64_interpreter` | no | 2.42 ms | ±0.6% | 11.26x | 11.3x |
| `wasmer_singlepass` | no | 2.96 ms | ±2.4% | 13.79x | 13.8x |
| `nub_interp` | yes | 4.05 ms | ±1.1% | 18.88x | 18.9x |
| `sbpf_interpreter` | yes | 10.17 ms | ±0.9% | 47.34x | 47.3x |

### keccak

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 16.54 µs | ±0.3% | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 32.72 µs | ±1.1% | 1.98x | 2.0x |
| `polkavm64_recompiler_async_gas` | yes | 33.80 µs | ±1.1% | 2.04x | 2.0x |
| `polkavm64_recompiler_sync_gas` | yes | 34.01 µs | ±0.5% | 2.06x | 2.1x |
| `nub_jit` | yes | 42.72 µs | ±0.4% | 2.58x | 2.6x |
| `polkavm64_recompiler_async_gas_full` | yes | 58.51 µs | ±0.6% | 3.54x | 3.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 59.35 µs | ±0.5% | 3.59x | 3.6x |
| `polkavm64_interpreter` | no | 109.01 µs | ±0.8% | 6.59x | 6.6x |
| `sbpf_jit` | yes | 234.89 µs | ±0.4% | 14.21x | 14.2x |
| `nub_interp` | yes | 278.27 µs | ±0.9% | 16.83x | 16.8x |
| `sbpf_interpreter` | yes | 331.01 µs | ±0.7% | 20.02x | 20.0x |
| `wasmtime_winch` | no | 812.71 µs | ±0.5% | 49.15x | 49.2x |
| `wasmer_singlepass` | no | 1.66 ms | ±1.3% | 100.37x | 100.4x |
| `wasmtime_cranelift` | no | 2.18 ms | ±0.6% | 131.56x | 131.6x |
| `wasmtime_cranelift_fuel` | yes | 2.91 ms | ±0.5% | 176.06x | 176.1x |

### mini-verifier

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 247.95 µs | ±0.3% | 1.00x | 1.0x |
| `nub_jit` | yes | 544.68 µs | ±0.7% | 2.20x | 2.2x |
| `polkavm64_recompiler_no_gas` | no | 601.69 µs | ±1.5% | 2.43x | 2.4x |
| `polkavm64_recompiler_sync_gas` | yes | 601.70 µs | ±0.2% | 2.43x | 2.4x |
| `polkavm64_recompiler_async_gas` | yes | 612.65 µs | ±0.1% | 2.47x | 2.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 623.64 µs | ±0.3% | 2.52x | 2.5x |
| `polkavm64_recompiler_async_gas_full` | yes | 653.72 µs | ±0.0% | 2.64x | 2.6x |
| `wasmtime_winch` | no | 1.84 ms | ±0.4% | 7.41x | 7.4x |
| `wasmtime_cranelift` | no | 3.26 ms | ±0.3% | 13.17x | 13.2x |
| `wasmtime_cranelift_fuel` | yes | 3.83 ms | ±0.4% | 15.47x | 15.5x |
| `wasmer_singlepass` | no | 6.26 ms | ±1.3% | 25.24x | 25.2x |
| `sbpf_jit` | yes | 6.42 ms | ±0.3% | 25.89x | 25.9x |
| `polkavm64_interpreter` | no | 10.52 ms | ±1.0% | 42.42x | 42.4x |
| `nub_interp` | yes | 14.53 ms | ±0.9% | 58.62x | 58.6x |
| `sbpf_interpreter` | yes | 30.10 ms | ±0.4% | 121.40x | 121.4x |

### poly-eval

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 691.82 µs | ±0.3% | 1.00x | 1.0x |
| `nub_jit` | yes | 1.14 ms | ±0.4% | 1.65x | 1.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.20 ms | ±1.6% | 1.74x | 1.7x |
| `polkavm64_recompiler_no_gas` | no | 1.23 ms | ±0.2% | 1.77x | 1.8x |
| `polkavm64_recompiler_sync_gas` | yes | 1.25 ms | ±1.0% | 1.80x | 1.8x |
| `polkavm64_recompiler_async_gas` | yes | 1.29 ms | ±0.0% | 1.87x | 1.9x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.30 ms | ±0.8% | 1.89x | 1.9x |
| `wasmtime_winch` | no | 3.05 ms | ±0.5% | 4.41x | 4.4x |
| `sbpf_jit` | yes | 4.83 ms | ±0.5% | 6.98x | 7.0x |
| `wasmtime_cranelift` | no | 7.01 ms | ±0.4% | 10.13x | 10.1x |
| `wasmer_singlepass` | no | 8.73 ms | ±1.6% | 12.62x | 12.6x |
| `polkavm64_interpreter` | no | 9.07 ms | ±1.2% | 13.11x | 13.1x |
| `wasmtime_cranelift_fuel` | yes | 9.97 ms | ±0.5% | 14.40x | 14.4x |
| `nub_interp` | yes | 17.73 ms | ±0.8% | 25.63x | 25.6x |
| `sbpf_interpreter` | yes | 33.13 ms | ±0.4% | 47.88x | 47.9x |

### poseidon2-perm

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 579.74 µs | ±0.5% | 1.00x | 1.0x |
| `nub_jit` | yes | 1.18 ms | ±0.4% | 2.03x | 2.0x |
| `polkavm64_recompiler_no_gas` | no | 1.41 ms | ±0.4% | 2.43x | 2.4x |
| `polkavm64_recompiler_async_gas` | yes | 1.41 ms | ±0.4% | 2.44x | 2.4x |
| `polkavm64_recompiler_sync_gas` | yes | 1.42 ms | ±0.8% | 2.45x | 2.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.45 ms | ±0.5% | 2.51x | 2.5x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.47 ms | ±0.0% | 2.53x | 2.5x |
| `wasmtime_winch` | no | 3.63 ms | ±0.4% | 6.27x | 6.3x |
| `wasmtime_cranelift` | no | 3.93 ms | ±0.5% | 6.78x | 6.8x |
| `wasmtime_cranelift_fuel` | yes | 4.43 ms | ±0.4% | 7.64x | 7.6x |
| `wasmer_singlepass` | no | 12.56 ms | ±1.5% | 21.66x | 21.7x |
| `sbpf_jit` | yes | 16.02 ms | ±0.3% | 27.64x | 27.6x |
| `polkavm64_interpreter` | no | 24.49 ms | ±0.4% | 42.25x | 42.2x |
| `nub_interp` | yes | 36.42 ms | ±0.5% | 62.81x | 62.8x |
| `sbpf_interpreter` | yes | 75.81 ms | ±0.6% | 130.77x | 130.8x |

### prime-sieve

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 90.12 µs | ±0.4% | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 126.82 µs | ±0.2% | 1.41x | 1.4x |
| `polkavm64_recompiler_async_gas` | yes | 220.49 µs | ±0.4% | 2.45x | 2.4x |
| `polkavm64_recompiler_sync_gas` | yes | 221.56 µs | ±0.6% | 2.46x | 2.5x |
| `nub_jit` | yes | 226.42 µs | ±0.6% | 2.51x | 2.5x |
| `polkavm64_recompiler_async_gas_full` | yes | 228.66 µs | ±0.8% | 2.54x | 2.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 231.43 µs | ±0.3% | 2.57x | 2.6x |
| `wasmtime_winch` | no | 559.56 µs | ±0.5% | 6.21x | 6.2x |
| `wasmtime_cranelift` | no | 650.97 µs | ±0.7% | 7.22x | 7.2x |
| `wasmtime_cranelift_fuel` | yes | 1.04 ms | ±0.4% | 11.54x | 11.5x |
| `wasmer_singlepass` | no | 1.55 ms | ±1.1% | 17.21x | 17.2x |
| `polkavm64_interpreter` | no | 2.11 ms | ±0.6% | 23.44x | 23.4x |
| `nub_interp` | yes | 8.24 ms | ±0.3% | 91.41x | 91.4x |

## compilation

Turning the program into executable form. Engine construction and file loading are excluded (a once-per-process cost, and the harness's own I/O). `native` is absent: the OS loader already did it.

**`nub_jit` measures publishing here, not codegen** — and publishing is *not* part of the bench target above. nub keeps its object store *inside* the sandbox, so this is the cost of shipping a blob across the VM boundary, decoding it, content-hashing it and materializing its data image. It is dominated by hashing and scales with blob size, not code size. `nub_jit_compile` is the codegen-only figure.

### blake2b

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `sbpf_interpreter` | yes | 10.60 µs | ±0.5% | 1.00x | - |
| `polkavm64_interpreter` | no | 17.91 µs | ±0.6% | 1.69x | - |
| `polkavm64_recompiler_no_gas` | no | 19.28 µs | ±0.4% | 1.82x | - |
| `polkavm64_recompiler_async_gas` | yes | 19.34 µs | ±0.4% | 1.82x | - |
| `polkavm64_recompiler_sync_gas` | yes | 19.34 µs | ±0.3% | 1.83x | - |
| `nub_jit_compile` | yes | 46.09 µs | ±0.3% | 4.35x | - |
| `sbpf_jit` | yes | 55.19 µs | ±0.2% | 5.21x | - |
| `nub_jit` | yes | 65.86 µs | ±0.3% | 6.22x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 99.36 µs | ±0.6% | 9.38x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 99.55 µs | ±0.5% | 9.39x | - |
| `wasmtime_winch` | no | 421.56 µs | ±0.3% | 39.79x | - |
| `wasmer_singlepass` | no | 935.60 µs | ±3.0% | 88.30x | - |
| `wasmtime_cranelift` | no | 3.30 ms | ±0.4% | 311.10x | - |
| `wasmtime_cranelift_fuel` | yes | 3.50 ms | ±0.2% | 330.06x | - |

### ecrecover

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `polkavm64_interpreter` | no | 196.56 µs | ±0.8% | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 260.17 µs | ±0.4% | 1.32x | - |
| `polkavm64_recompiler_async_gas` | yes | 260.22 µs | ±0.6% | 1.32x | - |
| `polkavm64_recompiler_sync_gas` | yes | 262.68 µs | ±0.5% | 1.34x | - |
| `nub_jit` | yes | 618.32 µs | ±0.5% | 3.15x | - |
| `nub_jit_compile` | yes | 788.47 µs | ±0.6% | 4.01x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.33 ms | ±0.8% | 6.75x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 1.34 ms | ±0.7% | 6.83x | - |
| `wasmer_singlepass` | no | 3.16 ms | ±1.4% | 16.08x | - |
| `wasmtime_winch` | no | 4.91 ms | ±0.7% | 24.98x | - |
| `wasmtime_cranelift` | no | 36.49 ms | ±0.3% | 185.65x | - |
| `wasmtime_cranelift_fuel` | yes | 45.35 ms | ±0.3% | 230.72x | - |

### ed25519

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `polkavm64_interpreter` | no | 84.39 µs | ±1.0% | 1.00x | - |
| `polkavm64_recompiler_no_gas` | no | 111.64 µs | ±0.4% | 1.32x | - |
| `polkavm64_recompiler_async_gas` | yes | 113.42 µs | ±0.4% | 1.34x | - |
| `polkavm64_recompiler_sync_gas` | yes | 113.49 µs | ±0.4% | 1.34x | - |
| `nub_jit` | yes | 288.25 µs | ±0.4% | 3.42x | - |
| `nub_jit_compile` | yes | 367.63 µs | ±0.6% | 4.36x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 525.16 µs | ±0.5% | 6.22x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 530.00 µs | ±0.6% | 6.28x | - |
| `wasmtime_winch` | no | 2.75 ms | ±0.5% | 32.62x | - |
| `wasmer_singlepass` | no | 3.41 ms | ±0.5% | 40.38x | - |
| `wasmtime_cranelift` | no | 24.25 ms | ±0.8% | 287.36x | - |
| `wasmtime_cranelift_fuel` | yes | 30.00 ms | ±0.4% | 355.54x | - |

### fri-fold-tree

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `sbpf_interpreter` | yes | 5.90 µs | ±0.8% | 1.00x | - |
| `polkavm64_interpreter` | no | 9.78 µs | ±0.6% | 1.66x | - |
| `polkavm64_recompiler_no_gas` | no | 11.10 µs | ±0.5% | 1.88x | - |
| `polkavm64_recompiler_async_gas` | yes | 11.16 µs | ±0.5% | 1.89x | - |
| `polkavm64_recompiler_sync_gas` | yes | 11.31 µs | ±0.3% | 1.92x | - |
| `nub_jit_compile` | yes | 27.94 µs | ±0.6% | 4.73x | - |
| `sbpf_jit` | yes | 42.09 µs | ±0.7% | 7.13x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 53.67 µs | ±0.6% | 9.09x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 53.96 µs | ±0.7% | 9.14x | - |
| `nub_jit` | yes | 73.68 µs | ±0.4% | 12.48x | - |
| `wasmer_singlepass` | no | 1.43 ms | ±0.7% | 241.53x | - |
| `wasmtime_winch` | no | 1.63 ms | ±0.6% | 276.89x | - |
| `wasmtime_cranelift` | no | 8.15 ms | ±0.6% | 1380.91x | - |
| `wasmtime_cranelift_fuel` | yes | 11.67 ms | ±0.5% | 1976.80x | - |

### goldilocks-mul

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `sbpf_interpreter` | yes | 243.7 ns | ±0.7% | 1.00x | - |
| `polkavm64_interpreter` | no | 357.4 ns | ±0.5% | 1.47x | - |
| `nub_jit_compile` | yes | 1.29 µs | ±0.5% | 5.30x | - |
| `polkavm64_recompiler_no_gas` | no | 1.60 µs | ±0.4% | 6.55x | - |
| `polkavm64_recompiler_sync_gas` | yes | 1.62 µs | ±0.4% | 6.64x | - |
| `polkavm64_recompiler_async_gas` | yes | 1.64 µs | ±0.7% | 6.74x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 3.17 µs | ±0.5% | 12.99x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 3.22 µs | ±0.7% | 13.22x | - |
| `sbpf_jit` | yes | 4.20 µs | ±0.8% | 17.25x | - |
| `nub_jit` | yes | 24.81 µs | ±0.4% | 101.78x | - |
| `wasmtime_winch` | no | 207.89 µs | ±0.2% | 852.95x | - |
| `wasmtime_cranelift` | no | 370.20 µs | ±0.4% | 1518.85x | - |
| `wasmtime_cranelift_fuel` | yes | 498.96 µs | ±0.3% | 2047.15x | - |
| `wasmer_singlepass` | no | 647.58 µs | ±1.8% | 2656.92x | - |

### keccak

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `sbpf_interpreter` | yes | 2.44 µs | ±0.7% | 1.00x | - |
| `polkavm64_interpreter` | no | 6.81 µs | ±0.4% | 2.79x | - |
| `polkavm64_recompiler_no_gas` | no | 7.62 µs | ±0.5% | 3.12x | - |
| `polkavm64_recompiler_sync_gas` | yes | 7.63 µs | ±0.3% | 3.12x | - |
| `polkavm64_recompiler_async_gas` | yes | 7.64 µs | ±0.4% | 3.13x | - |
| `nub_jit_compile` | yes | 9.50 µs | ±0.4% | 3.88x | - |
| `sbpf_jit` | yes | 17.25 µs | ±0.3% | 7.06x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 34.36 µs | ±0.4% | 14.06x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 34.52 µs | ±0.4% | 14.12x | - |
| `nub_jit` | yes | 36.05 µs | ±0.5% | 14.75x | - |
| `wasmtime_winch` | no | 765.84 µs | ±0.4% | 313.30x | - |
| `wasmer_singlepass` | no | 795.50 µs | ±1.7% | 325.43x | - |
| `wasmtime_cranelift` | no | 2.15 ms | ±0.4% | 879.07x | - |
| `wasmtime_cranelift_fuel` | yes | 2.89 ms | ±0.5% | 1183.11x | - |

### mini-verifier

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `sbpf_interpreter` | yes | 5.70 µs | ±0.8% | 1.00x | - |
| `polkavm64_interpreter` | no | 9.61 µs | ±0.4% | 1.69x | - |
| `polkavm64_recompiler_no_gas` | no | 9.76 µs | ±0.3% | 1.71x | - |
| `polkavm64_recompiler_async_gas` | yes | 9.81 µs | ±0.5% | 1.72x | - |
| `polkavm64_recompiler_sync_gas` | yes | 10.36 µs | ±0.5% | 1.82x | - |
| `nub_jit_compile` | yes | 27.47 µs | ±0.2% | 4.82x | - |
| `sbpf_jit` | yes | 40.58 µs | ±0.6% | 7.12x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 51.71 µs | ±0.4% | 9.08x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 51.95 µs | ±0.6% | 9.12x | - |
| `nub_jit` | yes | 55.13 µs | ±0.5% | 9.68x | - |
| `wasmtime_winch` | no | 558.15 µs | ±0.6% | 98.00x | - |
| `wasmer_singlepass` | no | 930.13 µs | ±1.5% | 163.31x | - |
| `wasmtime_cranelift` | no | 2.50 ms | ±0.3% | 438.42x | - |
| `wasmtime_cranelift_fuel` | yes | 2.98 ms | ±0.5% | 523.53x | - |

### poly-eval

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `sbpf_interpreter` | yes | 762.8 ns | ±1.6% | 1.00x | - |
| `polkavm64_interpreter` | no | 1.72 µs | ±0.5% | 2.26x | - |
| `polkavm64_recompiler_no_gas` | no | 3.02 µs | ±0.5% | 3.96x | - |
| `polkavm64_recompiler_async_gas` | yes | 3.15 µs | ±0.2% | 4.13x | - |
| `polkavm64_recompiler_sync_gas` | yes | 3.22 µs | ±0.6% | 4.23x | - |
| `sbpf_jit` | yes | 8.25 µs | ±0.5% | 10.81x | - |
| `nub_jit_compile` | yes | 9.52 µs | ±0.3% | 12.49x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 11.06 µs | ±0.4% | 14.50x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 11.23 µs | ±0.5% | 14.72x | - |
| `nub_jit` | yes | 32.90 µs | ±0.3% | 43.14x | - |
| `wasmtime_winch` | no | 1.30 ms | ±0.5% | 1706.90x | - |
| `wasmer_singlepass` | no | 1.35 ms | ±0.8% | 1768.29x | - |
| `wasmtime_cranelift` | no | 5.47 ms | ±0.5% | 7169.07x | - |
| `wasmtime_cranelift_fuel` | yes | 8.48 ms | ±0.5% | 11117.93x | - |

### poseidon2-perm

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `sbpf_interpreter` | yes | 4.75 µs | ±0.9% | 1.00x | - |
| `polkavm64_interpreter` | no | 7.57 µs | ±0.7% | 1.59x | - |
| `polkavm64_recompiler_no_gas` | no | 7.87 µs | ±0.4% | 1.66x | - |
| `polkavm64_recompiler_async_gas` | yes | 7.91 µs | ±0.4% | 1.66x | - |
| `polkavm64_recompiler_sync_gas` | yes | 7.94 µs | ±0.4% | 1.67x | - |
| `nub_jit_compile` | yes | 23.17 µs | ±0.4% | 4.87x | - |
| `sbpf_jit` | yes | 35.37 µs | ±0.4% | 7.44x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 37.29 µs | ±0.4% | 7.84x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 37.83 µs | ±0.5% | 7.96x | - |
| `nub_jit` | yes | 47.99 µs | ±0.6% | 10.09x | - |
| `wasmtime_winch` | no | 468.37 µs | ±0.2% | 98.51x | - |
| `wasmer_singlepass` | no | 893.39 µs | ±2.6% | 187.91x | - |
| `wasmtime_cranelift` | no | 2.00 ms | ±0.3% | 419.92x | - |
| `wasmtime_cranelift_fuel` | yes | 2.46 ms | ±0.4% | 516.50x | - |

### prime-sieve

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `polkavm64_interpreter` | no | 1.84 µs | ±0.4% | 1.00x | - |
| `nub_jit_compile` | yes | 3.63 µs | ±0.6% | 1.97x | - |
| `polkavm64_recompiler_sync_gas` | yes | 4.83 µs | ±0.6% | 2.62x | - |
| `polkavm64_recompiler_no_gas` | no | 4.84 µs | ±0.5% | 2.63x | - |
| `polkavm64_recompiler_async_gas` | yes | 4.85 µs | ±0.6% | 2.63x | - |
| `polkavm64_recompiler_sync_gas_full` | yes | 7.06 µs | ±0.6% | 3.83x | - |
| `polkavm64_recompiler_async_gas_full` | yes | 7.13 µs | ±0.7% | 3.86x | - |
| `wasmtime_winch` | no | 334.14 µs | ±0.5% | 181.15x | - |
| `wasmtime_cranelift` | no | 485.11 µs | ±0.4% | 262.99x | - |
| `nub_jit` | yes | 493.98 µs | ±0.8% | 267.80x | - |
| `wasmer_singlepass` | no | 742.09 µs | ±2.3% | 402.30x | - |
| `wasmtime_cranelift_fuel` | yes | 821.91 µs | ±0.2% | 445.58x | - |

## invoke

Cold invocation with compilation excluded: a fresh instance every sample. Where an engine's *instantiation* strategy shows up. Compare against `runtime` for the same row to see what a cold start costs it.

### blake2b

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 632.9 ns | ±0.5% | 1.00x | 1.0x |
| `nub_jit` | yes | 4.65 µs | ±0.5% | 7.35x | 7.4x |
| `wasmtime_cranelift` | no | 5.52 µs | ±1.2% | 8.71x | 8.7x |
| `wasmtime_cranelift_fuel` | yes | 5.68 µs | ±1.1% | 8.97x | 9.0x |
| `wasmtime_winch` | no | 6.13 µs | ±0.9% | 9.69x | 9.7x |
| `polkavm64_recompiler_no_gas` | no | 8.39 µs | ±6.5% | 13.26x | 13.3x |
| `polkavm64_recompiler_sync_gas` | yes | 8.53 µs | ±1.1% | 13.47x | 13.5x |
| `polkavm64_recompiler_async_gas` | yes | 8.64 µs | ±1.6% | 13.66x | 13.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 9.53 µs | ±3.2% | 15.05x | 15.0x |
| `polkavm64_recompiler_async_gas_full` | yes | 9.84 µs | ±1.2% | 15.54x | 15.5x |
| `wasmer_singlepass` | no | 46.46 µs | ±5.4% | 73.41x | 73.4x |
| `sbpf_jit` | yes | 69.25 µs | ±0.5% | 109.41x | 109.4x |
| `polkavm64_interpreter` | no | 103.96 µs | ±0.3% | 164.24x | 164.2x |
| `sbpf_interpreter` | yes | 132.97 µs | ±0.7% | 210.08x | 210.1x |
| `nub_interp` | yes | 156.62 µs | ±0.6% | 247.45x | 247.5x |

### ecrecover

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 94.25 µs | ±0.6% | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 261.53 µs | ±0.5% | 2.77x | 2.8x |
| `wasmtime_cranelift_fuel` | yes | 273.14 µs | ±0.6% | 2.90x | 2.9x |
| `polkavm64_recompiler_sync_gas` | yes | 334.45 µs | ±0.2% | 3.55x | 3.5x |
| `polkavm64_recompiler_async_gas` | yes | 334.47 µs | ±0.2% | 3.55x | 3.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 334.94 µs | ±0.2% | 3.55x | 3.6x |
| `nub_jit` | yes | 371.21 µs | ±0.5% | 3.94x | 3.9x |
| `polkavm64_recompiler_no_gas` | no | 411.76 µs | ±0.0% | 4.37x | 4.4x |
| `wasmtime_winch` | no | 414.59 µs | ±0.5% | 4.40x | 4.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 443.00 µs | ±0.4% | 4.70x | 4.7x |
| `wasmer_singlepass` | no | 1.17 ms | ±2.2% | 12.39x | 12.4x |
| `polkavm64_interpreter` | no | 12.87 ms | ±0.5% | 136.55x | 136.6x |
| `nub_interp` | yes | 26.96 ms | ±0.7% | 286.04x | 286.0x |

### ed25519

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 29.45 µs | ±0.4% | 1.00x | 1.0x |
| `polkavm64_recompiler_async_gas` | yes | 82.21 µs | ±0.4% | 2.79x | 2.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 82.78 µs | ±0.3% | 2.81x | 2.8x |
| `polkavm64_recompiler_no_gas` | no | 90.32 µs | ±0.4% | 3.07x | 3.1x |
| `nub_jit` | yes | 93.31 µs | ±0.4% | 3.17x | 3.2x |
| `polkavm64_recompiler_async_gas_full` | yes | 99.53 µs | ±0.8% | 3.38x | 3.4x |
| `polkavm64_recompiler_sync_gas` | yes | 99.87 µs | ±0.4% | 3.39x | 3.4x |
| `wasmtime_cranelift` | no | 198.79 µs | ±0.7% | 6.75x | 6.8x |
| `wasmtime_cranelift_fuel` | yes | 244.43 µs | ±0.4% | 8.30x | 8.3x |
| `wasmtime_winch` | no | 350.10 µs | ±0.4% | 11.89x | 11.9x |
| `wasmer_singlepass` | no | 1.28 ms | ±2.0% | 43.38x | 43.4x |
| `polkavm64_interpreter` | no | 1.90 ms | ±0.7% | 64.54x | 64.5x |
| `nub_interp` | yes | 4.92 ms | ±0.6% | 167.09x | 167.1x |

### fri-fold-tree

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 222.18 µs | ±0.6% | 1.00x | 1.0x |
| `nub_jit` | yes | 458.05 µs | ±0.4% | 2.06x | 2.1x |
| `polkavm64_recompiler_sync_gas` | yes | 499.11 µs | ±0.1% | 2.25x | 2.2x |
| `polkavm64_recompiler_async_gas` | yes | 499.66 µs | ±0.2% | 2.25x | 2.2x |
| `polkavm64_recompiler_no_gas` | no | 500.01 µs | ±0.2% | 2.25x | 2.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 500.19 µs | ±0.1% | 2.25x | 2.3x |
| `polkavm64_recompiler_async_gas_full` | yes | 500.81 µs | ±0.2% | 2.25x | 2.3x |
| `wasmtime_cranelift` | no | 749.05 µs | ±0.5% | 3.37x | 3.4x |
| `wasmtime_cranelift_fuel` | yes | 775.47 µs | ±0.4% | 3.49x | 3.5x |
| `wasmtime_winch` | no | 1.27 ms | ±0.4% | 5.72x | 5.7x |
| `wasmer_singlepass` | no | 4.50 ms | ±2.0% | 20.28x | 20.3x |
| `sbpf_jit` | yes | 5.81 ms | ±0.5% | 26.13x | 26.1x |
| `polkavm64_interpreter` | no | 9.83 ms | ±0.8% | 44.26x | 44.3x |
| `nub_interp` | yes | 13.75 ms | ±0.4% | 61.87x | 61.9x |
| `sbpf_interpreter` | yes | 28.08 ms | ±0.7% | 126.38x | 126.4x |

### goldilocks-mul

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 194.06 µs | ±0.4% | 1.00x | 1.0x |
| `nub_jit` | yes | 307.39 µs | ±0.9% | 1.58x | 1.6x |
| `polkavm64_recompiler_no_gas` | no | 332.07 µs | ±0.1% | 1.71x | 1.7x |
| `polkavm64_recompiler_sync_gas` | yes | 349.37 µs | ±0.2% | 1.80x | 1.8x |
| `polkavm64_recompiler_sync_gas_full` | yes | 349.92 µs | ±0.3% | 1.80x | 1.8x |
| `polkavm64_recompiler_async_gas` | yes | 365.23 µs | ±0.1% | 1.88x | 1.9x |
| `polkavm64_recompiler_async_gas_full` | yes | 365.30 µs | ±0.1% | 1.88x | 1.9x |
| `wasmtime_cranelift_fuel` | yes | 511.79 µs | ±0.5% | 2.64x | 2.6x |
| `wasmtime_cranelift` | no | 521.36 µs | ±0.9% | 2.69x | 2.7x |
| `wasmtime_winch` | no | 545.60 µs | ±0.6% | 2.81x | 2.8x |
| `sbpf_jit` | yes | 632.05 µs | ±0.8% | 3.26x | 3.3x |
| `wasmer_singlepass` | no | 1.64 ms | ±1.4% | 8.45x | 8.4x |
| `polkavm64_interpreter` | no | 2.37 ms | ±0.7% | 12.21x | 12.2x |
| `nub_interp` | yes | 3.97 ms | ±0.3% | 20.45x | 20.4x |
| `sbpf_interpreter` | yes | 10.18 ms | ±0.4% | 52.47x | 52.5x |

### keccak

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 1.64 µs | ±0.6% | 1.00x | 1.0x |
| `nub_jit` | yes | 6.56 µs | ±0.4% | 4.01x | 4.0x |
| `wasmtime_cranelift` | no | 7.64 µs | ±1.5% | 4.67x | 4.7x |
| `wasmtime_cranelift_fuel` | yes | 7.73 µs | ±0.9% | 4.72x | 4.7x |
| `wasmtime_winch` | no | 8.36 µs | ±1.2% | 5.11x | 5.1x |
| `polkavm64_recompiler_no_gas` | no | 10.53 µs | ±5.2% | 6.43x | 6.4x |
| `polkavm64_recompiler_sync_gas` | yes | 10.84 µs | ±1.3% | 6.62x | 6.6x |
| `polkavm64_recompiler_async_gas` | yes | 10.98 µs | ±1.8% | 6.71x | 6.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 12.86 µs | ±0.8% | 7.86x | 7.9x |
| `polkavm64_recompiler_sync_gas_full` | yes | 12.89 µs | ±0.9% | 7.88x | 7.9x |
| `wasmer_singlepass` | no | 27.56 µs | ±1.9% | 16.85x | 16.8x |
| `polkavm64_interpreter` | no | 100.77 µs | ±0.8% | 61.60x | 61.6x |
| `sbpf_jit` | yes | 176.60 µs | ±0.4% | 107.95x | 107.9x |
| `nub_interp` | yes | 239.30 µs | ±1.1% | 146.27x | 146.3x |
| `sbpf_interpreter` | yes | 302.32 µs | ±0.7% | 184.79x | 184.8x |

### mini-verifier

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 231.78 µs | ±0.3% | 1.00x | 1.0x |
| `nub_jit` | yes | 471.39 µs | ±0.5% | 2.03x | 2.0x |
| `polkavm64_recompiler_sync_gas` | yes | 515.96 µs | ±0.2% | 2.23x | 2.2x |
| `polkavm64_recompiler_async_gas_full` | yes | 517.21 µs | ±0.5% | 2.23x | 2.2x |
| `polkavm64_recompiler_sync_gas_full` | yes | 518.11 µs | ±0.4% | 2.24x | 2.2x |
| `polkavm64_recompiler_async_gas` | yes | 519.56 µs | ±0.6% | 2.24x | 2.2x |
| `polkavm64_recompiler_no_gas` | no | 521.32 µs | ±0.7% | 2.25x | 2.2x |
| `wasmtime_cranelift` | no | 781.66 µs | ±0.4% | 3.37x | 3.4x |
| `wasmtime_cranelift_fuel` | yes | 797.98 µs | ±0.5% | 3.44x | 3.4x |
| `wasmtime_winch` | no | 1.32 ms | ±0.5% | 5.68x | 5.7x |
| `wasmer_singlepass` | no | 4.43 ms | ±1.6% | 19.10x | 19.1x |
| `sbpf_jit` | yes | 6.42 ms | ±0.7% | 27.69x | 27.7x |
| `polkavm64_interpreter` | no | 10.66 ms | ±0.7% | 45.99x | 46.0x |
| `nub_interp` | yes | 14.41 ms | ±0.8% | 62.19x | 62.2x |
| `sbpf_interpreter` | yes | 29.98 ms | ±0.4% | 129.36x | 129.4x |

### poly-eval

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 666.59 µs | ±0.6% | 1.00x | 1.0x |
| `nub_jit` | yes | 1.11 ms | ±0.6% | 1.66x | 1.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.14 ms | ±0.1% | 1.71x | 1.7x |
| `polkavm64_recompiler_sync_gas` | yes | 1.14 ms | ±0.2% | 1.72x | 1.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.21 ms | ±0.4% | 1.81x | 1.8x |
| `polkavm64_recompiler_async_gas` | yes | 1.21 ms | ±0.2% | 1.82x | 1.8x |
| `polkavm64_recompiler_no_gas` | no | 1.21 ms | ±0.2% | 1.82x | 1.8x |
| `wasmtime_cranelift_fuel` | yes | 1.49 ms | ±0.6% | 2.24x | 2.2x |
| `wasmtime_cranelift` | no | 1.52 ms | ±0.4% | 2.28x | 2.3x |
| `wasmtime_winch` | no | 1.70 ms | ±0.6% | 2.55x | 2.5x |
| `sbpf_jit` | yes | 4.70 ms | ±0.4% | 7.06x | 7.1x |
| `wasmer_singlepass` | no | 5.84 ms | ±1.0% | 8.77x | 8.8x |
| `polkavm64_interpreter` | no | 9.06 ms | ±1.4% | 13.59x | 13.6x |
| `nub_interp` | yes | 17.70 ms | ±0.8% | 26.55x | 26.6x |
| `sbpf_interpreter` | yes | 33.36 ms | ±0.7% | 50.05x | 50.0x |

### poseidon2-perm

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 558.51 µs | ±0.7% | 1.00x | 1.0x |
| `nub_jit` | yes | 1.17 ms | ±0.5% | 2.09x | 2.1x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.25 ms | ±0.1% | 2.24x | 2.2x |
| `polkavm64_recompiler_no_gas` | no | 1.25 ms | ±0.3% | 2.24x | 2.2x |
| `polkavm64_recompiler_async_gas` | yes | 1.25 ms | ±0.1% | 2.24x | 2.2x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.25 ms | ±0.1% | 2.25x | 2.2x |
| `polkavm64_recompiler_sync_gas` | yes | 1.26 ms | ±0.2% | 2.25x | 2.2x |
| `wasmtime_cranelift` | no | 1.91 ms | ±0.5% | 3.42x | 3.4x |
| `wasmtime_cranelift_fuel` | yes | 1.95 ms | ±0.3% | 3.49x | 3.5x |
| `wasmtime_winch` | no | 3.31 ms | ±0.4% | 5.92x | 5.9x |
| `wasmer_singlepass` | no | 10.61 ms | ±0.1% | 18.99x | 19.0x |
| `sbpf_jit` | yes | 16.03 ms | ±0.4% | 28.70x | 28.7x |
| `polkavm64_interpreter` | no | 24.66 ms | ±0.7% | 44.16x | 44.2x |
| `nub_interp` | yes | 36.51 ms | ±0.8% | 65.37x | 65.4x |
| `sbpf_interpreter` | yes | 76.03 ms | ±1.0% | 136.13x | 136.1x |

### prime-sieve

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 55.49 µs | ±0.5% | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 104.19 µs | ±0.4% | 1.88x | 1.9x |
| `wasmtime_cranelift` | no | 115.89 µs | ±0.9% | 2.09x | 2.1x |
| `wasmtime_cranelift_fuel` | yes | 165.01 µs | ±0.6% | 2.97x | 3.0x |
| `wasmtime_winch` | no | 171.11 µs | ±0.5% | 3.08x | 3.1x |
| `wasmer_singlepass` | no | 171.31 µs | ±3.4% | 3.09x | 3.1x |
| `nub_jit` | yes | 180.39 µs | ±1.0% | 3.25x | 3.3x |
| `polkavm64_recompiler_async_gas` | yes | 199.76 µs | ±0.1% | 3.60x | 3.6x |
| `polkavm64_recompiler_async_gas_full` | yes | 200.39 µs | ±0.1% | 3.61x | 3.6x |
| `polkavm64_recompiler_sync_gas_full` | yes | 201.05 µs | ±0.1% | 3.62x | 3.6x |
| `polkavm64_recompiler_sync_gas` | yes | 201.27 µs | ±0.2% | 3.63x | 3.6x |
| `polkavm64_interpreter` | no | 2.10 ms | ±1.0% | 37.83x | 37.8x |
| `nub_interp` | yes | 8.09 ms | ±0.6% | 145.82x | 145.8x |

## runtime

Steady-state execution: one instance, invoked repeatedly. How fast the engine *executes*, with instantiation excluded.

Rows are absent where a program cannot be re-run in one instance (the three guests with a never-freeing bump arena).

**† — this row still contains per-invocation setup.** nub's invocation model builds a fresh frame and address space on every call by design, so there is no warm state to hoist out. Its figure is therefore *not* comparable to a row that reuses one warm instance; compare it against those rows' `invoke` figures instead, which also pay instantiation.

### blake2b

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 639.5 ns | ±0.7% | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 767.8 ns | ±0.7% | 1.20x | 1.2x |
| `wasmtime_cranelift_fuel` | yes | 797.9 ns | ±0.4% | 1.25x | 1.2x |
| `wasmtime_winch` | no | 1.24 µs | ±0.4% | 1.94x | 1.9x |
| `polkavm64_recompiler_no_gas` | no | 1.41 µs | ±0.4% | 2.20x | 2.2x |
| `polkavm64_recompiler_async_gas` | yes | 2.16 µs | ±0.3% | 3.38x | 3.4x |
| `polkavm64_recompiler_sync_gas_full` | yes | 2.17 µs | ±0.2% | 3.40x | 3.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 2.27 µs | ±0.2% | 3.55x | 3.6x |
| `polkavm64_recompiler_sync_gas` | yes | 2.45 µs | ±0.5% | 3.83x | 3.8x |
| `nub_jit` † | yes | 4.75 µs | ±0.3% | 7.43x | 7.4x |
| `wasmer_singlepass` | no | 4.75 µs | ±0.7% | 7.43x | 7.4x |
| `polkavm64_interpreter` | no | 45.05 µs | ±0.6% | 70.44x | 70.4x |
| `sbpf_jit` | yes | 61.54 µs | ±0.5% | 96.24x | 96.2x |
| `sbpf_interpreter` | yes | 129.71 µs | ±0.5% | 202.85x | 202.8x |
| `nub_interp` | yes | 145.62 µs | ±0.7% | 227.72x | 227.7x |

### ecrecover

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 93.93 µs | ±0.5% | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 252.56 µs | ±0.4% | 2.69x | 2.7x |
| `wasmtime_cranelift_fuel` | yes | 261.00 µs | ±0.9% | 2.78x | 2.8x |
| `polkavm64_recompiler_no_gas` | no | 311.29 µs | ±0.4% | 3.31x | 3.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 321.74 µs | ±0.3% | 3.43x | 3.4x |
| `polkavm64_recompiler_sync_gas` | yes | 322.34 µs | ±0.5% | 3.43x | 3.4x |
| `polkavm64_recompiler_async_gas_full` | yes | 324.55 µs | ±0.3% | 3.46x | 3.5x |
| `polkavm64_recompiler_async_gas` | yes | 325.37 µs | ±0.3% | 3.46x | 3.5x |
| `nub_jit` † | yes | 371.39 µs | ±0.4% | 3.95x | 4.0x |
| `wasmtime_winch` | no | 409.75 µs | ±0.3% | 4.36x | 4.4x |
| `wasmer_singlepass` | no | 765.26 µs | ±0.5% | 8.15x | 8.1x |
| `polkavm64_interpreter` | no | 12.01 ms | ±0.8% | 127.84x | 127.8x |
| `nub_interp` | yes | 26.88 ms | ±0.5% | 286.13x | 286.1x |

### ed25519

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 29.74 µs | ±0.6% | 1.00x | 1.0x |
| `polkavm64_recompiler_no_gas` | no | 65.74 µs | ±0.2% | 2.21x | 2.2x |
| `polkavm64_recompiler_async_gas_full` | yes | 73.63 µs | ±0.1% | 2.48x | 2.5x |
| `polkavm64_recompiler_sync_gas` | yes | 73.78 µs | ±0.1% | 2.48x | 2.5x |
| `polkavm64_recompiler_sync_gas_full` | yes | 91.38 µs | ±0.0% | 3.07x | 3.1x |
| `polkavm64_recompiler_async_gas` | yes | 91.60 µs | ±0.0% | 3.08x | 3.1x |
| `nub_jit` † | yes | 93.37 µs | ±0.3% | 3.14x | 3.1x |
| `wasmtime_cranelift` | no | 190.39 µs | ±0.7% | 6.40x | 6.4x |
| `wasmtime_cranelift_fuel` | yes | 237.30 µs | ±0.3% | 7.98x | 8.0x |
| `wasmtime_winch` | no | 341.80 µs | ±0.3% | 11.49x | 11.5x |
| `wasmer_singlepass` | no | 908.94 µs | ±0.5% | 30.57x | 30.6x |
| `polkavm64_interpreter` | no | 1.62 ms | ±0.7% | 54.53x | 54.5x |
| `nub_interp` | yes | 4.89 ms | ±0.5% | 164.58x | 164.6x |

### fri-fold-tree

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 223.02 µs | ±0.4% | 1.00x | 1.0x |
| `nub_jit` † | yes | 454.29 µs | ±0.6% | 2.04x | 2.0x |
| `wasmtime_cranelift` | no | 728.80 µs | ±0.4% | 3.27x | 3.3x |
| `wasmtime_cranelift_fuel` | yes | 756.82 µs | ±0.5% | 3.39x | 3.4x |
| `wasmtime_winch` | no | 1.27 ms | ±0.8% | 5.70x | 5.7x |
| `wasmer_singlepass` | no | 3.64 ms | ±0.4% | 16.30x | 16.3x |
| `sbpf_jit` | yes | 5.84 ms | ±0.5% | 26.16x | 26.2x |
| `sbpf_interpreter` | yes | 28.20 ms | ±0.5% | 126.45x | 126.4x |

### goldilocks-mul

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 196.56 µs | ±0.7% | 1.00x | 1.0x |
| `nub_jit` † | yes | 306.40 µs | ±0.4% | 1.56x | 1.6x |
| `polkavm64_recompiler_no_gas` | no | 331.61 µs | ±0.2% | 1.69x | 1.7x |
| `polkavm64_recompiler_sync_gas_full` | yes | 346.89 µs | ±0.1% | 1.76x | 1.8x |
| `polkavm64_recompiler_sync_gas` | yes | 347.46 µs | ±0.3% | 1.77x | 1.8x |
| `polkavm64_recompiler_async_gas_full` | yes | 359.63 µs | ±0.1% | 1.83x | 1.8x |
| `polkavm64_recompiler_async_gas` | yes | 359.99 µs | ±0.3% | 1.83x | 1.8x |
| `wasmtime_cranelift_fuel` | yes | 511.29 µs | ±0.5% | 2.60x | 2.6x |
| `wasmtime_cranelift` | no | 517.32 µs | ±0.6% | 2.63x | 2.6x |
| `wasmtime_winch` | no | 532.74 µs | ±0.7% | 2.71x | 2.7x |
| `sbpf_jit` | yes | 658.01 µs | ±0.5% | 3.35x | 3.3x |
| `wasmer_singlepass` | no | 1.45 ms | ±0.6% | 7.36x | 7.4x |
| `polkavm64_interpreter` | no | 2.38 ms | ±0.8% | 12.12x | 12.1x |
| `nub_interp` | yes | 4.00 ms | ±0.7% | 20.34x | 20.3x |
| `sbpf_interpreter` | yes | 10.18 ms | ±0.7% | 51.78x | 51.8x |

### keccak

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 1.64 µs | ±0.2% | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 2.17 µs | ±0.4% | 1.32x | 1.3x |
| `wasmtime_cranelift_fuel` | yes | 2.28 µs | ±0.5% | 1.40x | 1.4x |
| `polkavm64_recompiler_no_gas` | no | 2.37 µs | ±0.2% | 1.45x | 1.4x |
| `wasmtime_winch` | no | 2.70 µs | ±0.6% | 1.65x | 1.7x |
| `polkavm64_recompiler_async_gas_full` | yes | 3.36 µs | ±0.2% | 2.05x | 2.1x |
| `wasmer_singlepass` | no | 3.50 µs | ±0.3% | 2.14x | 2.1x |
| `polkavm64_recompiler_async_gas` | yes | 3.51 µs | ±0.1% | 2.14x | 2.1x |
| `polkavm64_recompiler_sync_gas_full` | yes | 3.53 µs | ±0.1% | 2.16x | 2.2x |
| `polkavm64_recompiler_sync_gas` | yes | 3.96 µs | ±0.0% | 2.42x | 2.4x |
| `nub_jit` † | yes | 6.54 µs | ±0.4% | 3.99x | 4.0x |
| `polkavm64_interpreter` | no | 80.26 µs | ±0.3% | 49.05x | 49.1x |
| `sbpf_jit` | yes | 175.11 µs | ±0.4% | 107.01x | 107.0x |
| `nub_interp` | yes | 237.69 µs | ±0.6% | 145.26x | 145.3x |
| `sbpf_interpreter` | yes | 297.20 µs | ±0.7% | 181.62x | 181.6x |

### mini-verifier

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 227.86 µs | ±0.6% | 1.00x | 1.0x |
| `nub_jit` † | yes | 471.62 µs | ±0.3% | 2.07x | 2.1x |
| `polkavm64_recompiler_async_gas` | yes | 510.08 µs | ±0.2% | 2.24x | 2.2x |
| `polkavm64_recompiler_sync_gas_full` | yes | 510.20 µs | ±0.3% | 2.24x | 2.2x |
| `polkavm64_recompiler_sync_gas` | yes | 511.12 µs | ±0.2% | 2.24x | 2.2x |
| `polkavm64_recompiler_no_gas` | no | 512.57 µs | ±0.6% | 2.25x | 2.2x |
| `polkavm64_recompiler_async_gas_full` | yes | 574.03 µs | ±0.1% | 2.52x | 2.5x |
| `wasmtime_cranelift` | no | 780.06 µs | ±0.3% | 3.42x | 3.4x |
| `wasmtime_cranelift_fuel` | yes | 790.30 µs | ±0.7% | 3.47x | 3.5x |
| `wasmtime_winch` | no | 1.32 ms | ±1.0% | 5.81x | 5.8x |
| `wasmer_singlepass` | no | 3.97 ms | ±0.5% | 17.42x | 17.4x |
| `sbpf_jit` | yes | 6.26 ms | ±0.6% | 27.49x | 27.5x |
| `polkavm64_interpreter` | no | 10.60 ms | ±0.3% | 46.54x | 46.5x |
| `nub_interp` | yes | 14.42 ms | ±0.7% | 63.28x | 63.3x |
| `sbpf_interpreter` | yes | 29.87 ms | ±0.5% | 131.09x | 131.1x |

### poly-eval

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 668.99 µs | ±0.4% | 1.00x | 1.0x |
| `nub_jit` † | yes | 1.11 ms | ±0.4% | 1.65x | 1.7x |
| `wasmtime_cranelift_fuel` | yes | 1.48 ms | ±0.5% | 2.21x | 2.2x |
| `wasmtime_cranelift` | no | 1.50 ms | ±0.5% | 2.24x | 2.2x |
| `wasmtime_winch` | no | 1.67 ms | ±0.4% | 2.50x | 2.5x |
| `sbpf_jit` | yes | 4.68 ms | ±0.3% | 6.99x | 7.0x |
| `wasmer_singlepass` | no | 4.96 ms | ±0.3% | 7.41x | 7.4x |
| `sbpf_interpreter` | yes | 33.16 ms | ±0.5% | 49.57x | 49.6x |

### poseidon2-perm

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 558.46 µs | ±0.8% | 1.00x | 1.0x |
| `nub_jit` † | yes | 1.17 ms | ±0.4% | 2.10x | 2.1x |
| `polkavm64_recompiler_async_gas_full` | yes | 1.24 ms | ±0.2% | 2.23x | 2.2x |
| `polkavm64_recompiler_async_gas` | yes | 1.25 ms | ±0.2% | 2.23x | 2.2x |
| `polkavm64_recompiler_sync_gas` | yes | 1.25 ms | ±0.4% | 2.24x | 2.2x |
| `polkavm64_recompiler_sync_gas_full` | yes | 1.25 ms | ±0.3% | 2.25x | 2.2x |
| `polkavm64_recompiler_no_gas` | no | 1.37 ms | ±0.6% | 2.46x | 2.5x |
| `wasmtime_cranelift` | no | 1.90 ms | ±0.6% | 3.41x | 3.4x |
| `wasmtime_cranelift_fuel` | yes | 1.95 ms | ±0.3% | 3.49x | 3.5x |
| `wasmtime_winch` | no | 3.10 ms | ±0.6% | 5.54x | 5.5x |
| `wasmer_singlepass` | no | 9.75 ms | ±0.8% | 17.46x | 17.5x |
| `sbpf_jit` | yes | 15.99 ms | ±0.5% | 28.63x | 28.6x |
| `polkavm64_interpreter` | no | 24.51 ms | ±0.9% | 43.90x | 43.9x |
| `nub_interp` | yes | 36.50 ms | ±0.4% | 65.35x | 65.4x |
| `sbpf_interpreter` | yes | 76.61 ms | ±0.4% | 137.18x | 137.2x |

### prime-sieve

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 56.07 µs | ±0.5% | 1.00x | 1.0x |
| `wasmtime_cranelift` | no | 77.89 µs | ±1.8% | 1.39x | 1.4x |
| `polkavm64_recompiler_no_gas` | no | 90.57 µs | ±0.1% | 1.62x | 1.6x |
| `wasmer_singlepass` | no | 120.34 µs | ±0.4% | 2.15x | 2.1x |
| `wasmtime_cranelift_fuel` | yes | 143.36 µs | ±0.5% | 2.56x | 2.6x |
| `wasmtime_winch` | no | 147.66 µs | ±0.5% | 2.63x | 2.6x |
| `nub_jit` † | yes | 184.75 µs | ±0.6% | 3.29x | 3.3x |
| `polkavm64_recompiler_sync_gas_full` | yes | 185.05 µs | ±0.1% | 3.30x | 3.3x |
| `polkavm64_recompiler_async_gas_full` | yes | 185.27 µs | ±0.2% | 3.30x | 3.3x |
| `polkavm64_recompiler_async_gas` | yes | 189.63 µs | ±0.8% | 3.38x | 3.4x |
| `polkavm64_recompiler_sync_gas` | yes | 199.60 µs | ±0.2% | 3.56x | 3.6x |
| `polkavm64_interpreter` | no | 2.09 ms | ±0.5% | 37.33x | 37.3x |
| `nub_interp` | yes | 8.01 ms | ±0.9% | 142.79x | 142.8x |
