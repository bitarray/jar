# nub benchmark comparison


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

### prime-sieve

| Engine | Metered | Time | ± | vs fastest | vs native |
|---|---|--:|--:|--:|--:|
| `native` | no | 91.36 µs | ±0.6% | 1.00x | 1.0x |
| `nub_interp` | yes | 8.37 ms | ±0.3% | 91.65x | 91.6x |
