# Grey — Codebase Guide

JAM protocol node in Rust, based on the JAR specification (`../spec/`). Test vectors come from `../spec/tests/vectors/`.

## Crates

```
crates/
  grey/              # Node binary
  grey-types/        # Protocol types and constants
  grey-codec/        # JAM serialization (Appendix C)
  grey-crypto/       # Blake2b, Keccak, Ed25519, Bandersnatch, BLS
  javm/              # PVM — RISC-V rv64em VM (Appendix A)
  grey-merkle/       # Binary Patricia trie, MMR (Appendix D & E)
  grey-erasure/      # Reed-Solomon erasure coding (Appendix H)
  grey-state/        # State transition logic (Sections 4-13)
  grey-consensus/    # Safrole & GRANDPA (Sections 6, 19)
  grey-services/     # Service accounts, accumulation (Sections 9, 12)
  grey-network/      # P2P networking
  grey-transpiler/   # RISC-V ELF to PVM blob transpiler
  grey-bench/        # Benchmarks (criterion)
  grey-rpc/          # RPC interface
  grey-store/        # Storage backend
```

## Build & Test

All commands run from the `grey/` directory.

```bash
cargo test --workspace                  # all tests (interpreter)
GREY_PVM=recompiler cargo test --workspace  # all tests (recompiler)
```

## Benchmarks

```bash
cargo bench -p grey-bench --features javm/signals                        # full suite
cargo bench -p grey-bench --features javm/signals -- 'fib/|sort/'        # skip ecrecover
cargo bench -p grey-bench --features javm/signals -- ecrecover           # ecrecover only
```

## Integration Harness

The integration harness (`harness/`) runs end-to-end scenarios against a local testnet node.

**Running locally:**

```bash
# Step 1: Kill any stale node processes
pkill -9 -f "grey.*testnet" 2>/dev/null; sleep 1

# Step 2: Clean-build the grey node binary (ensures fresh guest blobs + dependencies)
cargo clean -p grey-state && cargo build -p grey

# Step 3: Run the harness with --skip-build --seq-testnet
cargo run --release -p harness -- --skip-build --seq-testnet --scenario serial
```

**Why `--skip-build`:** The harness runs `cargo build -p grey` internally, but cargo fingerprinting doesn't always detect changes in dependency crates (grey-state, grey-transpiler, javm). This causes stale binaries. Always build yourself first (`cargo clean -p grey-state && cargo build -p grey`), then use `--skip-build`.

**Why `cargo clean -p grey-state`:** Cargo may cache .rlib files even after editing source. Cleaning the specific crate forces a rebuild. For transpiler changes, also `cargo clean -p grey-transpiler`.

**Why `--seq-testnet`:** CI uses the sequential (single-process) testnet. Without this flag, the harness spawns a multi-validator network which has a different WP processing path (guarantor + refine pipeline). Use `--seq-testnet` to match CI behavior.

**Scenarios:** serial, repeat, liveness, invalid_wp, recovery, metrics, throughput, consistency

**Reading node logs:**
```bash
# The node writes to /tmp/grey-harness-testnet.log
# Parse it (strips ANSI codes):
python3 -c "
import re
data = open('/tmp/grey-harness-testnet.log', 'rb').read()
clean = re.sub(rb'\x1b\[[0-9;]*m', b'', data).decode('utf-8', errors='replace')
for line in clean.split('\n'):
    if any(k in line for k in ['YOUR_SEARCH_TERM']):
        print(line.strip()[:200])
"
```

## Guidelines

- `#[cfg(test)]` for unit tests
- `thiserror` for errors, `tracing` for logging (not `eprintln!`)
- Strong typing: newtypes for hashes, keys, indices
- Prefer `no_std` where feasible
- Implement PVM from first principles — do not use `polkavm` or `polkavm-common` crates
