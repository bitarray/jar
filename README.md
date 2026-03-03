# Grey

A JAM (Join-Accumulate Machine) blockchain node implementation in Rust, following the [Gray Paper v0.7.2](https://github.com/gavofyork/graypaper/releases/download/v0.7.2/graypaper-0.7.2.pdf).

## Building

```
cargo build
```

## Test Status

**311 tests passing** across all crates.

| Category | Crate | Tests | Status |
|----------|-------|------:|--------|
| Codec (Appendix C) | `grey-codec` | 32 | All passing |
| Cryptography (Section 3.8) | `grey-crypto` | 15 | All passing |
| PVM — Polkadot Virtual Machine (Appendix A) | `grey-pvm` | 31 | All passing |
| Merkle tries (Appendices D & E) | `grey-merkle` | 14 | All passing |
| Erasure coding (Appendix H) | `grey-erasure` | 24 | All passing |
| Safrole consensus (Section 6) | `grey-consensus` | 25 | All passing |
| STF — Safrole | `grey-state` | 21 | All passing |
| STF — Disputes | `grey-state` | 28 | All passing |
| STF — Reports | `grey-state` | 42 | All passing |
| STF — Assurances | `grey-state` | 10 | All passing |
| STF — Accumulate | `grey-state` | 30 | All passing |
| STF — History | `grey-state` | 4 | All passing |
| STF — Preimages | `grey-state` | 8 | All passing |
| STF — Authorizations | `grey-state` | 3 | All passing |
| STF — Statistics | `grey-state` | 3 | All passing |
| State core | `grey-state` | 10 | All passing |
| Services | `grey-services` | 11 | All passing |

### Conformance Testing

Grey includes a conformance target binary (`grey-conform`) that speaks the JAM fuzz-proto v1 protocol over Unix domain sockets, compatible with [minifuzz](https://github.com/davxy/jam-conformance), Polkajam, and Jamzig fuzzers.

**Status**: 8 of 100 blocks passing on the `0.7.2/no_forks` trace (blocks 1–8). Block 9 fails in the third accumulation (host-call issue under investigation).

```bash
# Build
cargo build --release --bin grey-conform

# Run against minifuzz
./target/release/grey-conform /tmp/jam_target.sock &
python res/conformance/minifuzz/minifuzz.py \
  -d res/conformance/fuzz-proto/examples/0.7.2/no_forks \
  --target-sock /tmp/jam_target.sock
```

### Known Spec Issues

See [docs/pvm-sbrk.md](docs/pvm-sbrk.md) for a documented ambiguity in the Gray Paper's `sbrk` definition that caused a conformance failure.

## Project Structure

```
crates/
  grey/              # Binary — node executable + conformance target
  grey-types/        # Core protocol types and constants
  grey-codec/        # JAM serialization (Appendix C)
  grey-crypto/       # Blake2b, Keccak, Ed25519, Bandersnatch, BLS
  grey-pvm/          # Polkadot Virtual Machine (Appendix A)
  grey-merkle/       # Binary Patricia trie, MMR, state serialization (Appendices D & E)
  grey-erasure/      # Reed-Solomon erasure coding (Appendix H)
  grey-state/        # Chain state transitions (Sections 4–13)
  grey-consensus/    # Safrole block production (Section 6)
  grey-services/     # Service accounts, accumulation (Sections 9, 12)
  grey-network/      # P2P networking (scaffolded)
```

## License

See [LICENSE](LICENSE) for details.
