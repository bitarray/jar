import Jar.Notation
import Jar.Types
import Jar.Codec
import Jar.Crypto
import Jar.PVM
import Jar.PVM.Decode
import Jar.PVM.Memory
import Jar.PVM.Instructions
import Jar.PVM.Interpreter
import Jar.Merkle
import Jar.Erasure
import Jar.State
import Jar.Consensus
import Jar.Services
import Jar.Accumulation

/-!
# JAR — JAM Axiomatic Reference

Lean 4 formalization of the JAM protocol as specified in the
Gray Paper v0.7.2 (https://graypaper.com).

## Module structure

- `Jar.Notation`  — §3: Custom notation matching Gray Paper conventions
- `Jar.Types`     — §3–4: Core types, constants, and data structures
- `Jar.Codec`     — Appendix C: JAM serialization codec
- `Jar.Crypto`    — §3.8, Appendices F–G: Cryptographic primitives
- `Jar.PVM`       — Appendix A: Polkadot Virtual Machine
- `Jar.Merkle`    — Appendices D–E: Merklization and Merkle tries
- `Jar.Erasure`   — Appendix H: Reed-Solomon erasure coding
- `Jar.State`     — §4–13: State transition function
- `Jar.Consensus` — §6, §19: Safrole and GRANDPA
- `Jar.Services`  — §9, §12, §14: Service accounts and work pipeline
- `Jar.PVM.Decode` — Appendix A: Instruction decoding and deblob
- `Jar.PVM.Memory` — Appendix A: Memory read/write with fault detection
- `Jar.PVM.Instructions` — Appendix A: All ~141 PVM opcodes
- `Jar.PVM.Interpreter` — Appendix A: Execution loop Ψ and standard init
- `Jar.Accumulation` — §12: Accumulation pipeline (accseq/accpar/accone)
-/
