import VersoManual
import Jar.JAVM
import Jar.JAVM.Memory
import Jar.JAVM.Decode
import Jar.JAVM.Instructions
import Jar.JAVM.Interpreter
import Jar.JAVM.GasCostSinglePass

open Verso.Genre Manual

set_option verso.docstring.allowMissing true

#doc (Manual) "Join-Accumulate Virtual Machine" =>

The JAVM is the JAR protocol's virtual machine, based on the PVM (Polkadot Virtual
Machine, GP Appendix A). It is a RISC-V rv64em ISA with 13 general-purpose 64-bit
registers, pageable 32-bit-addressable RAM, and approximately 141 opcodes.

# jar1 JAVM Configuration

In jar1, the JAVM is configured differently from the base Gray Paper PVM specification:

- *Capability-based memory*: the flat 4GB address space is managed through DATA
  capabilities. Each DATA cap owns a set of physical pages with exclusive mapping
  and per-page access control. See the *JAVM Capability System* chapter for details.
- *Single-pass gas metering*: basic block gas costs are computed by a single-pass
  O(n) pipeline simulation rather than full pipeline tracking. This models decode
  throughput as the bottleneck, omitting EU contention (which is subsumed by decode
  for the rv64em instruction set).
- *Fixed u32 LE deblob*: program blob headers use u32 little-endian encoding for
  counts and offsets, not the JAM codec's variable-length natural encoding.
- *Capability extensions*: two additional exit reasons (`ecall` for management ops,
  `trap` for deliberate termination) beyond the base PVM's halt/panic/OOG/pageFault/hostCall.
  See the *JAVM Capability System* and *Capability Kernel* chapters for the multi-VM
  execution model.

{docstring Jar.JAVM.gasCostForBlockSinglePass}

# Machine Model

{docstring Jar.JAVM.Reg}

{docstring Jar.JAVM.Registers}

{docstring Jar.JAVM.PageAccess}

{docstring Jar.JAVM.Memory}

{docstring Jar.JAVM.MachineState}

{docstring Jar.JAVM.ExitReason}

{docstring Jar.JAVM.InvocationResult}

{docstring Jar.JAVM.InstructionCategory}

# Program Representation

{docstring Jar.JAVM.Program}

# Memory Operations (Appendix A.4)

{docstring Jar.JAVM.readU8}

{docstring Jar.JAVM.readU16}

{docstring Jar.JAVM.readU32}

{docstring Jar.JAVM.readU64}

{docstring Jar.JAVM.writeU8}

{docstring Jar.JAVM.writeU16}

{docstring Jar.JAVM.writeU32}

{docstring Jar.JAVM.writeU64}

{docstring Jar.JAVM.readByteArray}

{docstring Jar.JAVM.writeByteArray}

{docstring Jar.JAVM.sbrk}

# Instruction Decoding (Appendix A.5)

{docstring Jar.JAVM.sext}

{docstring Jar.JAVM.toSigned}

{docstring Jar.JAVM.toUnsigned}

{docstring Jar.JAVM.djump}

# Instruction Execution (Appendix A.6)

{docstring Jar.JAVM.StepResult}

{docstring Jar.JAVM.executeStep}

# Interpreter

{docstring Jar.JAVM.run}

{docstring Jar.JAVM.initStandard}

{docstring Jar.JAVM.runWithHostCalls}

{docstring Jar.JAVM.invokeStd}

# Capability System

The JAVM extends the base PVM with a capability-based execution model: multiple
concurrent VMs, seL4-style capabilities for memory and code, and synchronous
CALL/REPLY for inter-VM communication. See the *JAVM Capability System* chapter
for capability types, cap tables, VM lifecycle, and ecalli dispatch. See the
*Capability Kernel* chapter for the execution engine.
