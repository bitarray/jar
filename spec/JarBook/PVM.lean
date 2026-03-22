import VersoManual
import Jar.PVM
import Jar.PVM.Memory
import Jar.PVM.Decode
import Jar.PVM.Instructions
import Jar.PVM.Interpreter

open Verso.Genre Manual

set_option verso.docstring.allowMissing true

#doc (Manual) "Polkadot Virtual Machine" =>

The PVM is a RISC-V rv64em-based virtual machine for executing service code
(GP Appendix A). It has 13 general-purpose 64-bit registers, pageable
32-bit-addressable RAM, and approximately 141 opcodes.

# Machine Model

{docstring Jar.PVM.Reg}

{docstring Jar.PVM.Registers}

{docstring Jar.PVM.PageAccess}

{docstring Jar.PVM.Memory}

{docstring Jar.PVM.MachineState}

{docstring Jar.PVM.ExitReason}

{docstring Jar.PVM.InvocationResult}

{docstring Jar.PVM.InstructionCategory}

# Program Representation

{docstring Jar.PVM.Program}

# Memory Operations (Appendix A.4)

{docstring Jar.PVM.readU8}

{docstring Jar.PVM.readU16}

{docstring Jar.PVM.readU32}

{docstring Jar.PVM.readU64}

{docstring Jar.PVM.writeU8}

{docstring Jar.PVM.writeU16}

{docstring Jar.PVM.writeU32}

{docstring Jar.PVM.writeU64}

{docstring Jar.PVM.readByteArray}

{docstring Jar.PVM.writeByteArray}

{docstring Jar.PVM.sbrk}

# Instruction Decoding (Appendix A.5)

{docstring Jar.PVM.sext}

{docstring Jar.PVM.toSigned}

{docstring Jar.PVM.toUnsigned}

{docstring Jar.PVM.djump}

# Instruction Execution (Appendix A.6)

{docstring Jar.PVM.StepResult}

{docstring Jar.PVM.executeStep}

# Interpreter

{docstring Jar.PVM.run}

{docstring Jar.PVM.initStandard}

{docstring Jar.PVM.runWithHostCalls}

{docstring Jar.PVM.invokeStd}
