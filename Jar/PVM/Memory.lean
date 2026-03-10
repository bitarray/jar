import Jar.PVM
import Jar.PVM.Decode

/-!
# PVM Memory Operations — Appendix A

Memory read/write with page-level access control and fault detection.
References: `graypaper/text/pvm.tex`.
-/

namespace Jar.PVM

-- ============================================================================
-- Memory Access Results
-- ============================================================================

/-- Result of a memory access: success or fault. -/
inductive MemResult (α : Type) where
  | ok : α → MemResult α
  | panic : MemResult α         -- Address < 2^16: always inaccessible
  | fault : UInt64 → MemResult α  -- Page fault with page-aligned address

-- ============================================================================
-- Page Calculations — GP eq (4.17-4.19)
-- ============================================================================

/-- Page index for an address. -/
def pageOf (addr : UInt64) : Nat :=
  addr.toNat / Z_P

/-- Page-aligned address for fault reporting. -/
def pageAligned (addr : UInt64) : UInt64 :=
  UInt64.ofNat (pageOf addr * Z_P)

-- ============================================================================
-- Memory Read — GP Appendix A
-- ============================================================================

/-- Check read access for an address range [addr, addr+n). -/
def checkReadable (m : Memory) (addr : UInt64) (n : Nat) : MemResult Unit :=
  if addr.toNat < Z_Z then .panic
  else
    -- Check all pages touched by [addr, addr+n)
    let startPage := pageOf addr
    let endPage := pageOf (UInt64.ofNat (addr.toNat + n - 1))
    let rec go (p : Nat) (fuel : Nat) : MemResult Unit :=
      match fuel with
      | 0 => .ok ()
      | fuel' + 1 =>
        if p > endPage then .ok ()
        else if p < m.access.size then
          match m.access[p]! with
          | .inaccessible => .fault (UInt64.ofNat (p * Z_P))
          | _ => go (p + 1) fuel'
        else .fault (UInt64.ofNat (p * Z_P))
    go startPage (endPage - startPage + 1)

/-- Check write access for an address range [addr, addr+n). -/
def checkWritable (m : Memory) (addr : UInt64) (n : Nat) : MemResult Unit :=
  if addr.toNat < Z_Z then .panic
  else
    let startPage := pageOf addr
    let endPage := pageOf (UInt64.ofNat (addr.toNat + n - 1))
    let rec go (p : Nat) (fuel : Nat) : MemResult Unit :=
      match fuel with
      | 0 => .ok ()
      | fuel' + 1 =>
        if p > endPage then .ok ()
        else if p < m.access.size then
          match m.access[p]! with
          | .writable => go (p + 1) fuel'
          | _ => .fault (UInt64.ofNat (p * Z_P))
        else .fault (UInt64.ofNat (p * Z_P))
    go startPage (endPage - startPage + 1)

/-- Read n bytes from memory at address, returning LE-encoded UInt64. -/
def readMemBytes (m : Memory) (addr : UInt64) (n : Nat) : MemResult UInt64 :=
  match checkReadable m addr n with
  | .panic => .panic
  | .fault a => .fault a
  | .ok () =>
    let base := addr.toNat % (2^32)
    let val := Id.run do
      let mut acc : Nat := 0
      for i in [:n] do
        let idx := (base + i) % (2^32)
        let b := if idx < m.value.size then m.value.get! idx |>.toNat else 0
        acc := acc + b * 2 ^ (8 * i)
      return UInt64.ofNat acc
    .ok val

/-- Read 1 byte unsigned. -/
def readU8 (m : Memory) (addr : UInt64) : MemResult UInt64 :=
  readMemBytes m addr 1

/-- Read 1 byte sign-extended. -/
def readI8 (m : Memory) (addr : UInt64) : MemResult UInt64 :=
  match readMemBytes m addr 1 with
  | .ok v => .ok (sext 1 v)
  | .panic => .panic
  | .fault a => .fault a

/-- Read 2 bytes unsigned LE. -/
def readU16 (m : Memory) (addr : UInt64) : MemResult UInt64 :=
  readMemBytes m addr 2

/-- Read 2 bytes sign-extended LE. -/
def readI16 (m : Memory) (addr : UInt64) : MemResult UInt64 :=
  match readMemBytes m addr 2 with
  | .ok v => .ok (sext 2 v)
  | .panic => .panic
  | .fault a => .fault a

/-- Read 4 bytes unsigned LE. -/
def readU32 (m : Memory) (addr : UInt64) : MemResult UInt64 :=
  readMemBytes m addr 4

/-- Read 4 bytes sign-extended LE. -/
def readI32 (m : Memory) (addr : UInt64) : MemResult UInt64 :=
  match readMemBytes m addr 4 with
  | .ok v => .ok (sext 4 v)
  | .panic => .panic
  | .fault a => .fault a

/-- Read 8 bytes LE. -/
def readU64 (m : Memory) (addr : UInt64) : MemResult UInt64 :=
  readMemBytes m addr 8

-- ============================================================================
-- Memory Write — GP Appendix A
-- ============================================================================

/-- Write bytes to memory at address in LE order. Returns updated memory or fault. -/
def writeMemBytes (m : Memory) (addr : UInt64) (val : UInt64) (n : Nat)
    : MemResult Memory :=
  match checkWritable m addr n with
  | .panic => .panic
  | .fault a => .fault a
  | .ok () =>
    let base := addr.toNat % (2^32)
    let mem' := Id.run do
      let mut v := m.value
      for i in [:n] do
        let idx := (base + i) % (2^32)
        let b := UInt8.ofNat ((val.toNat / 2 ^ (8 * i)) % 256)
        if idx < v.size then
          v := v.set! idx b
      return v
    .ok { m with value := mem' }

/-- Write 1 byte. -/
def writeU8 (m : Memory) (addr : UInt64) (val : UInt64) : MemResult Memory :=
  writeMemBytes m addr val 1

/-- Write 2 bytes LE. -/
def writeU16 (m : Memory) (addr : UInt64) (val : UInt64) : MemResult Memory :=
  writeMemBytes m addr val 2

/-- Write 4 bytes LE. -/
def writeU32 (m : Memory) (addr : UInt64) (val : UInt64) : MemResult Memory :=
  writeMemBytes m addr val 4

/-- Write 8 bytes LE. -/
def writeU64 (m : Memory) (addr : UInt64) (val : UInt64) : MemResult Memory :=
  writeMemBytes m addr val 8

-- ============================================================================
-- Byte-Array Reads/Writes — for host-call data transfer
-- ============================================================================

/-- Read n raw bytes from memory starting at addr. Returns ByteArray or fault. -/
def readByteArray (m : Memory) (addr : UInt64) (n : Nat) : MemResult ByteArray :=
  if n == 0 then .ok ByteArray.empty
  else
    match checkReadable m addr n with
    | .panic => .panic
    | .fault a => .fault a
    | .ok () =>
      let base := addr.toNat % (2^32)
      let bytes := Id.run do
        let mut arr := ByteArray.mkEmpty n
        for i in [:n] do
          let idx := (base + i) % (2^32)
          let b := if idx < m.value.size then m.value.get! idx else 0
          arr := arr.push b
        return arr
      .ok bytes

/-- Write a ByteArray into memory starting at addr. Returns updated memory or fault. -/
def writeByteArray (m : Memory) (addr : UInt64) (data : ByteArray) : MemResult Memory :=
  if data.size == 0 then .ok m
  else
    match checkWritable m addr data.size with
    | .panic => .panic
    | .fault a => .fault a
    | .ok () =>
      let base := addr.toNat % (2^32)
      let mem' := Id.run do
        let mut v := m.value
        for i in [:data.size] do
          let idx := (base + i) % (2^32)
          if idx < v.size then
            v := v.set! idx (data.get! i)
        return v
      .ok { m with value := mem' }

-- ============================================================================
-- sbrk — GP Appendix A
-- ============================================================================

/-- sbrk(n): Grow the heap by n pages. Returns new heap base or 0 on failure.
    Finds the first inaccessible page after existing writable heap and
    marks n new pages as writable. -/
def sbrk (m : Memory) (nPages : UInt64) : Memory × UInt64 :=
  if nPages.toNat == 0 then (m, 0)
  else
    -- Find the end of current writable region (simplified: scan from start)
    let firstFree := Id.run do
      let mut p := Z_Z / Z_P  -- Start after reserved zone
      for _ in [:m.access.size] do
        if p < m.access.size then
          match m.access[p]! with
          | .writable => p := p + 1
          | .readable => p := p + 1
          | .inaccessible => return p
        else return p
      return p
    let n := nPages.toNat
    if firstFree + n > m.access.size then (m, 0)
    else
      let access' := Id.run do
        let mut acc := m.access
        for i in [:n] do
          acc := acc.set! (firstFree + i) .writable
        return acc
      ({ m with access := access' }, UInt64.ofNat (firstFree * Z_P))

end Jar.PVM
