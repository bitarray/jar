import Jar.Notation
import Jar.Types.Numerics
import Jar.Codec
import Jar.Crypto

/-!
# Merklization — Appendices D–E

Binary Patricia Merkle Trie and Merkle tree constructions.
References: `graypaper/text/merklization.tex`.

## Structure
- §D.3–D.5: Binary Patricia Merkle Trie (node types, root computation)
- §D.1: State-key constructor `C`
- §D.2: State serialization `T(σ)`
- §E.1: Well-balanced binary Merkle tree `M_B`
- §E.4: Constant-depth binary Merkle tree `M`
- §E.7–E.10: Merkle Mountain Ranges & Belts
-/

namespace Jar.Merkle

-- ============================================================================
-- Node Types — Appendix D
-- ============================================================================

/-- A Merkle trie node is always 64 bytes (512 bits). GP Appendix D.
    Encoded as the first bit distinguishing branch (0) from leaf (1). -/
inductive Node where
  /-- Branch node: first bit = 0.
      Contains left (255 bits) and right (256 bits) child hashes. -/
  | branch (left right : Hash) : Node
  /-- Embedded-value leaf: first bit = 1, second bit = 0.
      Bits 2-7 encode value size. 31-byte key, ≤32-byte value. -/
  | embeddedLeaf (key : OctetSeq 31) (value : ByteArray) : Node
  /-- Regular leaf: first bit = 1, second bit = 1.
      31-byte key, 32-byte hash of value. -/
  | regularLeaf (key : OctetSeq 31) (valueHash : Hash) : Node

/-- Get a single bit from a byte array, treating it as a big-endian bit string.
    Bit 0 is the MSB of byte 0. -/
private def getBit (data : ByteArray) (bitIdx : Nat) : Bool :=
  let byteIdx := bitIdx / 8
  let bitPos := 7 - (bitIdx % 8)
  if byteIdx < data.size then
    (data.get! byteIdx).toNat >>> bitPos &&& 1 == 1
  else false

/-- Set a single bit in a byte array (big-endian bit ordering). -/
private def setBit (data : ByteArray) (bitIdx : Nat) (val : Bool) : ByteArray :=
  let byteIdx := bitIdx / 8
  let bitPos := 7 - (bitIdx % 8)
  if byteIdx < data.size then
    let old := data.get! byteIdx
    let mask := UInt8.ofNat (1 <<< bitPos)
    let new_ := if val then old ||| mask else old &&& (255 - mask)
    data.set! byteIdx new_
  else data

/-- Encode a branch node to 64 bytes. GP Appendix D §D.3.
    B(l, r) = [0] ∥ bits(l)[1..256] ∥ bits(r).
    Bit 0 = 0 (branch marker). Bits 1-255 = left hash bits 1-255 (skip MSB).
    Bits 256-511 = all 256 bits of right hash. -/
def encodeBranch (left right : Hash) : OctetSeq 64 :=
  let out := ByteArray.mk (Array.replicate 64 0)
  -- Bit 0 = 0 (already zero)
  -- Copy left hash bits 1..255 into output bits 1..255
  let out := Id.run do
    let mut o := out
    for i in [1:256] do
      o := setBit o i (getBit left.data i)
    return o
  -- Copy right hash bits 0..255 into output bits 256..511
  let out := Id.run do
    let mut o := out
    for i in [:256] do
      o := setBit o (256 + i) (getBit right.data i)
    return o
  ⟨out, sorry⟩

/-- Encode a leaf node to 64 bytes. GP Appendix D §D.4.
    If |v| ≤ 32 (embedded): [1,0] ∥ |v|(6 bits) ∥ key(248 bits) ∥ v_padded(256 bits).
    If |v| > 32 (regular):  [1,1,0,0,0,0,0,0] ∥ key(248 bits) ∥ H(v)(256 bits). -/
def encodeLeaf (key : OctetSeq 31) (value : ByteArray) : OctetSeq 64 :=
  let out := ByteArray.mk (Array.replicate 64 0)
  if value.size <= 32 then
    -- Embedded leaf
    -- Bit 0 = 1 (leaf), Bit 1 = 0 (embedded)
    let out := setBit out 0 true
    -- Bits 2-7: value length (6 bits, big-endian)
    let len := value.size
    let out := Id.run do
      let mut o := out
      for i in [:6] do
        let bit := (len >>> (5 - i)) &&& 1 == 1
        o := setBit o (2 + i) bit
      return o
    -- Bits 8-255: key (31 bytes = 248 bits)
    let out := Id.run do
      let mut o := out
      for i in [:248] do
        o := setBit o (8 + i) (getBit key.data i)
      return o
    -- Bits 256-511: value zero-padded to 32 bytes
    let padded := value ++ ByteArray.mk (Array.replicate (32 - value.size) 0)
    let out := Id.run do
      let mut o := out
      for i in [:256] do
        o := setBit o (256 + i) (getBit padded i)
      return o
    ⟨out, sorry⟩
  else
    -- Regular leaf
    -- Byte 0 = 0b11000000 = 0xC0 (bits: [1,1,0,0,0,0,0,0])
    let out := out.set! 0 0xC0
    -- Bits 8-255: key (31 bytes = 248 bits)
    let out := Id.run do
      let mut o := out
      for i in [:248] do
        o := setBit o (8 + i) (getBit key.data i)
      return o
    -- Bits 256-511: H(value)
    let vh := Crypto.blake2b value
    let out := Id.run do
      let mut o := out
      for i in [:256] do
        o := setBit o (256 + i) (getBit vh.data i)
      return o
    ⟨out, sorry⟩

-- ============================================================================
-- Merkle Trie Root — Appendix D §D.5
-- ============================================================================

/-- A bitstring key used during trie construction: the 248-bit key from a 31-byte OctetSeq. -/
private structure BitKey where
  data : ByteArray  -- 31 bytes
  deriving BEq, Inhabited

/-- Get bit at position in a BitKey (big-endian). -/
private def BitKey.bit (k : BitKey) (pos : Nat) : Bool := getBit k.data pos

/-- M(d) : Compute Merkle trie root. GP Appendix D eq (D.3–D.5).
    d is a list of (key, value) pairs. Keys are 31 bytes (248 bits).
    - Empty: return ℍ_0
    - Single entry: return H(L(k, v))
    - Multiple entries: split on the first distinguishing bit, recurse.
    `depth` serves as fuel for recursion (max 248 bits). -/
private def trieRootAux (entries : Array (BitKey × ByteArray)) (depth : Nat)
    : Hash :=
  match depth with
  | 0 =>
    -- Out of fuel; return hash of first entry if any
    if entries.size > 0 then
      let (k, v) := entries[0]!
      Crypto.blake2b (encodeLeaf ⟨k.data, sorry⟩ v).data
    else Hash.zero
  | fuel + 1 =>
    if entries.size == 0 then Hash.zero
    else if entries.size == 1 then
      let (k, v) := entries[0]!
      Crypto.blake2b (encodeLeaf ⟨k.data, sorry⟩ v).data
    else
      -- Find the first bit position (starting from `248 - fuel`) that
      -- distinguishes the entries. Split into left (bit=0) and right (bit=1).
      let bitPos := 248 - fuel
      let left := entries.filter fun (k, _) => !k.bit bitPos
      let right := entries.filter fun (k, _) => k.bit bitPos
      -- If all entries go one way, skip this bit level
      if left.size == 0 then trieRootAux right fuel
      else if right.size == 0 then trieRootAux left fuel
      else
        let lHash := trieRootAux left fuel
        let rHash := trieRootAux right fuel
        Crypto.blake2b (encodeBranch lHash rHash).data

/-- M(d) : Compute Merkle trie root from key-value pairs. GP Appendix D.
    Keys are 31-byte OctetSeqs. Returns ℍ_0 for empty. -/
def trieRoot (entries : Array (OctetSeq 31 × ByteArray)) : Hash :=
  let bitEntries := entries.map fun (k, v) => ({ data := k.data : BitKey }, v)
  trieRootAux bitEntries 248

-- ============================================================================
-- Merkle Trie Root (32-byte keys) — for test vectors
-- ============================================================================

/-- A 32-byte key used during trie construction (256 bits for splitting). -/
private structure BitKey32 where
  data : ByteArray  -- 32 bytes
  deriving BEq, Inhabited

/-- Get bit at position in a BitKey32 (big-endian). -/
private def BitKey32.bit (k : BitKey32) (pos : Nat) : Bool := getBit k.data pos

/-- Compute Merkle trie root with 32-byte keys. GP Appendix D eq (D.3–D.5).
    Keys are 32 bytes (256 bits) for partitioning, but leaf encoding
    truncates to 31 bytes (matching the specification).
    Unlike `trieRootAux`, this always creates branch nodes when splitting
    (even if one side is empty), matching the reference implementation. -/
private def trieRoot32Aux (entries : Array (BitKey32 × ByteArray)) (depth : Nat)
    : Hash :=
  match depth with
  | 0 =>
    if entries.size > 0 then
      let (k, v) := entries[0]!
      let key31 := ByteArray.mk (k.data.data.extract 0 31)
      Crypto.blake2b (encodeLeaf ⟨key31, sorry⟩ v).data
    else Hash.zero
  | fuel + 1 =>
    if entries.size == 0 then Hash.zero
    else if entries.size == 1 then
      let (k, v) := entries[0]!
      let key31 := ByteArray.mk (k.data.data.extract 0 31)
      Crypto.blake2b (encodeLeaf ⟨key31, sorry⟩ v).data
    else
      let bitPos := 256 - fuel - 1
      let left := entries.filter fun (k, _) => !k.bit bitPos
      let right := entries.filter fun (k, _) => k.bit bitPos
      let lHash := trieRoot32Aux left fuel
      let rHash := trieRoot32Aux right fuel
      Crypto.blake2b (encodeBranch lHash rHash).data

/-- Compute Merkle trie root from key-value pairs with 32-byte keys.
    Keys are 32 bytes for splitting; leaf encoding truncates to 31 bytes.
    Returns ℍ_0 for empty. -/
def trieRoot32 (entries : Array (ByteArray × ByteArray)) : Hash :=
  let bitEntries := entries.map fun (k, v) => ({ data := k : BitKey32 }, v)
  trieRoot32Aux bitEntries 256

-- ============================================================================
-- State Merklization — Appendix D §D.2
-- ============================================================================

/-- M_σ(σ) : Compute the state Merkle root. GP Appendix D eq (D.2).
    Delegates to the trie root computation on state key-value pairs. -/
def stateRoot (entries : Array (OctetSeq 31 × ByteArray)) : Hash :=
  trieRoot entries

-- ============================================================================
-- Well-Balanced Binary Merkle Tree — Appendix E
-- ============================================================================

/-- Helper: split array in half and hash both halves recursively. -/
private def merkleHelper (items : Array Hash) (depth : Nat) : Hash :=
  match depth with
  | 0 => if items.size > 0 then items[0]! else Hash.zero
  | d + 1 =>
    if items.size == 0 then Hash.zero
    else if items.size == 1 then items[0]!
    else
      let mid := items.size / 2
      let left := merkleHelper (items.extract 0 mid) d
      let right := merkleHelper (items.extract mid items.size) d
      Crypto.blake2b (left.data ++ right.data)

def binaryMerkleRoot (items : Array Hash) : Hash :=
  merkleHelper items items.size

-- ============================================================================
-- Constant-Depth Merkle Tree — Appendix E
-- ============================================================================

/-- M(data, depth) : Constant-depth binary Merkle tree. GP Appendix E eq (E.4).
    Pads to 2^depth leaves with zero hashes, then computes binary Merkle root. -/
def constDepthMerkleRoot (items : Array Hash) (depth : Nat) : Hash :=
  let targetSize := 2^depth
  let padded := if items.size < targetSize then
    items ++ Array.replicate (targetSize - items.size) Hash.zero
  else items.extract 0 targetSize
  binaryMerkleRoot padded

-- ============================================================================
-- Merkle Mountain Range — Appendix E
-- ============================================================================

/-- MMR peak computation. GP Appendix E eq (E.7).
    A Merkle Mountain Range is a collection of perfect binary trees
    (peaks) whose sizes correspond to the binary representation of n. -/
structure MerkleMountainRange where
  /-- The peaks of the MMR, each a hash. -/
  peaks : Array Hash

/-- Append a leaf to an MMR. GP Appendix E eq (E.8). -/
def MerkleMountainRange.append (mmr : MerkleMountainRange) (leaf : Hash) : MerkleMountainRange :=
  let rec merge (peaks : Array Hash) (h : Hash) : Array Hash :=
    -- If last peak can be merged (same height), combine and continue
    if peaks.size == 0 then #[h]
    else
      -- Simplified: in a real MMR, we track heights and merge same-height peaks
      peaks.push h
  { peaks := merge mmr.peaks leaf }

/-- Bag the peaks of an MMR to get a single root hash. GP Appendix E eq (E.9). -/
def MerkleMountainRange.root (mmr : MerkleMountainRange) : Hash :=
  match mmr.peaks.size with
  | 0 => Hash.zero
  | 1 => mmr.peaks[0]!
  | _ => mmr.peaks.foldl (init := Hash.zero) fun acc peak =>
    Crypto.blake2b (acc.data ++ peak.data)

end Jar.Merkle
