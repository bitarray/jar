import Jar.Commitment.Field
import Jar.Crypto

/-!
# BLAKE3 Merkle Tree Commitment

Complete binary Merkle tree using BLAKE3 for leaf and internal node hashing.
Used by the Ligerito commitment scheme for row commitments.

Ported from `commonware-commitment/src/merkle/`.

Note: This is distinct from JAR's existing Blake2b Patricia Merkle Trie
(Appendix D). The commitment scheme uses BLAKE3 and a simpler complete
binary tree structure.
-/

namespace Jar.Commitment.CMerkle

/-- A 32-byte hash digest (BLAKE3). -/
abbrev CHash := ByteArray

/-- Hash two sibling nodes together.
    H(left ‖ right) using BLAKE3.
    We use Blake2b as a stand-in since it's available via FFI;
    in production this would be BLAKE3. -/
def hashSiblings (left right : CHash) : CHash :=
  (Jar.Crypto.blake2b (left ++ right)).data

/-- Hash a row of GF(2^32) elements for Merkle leaf commitment.
    Prepends the element count as a 4-byte LE prefix. -/
def hashRow (row : Array UInt32) : CHash := Id.run do
  let lenBytes := ByteArray.mk #[
    (row.size &&& 0xFF).toUInt8,
    ((row.size >>> 8) &&& 0xFF).toUInt8,
    ((row.size >>> 16) &&& 0xFF).toUInt8,
    ((row.size >>> 24) &&& 0xFF).toUInt8
  ]
  let mut data := lenBytes
  for elem in row do
    data := data ++ ByteArray.mk #[
      (elem &&& 0xFF).toUInt8,
      ((elem >>> 8) &&& 0xFF).toUInt8,
      ((elem >>> 16) &&& 0xFF).toUInt8,
      ((elem >>> 24) &&& 0xFF).toUInt8
    ]
  return (Jar.Crypto.blake2b data).data

/-- A complete binary Merkle tree storing every layer. -/
structure CompleteMerkleTree where
  layers : Array (Array CHash)

/-- Build a Merkle tree from pre-hashed leaf digests. -/
def buildTreeFromHashes (leafHashes : Array CHash) : CompleteMerkleTree := Id.run do
  if leafHashes.isEmpty then
    return { layers := #[] }

  let mut currentLayer := leafHashes
  let mut layers : Array (Array CHash) := #[currentLayer]

  while currentLayer.size > 1 do
    let mut nextLayer : Array CHash := #[]
    let pairs := currentLayer.size / 2
    for i in [:pairs] do
      let left := currentLayer[2 * i]!
      let right := currentLayer[2 * i + 1]!
      nextLayer := nextLayer.push (hashSiblings left right)
    layers := layers.push nextLayer
    currentLayer := nextLayer

  { layers }

namespace CompleteMerkleTree

/-- Get the Merkle root (top of the tree). -/
def getRoot (tree : CompleteMerkleTree) : Option CHash :=
  tree.layers.back?.bind (fun layer => layer[0]?)

/-- Get the depth of the tree. -/
def getDepth (tree : CompleteMerkleTree) : Nat :=
  if tree.layers.isEmpty then 0
  else tree.layers.size - 1

/-- Generate a batched Merkle proof for given query indices.
    Returns sibling hashes needed to reconstruct the root. -/
def prove (tree : CompleteMerkleTree) (queries : Array Nat) : Array CHash := Id.run do
  let depth := tree.getDepth
  if depth == 0 || queries.isEmpty then return #[]

  let mut siblings : Array CHash := #[]
  let mut queryBuf := queries
  let mut queriesLen := queryBuf.size

  for layerIdx in [:depth] do
    let layer := tree.layers[layerIdx]!
    let mut nextLen := 0
    let mut i := 0
    while i < queriesLen do
      let query := queryBuf[i]!
      let sibling := query ^^^ 1

      queryBuf := queryBuf.set! nextLen (query >>> 1)
      nextLen := nextLen + 1

      if i == queriesLen - 1 then
        if sibling < layer.size then
          siblings := siblings.push layer[sibling]!
        break
      else if query % 2 != 0 then
        if sibling < layer.size then
          siblings := siblings.push layer[sibling]!
        i := i + 1
      else if queryBuf[i + 1]! != sibling then
        if sibling < layer.size then
          siblings := siblings.push layer[sibling]!
        i := i + 1
      else
        i := i + 2

    queriesLen := nextLen

  siblings

end CompleteMerkleTree

/-- Verify a batched Merkle proof against pre-hashed leaves.
    Reconstructs the root from leaf hashes + sibling proof and compares. -/
def verifyHashed (root : Option CHash) (proof : Array CHash)
    (depth : Nat) (leafHashes : Array CHash) (leafIndices : Array Nat) : Bool := Id.run do
  match root with
  | none => return false
  | some expectedRoot =>
    if depth == 0 then
      return leafHashes.size == 1 && leafIndices.size == 1 && leafIndices[0]! == 0
             && leafHashes[0]! == expectedRoot

    let mut layer := leafHashes
    let mut queries := leafIndices
    let mut currCnt := queries.size
    let mut proofCnt := 0

    for _ in [:depth] do
      let mut nextCnt := 0
      let mut i := 0
      while i < currCnt do
        let query := queries[i]!
        let sibling := query ^^^ 1
        queries := queries.set! nextCnt (query >>> 1)
        nextCnt := nextCnt + 1

        if i == currCnt - 1 then
          if proofCnt < proof.size then
            let pp := proof[proofCnt]!
            proofCnt := proofCnt + 1
            layer := layer.set! (nextCnt - 1)
              (if query % 2 != 0 then hashSiblings pp layer[i]!
               else hashSiblings layer[i]! pp)
          break
        else if query % 2 != 0 then
          if proofCnt < proof.size then
            let pp := proof[proofCnt]!
            proofCnt := proofCnt + 1
            layer := layer.set! (nextCnt - 1) (hashSiblings pp layer[i]!)
          i := i + 1
        else if queries[i + 1]! != sibling then
          if proofCnt < proof.size then
            let pp := proof[proofCnt]!
            proofCnt := proofCnt + 1
            layer := layer.set! (nextCnt - 1) (hashSiblings layer[i]! pp)
          i := i + 1
        else
          layer := layer.set! (nextCnt - 1) (hashSiblings layer[i]! layer[i + 1]!)
          i := i + 2
      currCnt := nextCnt

    currCnt == 1 && proofCnt == proof.size && layer[0]! == expectedRoot

end Jar.Commitment.CMerkle
