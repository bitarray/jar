import Jar.Commitment.Field
import Jar.Commitment.ReedSolomon
import Jar.Commitment.Merkle
import Jar.Commitment.Proof

/-!
# Encoding Pipeline

Polynomial to column-major matrix, RS-encode in-place, hash rows
into a Merkle tree. This is the Ligero commitment step.

Ported from `commonware-commitment/src/encode.rs`.

## Memory layout

The matrix is stored column-major in a flat buffer for cache-friendly
RS encoding. Column j occupies `data[j * rows .. (j+1) * rows]`.
-/

namespace Jar.Commitment.Encode

open Jar.Commitment.Field
open Jar.Commitment.ReedSolomon
open Jar.Commitment.CMerkle
open Jar.Commitment.Proof

/-- Witness: prover-side matrix representation with Merkle commitment.
    Column-major layout. -/
structure Witness where
  /-- Column-major flat buffer. -/
  data : Array GF32
  /-- Number of rows (= m * invRate). -/
  rows : Nat
  /-- Number of columns. -/
  cols : Nat
  /-- Merkle tree over hashed rows. -/
  tree : CompleteMerkleTree

/-- Gather row i from column-major layout into a contiguous array. -/
def gatherRow (w : Witness) (i : Nat) : Array GF32 := Id.run do
  let mut row := Array.replicate w.cols (0 : GF32)
  for j in [:w.cols] do
    let idx := j * w.rows + i
    if idx < w.data.size then
      row := row.set! j (w.data[idx]!)
  row

/-- Hash row i from column-major layout. -/
def hashRowColmajor (data : Array GF32) (rows cols i : Nat) : CHash := Id.run do
  let mut rowBuf := Array.replicate cols (0 : UInt32)
  for j in [:cols] do
    let idx := j * rows + i
    if idx < data.size then
      rowBuf := rowBuf.set! j (data[idx]!)
  hashRow rowBuf

/-- Build and encode: arrange polynomial as column-major matrix,
    RS-encode each column in-place. Returns (data, rows, cols). -/
def buildAndEncode (poly : Array GF32) (m n invRate : Nat) (rs : RSConfig)
    : Array GF32 × Nat × Nat := Id.run do
  let mTarget := m * invRate
  let mut data := Array.replicate (mTarget * n) (0 : GF32)

  -- Fill column-major: poly[j*m + i] → data[j*mTarget + i]
  for j in [:n] do
    let colStart := j * mTarget
    for i in [:m] do
      let polyIdx := j * m + i
      if polyIdx < poly.size then
        data := data.set! (colStart + i) (poly[polyIdx]!)

  -- RS-encode each column (contiguous slice)
  for j in [:n] do
    let start := j * mTarget
    let col := data.extract start (start + mTarget)
    let encoded := encode rs col
    for i in [:mTarget] do
      if i < encoded.size then
        data := data.set! (start + i) (encoded[i]!)

  (data, mTarget, n)

/-- Commit to a polynomial: encode as column-major matrix, hash rows,
    build Merkle tree. Returns Witness. -/
def ligeroCommit (poly : Array GF32) (m n : Nat) (rs : RSConfig) : Witness := Id.run do
  let (data, rows, cols) := buildAndEncode poly m n 4 rs

  -- Hash rows (strided gather from column-major layout)
  let mut hashedRows : Array CHash := #[]
  for i in [:rows] do
    hashedRows := hashedRows.push (hashRowColmajor data rows cols i)

  let tree := buildTreeFromHashes hashedRows

  { data, rows, cols, tree }

/-- Extract commitment from a witness. -/
def commitmentFromWitness (w : Witness) : Proof.Commitment :=
  { root := w.tree.getRoot }

end Jar.Commitment.Encode
