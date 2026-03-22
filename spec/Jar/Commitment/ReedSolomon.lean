import Jar.Commitment.Field

/-!
# Reed-Solomon Encoding over Binary Extension Fields

Binary field FFT and Reed-Solomon encoding for GF(2^32), based on
recursive subspace polynomial evaluation. This is the encoding used
by the Ligerito commitment scheme.

Ported from `commonware-commitment/src/reed_solomon/`.

## Algorithm

Uses the additive FFT over binary fields:
1. Compute twiddle factors from subspace polynomial evaluations
2. FFT butterfly: u' = u + λ·w; w' = w + u' (characteristic 2)
3. Systematic encoding: IFFT on message, then FFT on full block
-/

namespace Jar.Commitment.ReedSolomon

open Jar.Commitment.Field

-- ============================================================================
-- Twiddle Factor Computation
-- ============================================================================

/-- Initialize layer 0 of twiddle computation.
    Fills with beta + from_bits(i << 1) for i = 0..2^(k-1)-1. -/
def initLayer0 (beta : GF32) (k : Nat) : Array GF32 := Id.run do
  let len := 1 <<< (k - 1)
  let mut layer := Array.replicate len (0 : GF32)
  for i in [:len] do
    layer := layer.set! i (gf32Add beta (gf32FromBits (i * 2)))
  layer

/-- Update twiddle layer: compute next subspace polynomial values.
    Returns (updated_layer, s_at_root). -/
def updateLayer (layer : Array GF32) (layerLen : Nat) (sPrevAtRoot : GF32)
    : Array GF32 × GF32 := Id.run do
  let prevLen := 2 * layerLen
  let sAtRoot := nextSubspacePoly
    (gf32Add layer[1]! layer[0]!)
    sPrevAtRoot
  let mut l := layer
  for idx in List.range prevLen |>.filter (· % 2 == 0) do
    let sPrev := l[idx]!
    l := l.set! (idx / 2) (nextSubspacePoly sPrev sPrevAtRoot)
  (l, sAtRoot)

/-- Compute twiddle factors for binary FFT.
    Returns array of n-1 twiddle factors. -/
def computeTwiddles (logN : Nat) (beta : GF32) : Array GF32 := Id.run do
  if logN == 0 then return #[]
  let n := 1 <<< logN
  let mut twiddles := Array.replicate n (0 : GF32)

  let layer := initLayer0 beta logN
  let mut curLayer := layer
  let mut writeAt := 1 <<< (logN - 1)
  let mut sPrevAtRoot : GF32 := 1  -- layer_0 returns one()

  for i in [:curLayer.size.min writeAt] do
    twiddles := twiddles.set! (writeAt + i) curLayer[i]!

  for _ in [1:logN] do
    writeAt := writeAt >>> 1
    let (newLayer, newSAtRoot) := updateLayer curLayer writeAt sPrevAtRoot
    curLayer := newLayer
    sPrevAtRoot := newSAtRoot

    let sInv := gf32Inv sPrevAtRoot
    for i in [:writeAt] do
      twiddles := twiddles.set! (writeAt + i) (gf32Mul sInv curLayer[i]!)

  -- Remove dummy element 0, return elements 1..n
  twiddles.extract 1 n

-- ============================================================================
-- FFT and IFFT
-- ============================================================================

/-- FFT butterfly in-place: u' = u + λ·w; w' = w + u' (char 2). -/
def fftButterfly (data : Array GF32) (start half : Nat) (lambda : GF32)
    : Array GF32 := Id.run do
  let mut d := data
  for i in [:half] do
    let u := d[start + i]!
    let w := d[start + half + i]!
    let lambdaW := gf32Mul lambda w
    let newU := gf32Add u lambdaW
    d := d.set! (start + i) newU
    d := d.set! (start + half + i) (gf32Add w newU)
  d

/-- Recursive in-place FFT with twiddles. idx is 1-based. -/
partial def fftTwiddles (data : Array GF32) (start len : Nat) (twiddles : Array GF32)
    (idx : Nat) : Array GF32 :=
  if len ≤ 1 then data
  else
    let half := len / 2
    let lambda := twiddles[idx - 1]!
    let d := fftButterfly data start half lambda
    let d := fftTwiddles d start half twiddles (2 * idx)
    fftTwiddles d (start + half) half twiddles (2 * idx + 1)

/-- In-place FFT over GF(2^32). -/
def fft (data : Array GF32) (twiddles : Array GF32) : Array GF32 :=
  if data.size ≤ 1 then data
  else fftTwiddles data 0 data.size twiddles 1

/-- IFFT butterfly in-place: hi += lo; lo += λ·hi (char 2). -/
def ifftButterfly (data : Array GF32) (start half : Nat) (lambda : GF32)
    : Array GF32 := Id.run do
  let mut d := data
  for i in [:half] do
    let lo := d[start + i]!
    let hi := d[start + half + i]!
    let newHi := gf32Add hi lo
    let lambdaHi := gf32Mul lambda newHi
    d := d.set! (start + i) (gf32Add lo lambdaHi)
    d := d.set! (start + half + i) newHi
  d

/-- Recursive in-place IFFT with twiddles. -/
partial def ifftTwiddles (data : Array GF32) (start len : Nat) (twiddles : Array GF32)
    (idx : Nat) : Array GF32 :=
  if len ≤ 1 then data
  else
    let half := len / 2
    let d := ifftTwiddles data start half twiddles (2 * idx)
    let d := ifftTwiddles d (start + half) half twiddles (2 * idx + 1)
    let lambda := twiddles[idx - 1]!
    ifftButterfly d start half lambda

/-- In-place IFFT over GF(2^32). -/
def ifft (data : Array GF32) (twiddles : Array GF32) : Array GF32 :=
  if data.size ≤ 1 then data
  else ifftTwiddles data 0 data.size twiddles 1

-- ============================================================================
-- Reed-Solomon Encoding
-- ============================================================================

/-- Extract short twiddles from long twiddles for systematic encoding. -/
def shortFromLongTwiddles (longTwiddles : Array GF32) (logN logK : Nat)
    : Array GF32 := Id.run do
  let k := 1 <<< logK
  let mut short := Array.replicate (k - 1) (0 : GF32)

  let mut jump := 1 <<< (logN - logK)
  if jump > 0 && jump ≤ longTwiddles.size then
    short := short.set! 0 longTwiddles[jump - 1]!

  let mut idx := 1
  for i in [1:logK] do
    jump := jump * 2
    let take := 1 <<< i
    for j in [:take] do
      if jump - 1 + j < longTwiddles.size && idx + j < short.size then
        short := short.set! (idx + j) longTwiddles[jump - 1 + j]!
    idx := idx + take

  short

/-- Reed-Solomon encoder configuration. -/
structure RSConfig where
  logMessageLength : Nat
  logBlockLength : Nat
  twiddles : Array GF32

/-- Create an RS encoder for given message and block lengths (must be powers of 2). -/
def mkRSConfig (messageLength blockLength : Nat) : RSConfig :=
  let logMsg := messageLength.log2
  let logBlk := blockLength.log2
  let twiddles := computeTwiddles logBlk 0
  { logMessageLength := logMsg
    logBlockLength := logBlk
    twiddles := twiddles }

/-- Systematic RS encoding: message → codeword of blockLength elements.
    First messageLength elements of codeword are the original message
    (after IFFT/FFT cycle). -/
def encode (rs : RSConfig) (message : Array GF32) : Array GF32 := Id.run do
  let blockLen := 1 <<< rs.logBlockLength
  let msgLen := 1 <<< rs.logMessageLength
  let mut data := Array.replicate blockLen (0 : GF32)
  for i in [:message.size.min msgLen] do
    data := data.set! i message[i]!

  let shortTwiddles := shortFromLongTwiddles rs.twiddles rs.logBlockLength rs.logMessageLength

  -- IFFT on message portion
  let msgPart := (data.extract 0 msgLen)
  let ifftResult := ifft msgPart shortTwiddles
  for i in [:msgLen] do
    data := data.set! i ifftResult[i]!

  -- FFT on full block
  fft data rs.twiddles

end Jar.Commitment.ReedSolomon
