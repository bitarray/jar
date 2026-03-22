import Jar.Commitment.Field
import Jar.Crypto

/-!
# Fiat-Shamir Transcript

SHA-256/Blake2b based Fiat-Shamir transcript for non-interactive proofs.
Absorbs protocol messages and squeezes deterministic challenges.

Ported from `commonware-commitment/src/transcript.rs`.
-/

namespace Jar.Commitment.Transcript

open Jar.Commitment.Field

/-- Transcript state: accumulated hash state + counter for squeezing. -/
structure FiatShamirTranscript where
  /-- Accumulated data to be hashed. -/
  buffer : ByteArray
  /-- Monotonic counter for domain separation during squeezes. -/
  counter : Nat
  deriving Inhabited

/-- Create a new transcript seeded with the given value. -/
def mkTranscript (seed : Int) : FiatShamirTranscript :=
  let seedBytes := ByteArray.mk #[
    (seed.toNat &&& 0xFF).toUInt8,
    ((seed.toNat >>> 8) &&& 0xFF).toUInt8,
    ((seed.toNat >>> 16) &&& 0xFF).toUInt8,
    ((seed.toNat >>> 24) &&& 0xFF).toUInt8
  ]
  { buffer := seedBytes, counter := 0 }

/-- Absorb a Merkle root into the transcript. -/
def absorbRoot (ts : FiatShamirTranscript) (root : ByteArray) : FiatShamirTranscript :=
  let label := "merkle_root".toUTF8
  let lenBytes := ByteArray.mk #[
    (root.size &&& 0xFF).toUInt8,
    ((root.size >>> 8) &&& 0xFF).toUInt8,
    ((root.size >>> 16) &&& 0xFF).toUInt8,
    ((root.size >>> 24) &&& 0xFF).toUInt8,
    0, 0, 0, 0
  ]
  { ts with buffer := ts.buffer ++ label ++ lenBytes ++ root }

/-- Absorb a GF(2^32) element. -/
def absorbGF32 (ts : FiatShamirTranscript) (elem : GF32) : FiatShamirTranscript :=
  let label := "field_element".toUTF8
  let lenBytes := ByteArray.mk #[4, 0, 0, 0, 0, 0, 0, 0]
  let elemBytes := ByteArray.mk #[
    (elem &&& 0xFF).toUInt8,
    ((elem >>> 8) &&& 0xFF).toUInt8,
    ((elem >>> 16) &&& 0xFF).toUInt8,
    ((elem >>> 24) &&& 0xFF).toUInt8
  ]
  { ts with buffer := ts.buffer ++ label ++ lenBytes ++ elemBytes }

/-- Absorb a GF(2^128) element. -/
def absorbGF128 (ts : FiatShamirTranscript) (elem : GF128) : FiatShamirTranscript :=
  let label := "field_element".toUTF8
  let lenBytes := ByteArray.mk #[16, 0, 0, 0, 0, 0, 0, 0]
  let loBytes := ByteArray.mk #[
    (elem.lo &&& 0xFF).toUInt8, ((elem.lo >>> 8) &&& 0xFF).toUInt8,
    ((elem.lo >>> 16) &&& 0xFF).toUInt8, ((elem.lo >>> 24) &&& 0xFF).toUInt8,
    ((elem.lo >>> 32) &&& 0xFF).toUInt8, ((elem.lo >>> 40) &&& 0xFF).toUInt8,
    ((elem.lo >>> 48) &&& 0xFF).toUInt8, ((elem.lo >>> 56) &&& 0xFF).toUInt8
  ]
  let hiBytes := ByteArray.mk #[
    (elem.hi &&& 0xFF).toUInt8, ((elem.hi >>> 8) &&& 0xFF).toUInt8,
    ((elem.hi >>> 16) &&& 0xFF).toUInt8, ((elem.hi >>> 24) &&& 0xFF).toUInt8,
    ((elem.hi >>> 32) &&& 0xFF).toUInt8, ((elem.hi >>> 40) &&& 0xFF).toUInt8,
    ((elem.hi >>> 48) &&& 0xFF).toUInt8, ((elem.hi >>> 56) &&& 0xFF).toUInt8
  ]
  { ts with buffer := ts.buffer ++ label ++ lenBytes ++ loBytes ++ hiBytes }

/-- Absorb multiple GF(2^128) elements. -/
def absorbGF128s (ts : FiatShamirTranscript) (elems : Array GF128) : FiatShamirTranscript :=
  elems.foldl absorbGF128 ts

/-- Squeeze bytes from the transcript using hash-based expansion. -/
def squeezeBytes (ts : FiatShamirTranscript) (count : Nat)
    : ByteArray × FiatShamirTranscript := Id.run do
  let counterBytes := ByteArray.mk #[
    (ts.counter &&& 0xFF).toUInt8,
    ((ts.counter >>> 8) &&& 0xFF).toUInt8,
    ((ts.counter >>> 16) &&& 0xFF).toUInt8,
    ((ts.counter >>> 24) &&& 0xFF).toUInt8
  ]
  let digest := Jar.Crypto.blake2b (ts.buffer ++ counterBytes)
  let ts' := { ts with counter := ts.counter + 1 }

  if count ≤ 32 then
    (ByteArray.mk (digest.data.data.extract 0 count), ts')
  else
    let mut result := digest.data
    let mut tsAcc := ts'
    while result.size < count do
      let cBytes := ByteArray.mk #[
        (tsAcc.counter &&& 0xFF).toUInt8,
        ((tsAcc.counter >>> 8) &&& 0xFF).toUInt8,
        ((tsAcc.counter >>> 16) &&& 0xFF).toUInt8,
        ((tsAcc.counter >>> 24) &&& 0xFF).toUInt8
      ]
      let d := Jar.Crypto.blake2b (tsAcc.buffer ++ cBytes)
      tsAcc := { tsAcc with counter := tsAcc.counter + 1 }
      let needed := count - result.size
      let take := needed.min 32
      result := result ++ ByteArray.mk (d.data.data.extract 0 take)
    (ByteArray.mk (result.data.extract 0 count), tsAcc)

/-- Squeeze a GF(2^32) challenge from the transcript. -/
def challengeGF32 (ts : FiatShamirTranscript) : GF32 × FiatShamirTranscript :=
  let (bytes, ts') := squeezeBytes ts 4
  let value := (bytes[0]!.toUInt32)
    ||| (bytes[1]!.toUInt32 <<< 8)
    ||| (bytes[2]!.toUInt32 <<< 16)
    ||| (bytes[3]!.toUInt32 <<< 24)
  (value, ts')

/-- Squeeze a GF(2^128) challenge from the transcript. -/
def challengeGF128 (ts : FiatShamirTranscript) : GF128 × FiatShamirTranscript :=
  let (bytes, ts') := squeezeBytes ts 16
  let lo := (bytes[0]!.toUInt64)
    ||| (bytes[1]!.toUInt64 <<< 8)
    ||| (bytes[2]!.toUInt64 <<< 16)
    ||| (bytes[3]!.toUInt64 <<< 24)
    ||| (bytes[4]!.toUInt64 <<< 32)
    ||| (bytes[5]!.toUInt64 <<< 40)
    ||| (bytes[6]!.toUInt64 <<< 48)
    ||| (bytes[7]!.toUInt64 <<< 56)
  let hi := (bytes[8]!.toUInt64)
    ||| (bytes[9]!.toUInt64 <<< 8)
    ||| (bytes[10]!.toUInt64 <<< 16)
    ||| (bytes[11]!.toUInt64 <<< 24)
    ||| (bytes[12]!.toUInt64 <<< 32)
    ||| (bytes[13]!.toUInt64 <<< 40)
    ||| (bytes[14]!.toUInt64 <<< 48)
    ||| (bytes[15]!.toUInt64 <<< 56)
  (GF128.mk lo hi, ts')

/-- Squeeze a query index in [0, max). -/
def queryIndex (ts : FiatShamirTranscript) (max : Nat)
    : Nat × FiatShamirTranscript :=
  let (bytes, ts') := squeezeBytes ts 8
  let value := (bytes[0]!.toNat)
    + bytes[1]!.toNat * 256
    + bytes[2]!.toNat * 65536
    + bytes[3]!.toNat * 16777216
    + bytes[4]!.toNat * (2^32)
    + bytes[5]!.toNat * (2^40)
    + bytes[6]!.toNat * (2^48)
    + bytes[7]!.toNat * (2^56)
  (value % max, ts')

/-- Squeeze `count` distinct query indices in [0, max), sorted. -/
def distinctQueries (ts : FiatShamirTranscript) (max count : Nat)
    : Array Nat × FiatShamirTranscript := Id.run do
  let actualCount := count.min max
  let mut queries : Array Nat := #[]
  let mut tsAcc := ts
  while queries.size < actualCount do
    let (q, ts') := queryIndex tsAcc max
    tsAcc := ts'
    if !queries.contains q then
      queries := queries.push q
  let sorted := queries.qsort (· < ·)
  (sorted, tsAcc)

end Jar.Commitment.Transcript
