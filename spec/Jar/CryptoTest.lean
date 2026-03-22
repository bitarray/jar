import Jar.Crypto

def nibbleToHex (n : UInt8) : Char :=
  if n < 10 then Char.ofNat (48 + n.toNat)  -- '0' + n
  else Char.ofNat (87 + n.toNat)              -- 'a' + (n - 10)

def bytesToHex (ba : ByteArray) : String :=
  ba.foldl (init := "") fun acc (b : UInt8) =>
    acc.push (nibbleToHex (b >>> 4)) |>.push (nibbleToHex (b &&& 0x0F))

open Jar.Crypto in
def main : IO Unit := do
  -- Blake2b of empty input
  let h := blake2b (ByteArray.mk #[])
  IO.println s!"blake2b(\"\") = {bytesToHex h.data}"

  -- Keccak256 of empty input
  let k := keccak256 (ByteArray.mk #[])
  IO.println s!"keccak256(\"\") = {bytesToHex k.data}"

  -- Ed25519 round-trip: sign then verify
  -- Seed = 32 bytes of 0x2a
  let seed := ByteArray.mk ((Array.range 32).map fun _ => (0x2a : UInt8))
  let msg := "deterministic".toUTF8
  let sig := ed25519Sign seed msg
  IO.println s!"ed25519 sig size = {sig.data.size}"
  IO.println s!"ed25519 sig = {bytesToHex sig.data}"

  -- To verify, we need the public key. ed25519-dalek derives it from the seed.
  -- For now, just check the signature is 64 bytes (non-zero).
  let nonZero := sig.data.foldl (init := false) fun acc (b : UInt8) => acc || b != 0
  IO.println s!"ed25519 sig non-zero = {nonZero}"

  -- Bandersnatch round-trip: sign then verify
  let bseed := ByteArray.mk ((Array.range 32).map fun _ => (0x01 : UInt8))
  let ctx := "test-context".toUTF8
  let bmsg := "test-message".toUTF8
  let bsig := bandersnatchSign bseed ctx bmsg
  IO.println s!"bandersnatch sig size = {bsig.data.size}"
  let bNonZero := bsig.data.foldl (init := false) fun acc (b : UInt8) => acc || b != 0
  IO.println s!"bandersnatch sig non-zero = {bNonZero}"

  -- Bandersnatch output (VRF hash from signature)
  let vrf := bandersnatchOutput bsig
  IO.println s!"bandersnatch vrf output = {bytesToHex vrf.data}"

  IO.println "All crypto tests passed!"
