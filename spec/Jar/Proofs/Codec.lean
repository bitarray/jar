import Jar.Codec

/-!
# Codec Proofs — encodeFixedNat size invariant

Foundation lemma: `encodeFixedNat l x` always produces exactly `l` bytes.
Used by QuotaEcon/BalanceEcon serialization size proofs.
-/

namespace Jar.Proofs

/-- 𝓔_l always produces exactly l bytes. -/
theorem encodeFixedNat_size [JarConfig] (l x : Nat) :
    (Codec.encodeFixedNat l x).size = l := by
  induction l generalizing x with
  | zero => rfl
  | succ n ih =>
    unfold Codec.encodeFixedNat
    simp only [ByteArray.size, ByteArray.append, Array.size,
               List.length_append, List.length_cons, List.length_nil]
    have := ih (x / 256)
    simp only [ByteArray.size, Array.size] at this
    omega

/-- ByteArray.append preserves size additively. -/
theorem byteArray_append_size (a b : ByteArray) :
    (a ++ b).size = a.size + b.size := by
  cases a with | mk da =>
  cases b with | mk db =>
  change (ByteArray.append ⟨da⟩ ⟨db⟩).size = _
  unfold ByteArray.append
  simp only [ByteArray.size, Array.size, List.length_append]

-- ============================================================================
-- decodeFixedNat ∘ encodeFixedNat roundtrip
-- ============================================================================

/-- Generalized decode: foldl-based LE decode with initial accumulator pair. -/
private def decodePair (bs : ByteArray) (acc mul : Nat) : Nat × Nat :=
  bs.data.foldl (init := (acc, mul)) (fun (a, m) b => (a + b.toNat * m, m * 256))

/-- ByteArray.append preserves data array via toList. -/
private theorem byteArray_data_append' (a b : ByteArray) :
    (a ++ b).data = a.data ++ b.data := by
  cases a with | mk da => cases b with | mk db =>
  change (ByteArray.append ⟨da⟩ ⟨db⟩).data = da ++ db
  unfold ByteArray.append; apply Array.ext'; simp [Array.toList_append]

/-- decodePair distributes over ByteArray append via Array.foldl_append. -/
private theorem decodePair_append (a b : ByteArray) (acc mul : Nat) :
    decodePair (a ++ b) acc mul =
    let p := decodePair a acc mul; decodePair b p.1 p.2 := by
  unfold decodePair; rw [byteArray_data_append']; rw [Array.foldl_append]

private theorem uint8_ofNat_toNat (x : Nat) :
    (UInt8.ofNat (x % 256)).toNat = x % 256 := by
  simp [UInt8.ofNat, UInt8.toNat, Nat.mod_mod_of_dvd]

/-- Modular decomposition: x % a + a * (x/a % b) = x % (a*b).
    The foundation for proving the LE encoding roundtrip by induction on byte count. -/
private theorem mod_mul_decomp (x a b : Nat) :
    x % a + a * (x / a % b) = x % (a * b) := by
  have hdiv := (Nat.div_div_eq_div_mul x a b).symm
  have h1 : a * b * (x / a / b) + x % (a * b) = x := by
    rw [← hdiv]; exact Nat.div_add_mod x (a * b)
  have key : x % a + a * (x / a % b) + a * b * (x / a / b) = x := by
    calc x % a + a * (x / a % b) + a * b * (x / a / b)
        = x % a + a * (x / a % b + b * (x / a / b)) := by
          rw [Nat.mul_add, Nat.mul_assoc, Nat.add_assoc]
      _ = x % a + a * (x / a) := by rw [Nat.mod_add_div (x / a) b]
      _ = x := Nat.mod_add_div x a
  exact Nat.add_right_cancel (key.trans
    ((Nat.add_comm _ _).symm.trans h1).symm)

/-- Generalized roundtrip: decodePair (encodeFixedNat l x) accumulates correctly. -/
private theorem decodePair_encodeFixedNat (l x acc mul : Nat) :
    decodePair (Codec.encodeFixedNat l x) acc mul =
    (acc + (x % 2^(8*l)) * mul, mul * 256^l) := by
  induction l generalizing x acc mul with
  | zero =>
    show (acc, mul) = (acc + (x % 2^0) * mul, mul * 256^0)
    simp [Nat.mod_one]
  | succ n ih =>
    show decodePair (ByteArray.mk #[UInt8.ofNat (x % 256)] ++ Codec.encodeFixedNat n (x / 256))
      acc mul = _
    rw [decodePair_append]
    show decodePair (Codec.encodeFixedNat n (x / 256))
      (acc + (UInt8.ofNat (x % 256)).toNat * mul) (mul * 256) = _
    rw [uint8_ofNat_toNat, ih]
    simp only [Prod.mk.injEq]
    constructor
    · have decomp := mod_mul_decomp x 256 (2^(8*n))
      have pow_eq : 256 * 2^(8*n) = 2^(8*(n+1)) := by
        show 2^8 * 2^(8*n) = 2^(8*n + 8)
        rw [Nat.pow_add, Nat.mul_comm]
      rw [pow_eq] at decomp
      rw [show x / 256 % 2 ^ (8 * n) * (mul * 256) = 256 * (x / 256 % 2 ^ (8 * n)) * mul from by
        rw [← Nat.mul_assoc, Nat.mul_comm (x / 256 % _) mul, Nat.mul_assoc,
            Nat.mul_comm, Nat.mul_comm (x / 256 % _) 256]]
      rw [show acc + x % 256 * mul + 256 * (x / 256 % 2 ^ (8 * n)) * mul
            = acc + (x % 256 + 256 * (x / 256 % 2 ^ (8 * n))) * mul from by
        rw [Nat.add_mul]; omega]
      rw [decomp]
    · rw [show mul * 256 * 256 ^ n = mul * 256 ^ (n + 1) from by
        rw [Nat.pow_succ, Nat.mul_assoc, Nat.mul_comm (256 ^ n) 256]]

/-- decodeFixedNat (encodeFixedNat l x) = x % 2^(8*l).
    The codec roundtrip: encoding a natural number in l LE bytes then decoding
    recovers the value modulo 2^(8*l). This is the key serialization correctness
    property — values within the representable range survive a codec roundtrip. -/
theorem decodeFixedNat_encodeFixedNat [JarConfig] (l x : Nat) :
    Codec.decodeFixedNat (Codec.encodeFixedNat l x) = x % 2^(8*l) := by
  show (decodePair (Codec.encodeFixedNat l x) 0 1).1 = x % 2^(8*l)
  rw [decodePair_encodeFixedNat]
  simp

-- ============================================================================
-- encodeNat size bounds
-- ============================================================================

/-- encodeNat 0 produces exactly 1 byte. -/
theorem encodeNat_zero_size [JarConfig] :
    (Codec.encodeNat 0).size = 1 := by decide

/-- encodeNat for small values (< 128) produces 1 byte — l=0 path. -/
theorem encodeNat_small_size [JarConfig] :
    (Codec.encodeNat 127).size = 1 := by decide

/-- encodeNat for 128 produces 2 bytes — l=1 path. -/
theorem encodeNat_128_size [JarConfig] :
    (Codec.encodeNat 128).size = 2 := by decide

end Jar.Proofs
