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

end Jar.Proofs
