import Jar.JAVM.Memory

/-!
# JAVM Memory Proofs

Properties of JAVM memory operations: page arithmetic (pageOf, pageAligned),
access control (guard zone checks), and heap growth (sbrk).
-/

namespace Jar.Proofs

-- ============================================================================
-- Page arithmetic (pageOf, pageAligned)
-- ============================================================================

/-- pageOf zero is zero — the first page. -/
theorem pageOf_zero : Jar.JAVM.pageOf 0 = 0 := by
  unfold Jar.JAVM.pageOf; simp

/-- pageAligned zero is zero. -/
theorem pageAligned_zero : Jar.JAVM.pageAligned 0 = 0 := by
  unfold Jar.JAVM.pageAligned; simp [pageOf_zero]

-- ============================================================================
-- Guard zone: addresses below guardZone always panic
-- ============================================================================

/-- Reading from the guard zone (addr < guardZone) always panics.
    This is the core memory safety invariant — low addresses are never accessible. -/
theorem checkReadable_guard_zone_panics (m : Jar.JAVM.Memory) (addr : UInt64) (n : Nat)
    (h : addr.toNat < m.guardZone) :
    Jar.JAVM.checkReadable m addr n = .panic := by
  unfold Jar.JAVM.checkReadable
  simp [h]

/-- Writing to the guard zone (addr < guardZone) always panics. -/
theorem checkWritable_guard_zone_panics (m : Jar.JAVM.Memory) (addr : UInt64) (n : Nat)
    (h : addr.toNat < m.guardZone) :
    Jar.JAVM.checkWritable m addr n = .panic := by
  unfold Jar.JAVM.checkWritable
  simp [h]

/-- Reading from the guard zone propagates through readMemBytes. -/
theorem readMemBytes_guard_zone_panics (m : Jar.JAVM.Memory) (addr : UInt64) (n : Nat)
    (h : addr.toNat < m.guardZone) :
    Jar.JAVM.readMemBytes m addr n = .panic := by
  unfold Jar.JAVM.readMemBytes
  rw [checkReadable_guard_zone_panics m addr n h]

-- ============================================================================
-- sbrk query mode (size = 0)
-- ============================================================================

/-- sbrk with zero size is a query: returns unchanged memory and current heap top. -/
theorem sbrk_zero (m : Jar.JAVM.Memory) :
    Jar.JAVM.sbrk m 0 = (m, UInt64.ofNat m.heapTop) := by
  unfold Jar.JAVM.sbrk
  simp

/-- sbrk with zero size preserves memory state. -/
theorem sbrk_zero_preserves (m : Jar.JAVM.Memory) :
    (Jar.JAVM.sbrk m 0).1 = m := by
  rw [sbrk_zero]

/-- sbrk with zero size returns the current heap top. -/
theorem sbrk_zero_returns_top (m : Jar.JAVM.Memory) :
    (Jar.JAVM.sbrk m 0).2 = UInt64.ofNat m.heapTop := by
  rw [sbrk_zero]

-- ============================================================================
-- sbrk oversized request
-- ============================================================================

/-- sbrk rejects requests larger than 2^32 bytes by returning 0.
    This ensures the 32-bit address space bound is enforced. -/
theorem sbrk_too_large (m : Jar.JAVM.Memory) (size : UInt64)
    (h : size.toNat > 2^32) :
    Jar.JAVM.sbrk m size = (m, 0) := by
  unfold Jar.JAVM.sbrk
  simp [h]

/-- sbrk returns 0 (failure) for oversized requests. -/
theorem sbrk_too_large_fails (m : Jar.JAVM.Memory) (size : UInt64)
    (h : size.toNat > 2^32) :
    (Jar.JAVM.sbrk m size).2 = 0 := by
  rw [sbrk_too_large m size h]

/-- sbrk preserves memory for oversized requests. -/
theorem sbrk_too_large_preserves (m : Jar.JAVM.Memory) (size : UInt64)
    (h : size.toNat > 2^32) :
    (Jar.JAVM.sbrk m size).1 = m := by
  rw [sbrk_too_large m size h]

end Jar.Proofs
