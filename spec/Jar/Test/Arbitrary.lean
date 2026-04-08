import Plausible
import Jar.Notation
import Jar.Types

/-!
# Arbitrary Instances for Jar Types

Random generators for property-based testing with Plausible.
-/

namespace Jar.Test.Arb

open Jar
open Plausible Plausible.Arbitrary Plausible.Gen

variable [JarConfig]

-- ============================================================================
-- ByteArray
-- ============================================================================

instance : Arbitrary ByteArray where
  arbitrary := do
    let arr ← Gen.arrayOf (arbitrary : Gen UInt8)
    return ByteArray.mk arr

instance : Shrinkable ByteArray where
  shrink bs :=
    if bs.size == 0 then []
    else [ByteArray.mk (bs.data.extract 0 (bs.size / 2))]

-- ============================================================================
-- OctetSeq n — fixed-size byte sequences
-- ============================================================================

/-- Generate exactly n random bytes. -/
def genOctetSeq (n : Nat) : Gen (OctetSeq n) := do
  let mut arr := ByteArray.empty
  for _ in List.range n do
    let b ← (arbitrary : Gen UInt8)
    arr := arr.push b
  -- arr should have exactly n bytes from the loop
  if h : arr.size = n then
    return ⟨arr, h⟩
  else
    -- Fallback: use default (all zeros)
    return default

instance : Arbitrary (OctetSeq n) where
  arbitrary := genOctetSeq n

instance : Shrinkable (OctetSeq n) where
  shrink _ := []

-- ============================================================================
-- Dict K V — association lists
-- ============================================================================

instance {α β : Type} [BEq α] [Arbitrary α] [Arbitrary β] : Arbitrary (Dict α β) where
  arbitrary := do
    let pairs ← Gen.listOf (do return (← arbitrary, ← arbitrary) : Gen (α × β))
    return ⟨pairs⟩

instance {α β : Type} [BEq α] : Shrinkable (Dict α β) where
  shrink d := match d.entries with
    | [] => []
    | _ :: rest => [⟨rest⟩]

-- ============================================================================
-- Fin-based type aliases: CoreIndex, ValidatorIndex
-- Plausible has Arbitrary (Fin (n+1)), these just need the right defeq.
-- ============================================================================

instance : Arbitrary CoreIndex where
  arbitrary := do
    let n ← Gen.chooseNat
    return ⟨n % Jar.C, Nat.mod_lt _ JarConfig.valid.hC⟩

instance : Shrinkable CoreIndex where
  shrink _ := []

instance : Arbitrary ValidatorIndex where
  arbitrary := do
    let n ← Gen.chooseNat
    return ⟨n % Jar.V, Nat.mod_lt _ JarConfig.valid.hV⟩

instance : Shrinkable ValidatorIndex where
  shrink _ := []

-- ============================================================================
-- Work types
-- ============================================================================

instance : Arbitrary WorkError where
  arbitrary := do
    let n ← (arbitrary : Gen UInt8)
    match n.toNat % 6 with
    | 0 => return .outOfGas
    | 1 => return .panic
    | 2 => return .badExports
    | 3 => return .oversize
    | 4 => return .badCode
    | _ => return .bigCode

instance : Shrinkable WorkError where
  shrink _ := []

instance : Arbitrary WorkResult where
  arbitrary := do
    let b ← Gen.chooseAny Bool
    if b then return .ok (← arbitrary)
    else return .err (← arbitrary)

instance : Shrinkable WorkResult where
  shrink _ := []

instance : Arbitrary WorkDigest where
  arbitrary := do
    return {
      serviceId := ← arbitrary
      codeHash := ← arbitrary
      payloadHash := ← arbitrary
      gasLimit := ← arbitrary
      result := ← arbitrary
      gasUsed := ← arbitrary
      importsCount := ← Gen.chooseNat
      extrinsicsCount := ← Gen.chooseNat
      extrinsicsSize := ← Gen.chooseNat
      exportsCount := ← Gen.chooseNat
    }

instance : Shrinkable WorkDigest where
  shrink _ := []

instance : Arbitrary AvailabilitySpec where
  arbitrary := do
    return {
      packageHash := ← arbitrary
      bundleLength := ← arbitrary
      erasureRoot := ← arbitrary
      segmentRoot := ← arbitrary
      segmentCount := ← Gen.chooseNat
    }

instance : Shrinkable AvailabilitySpec where
  shrink _ := []

instance : Arbitrary RefinementContext where
  arbitrary := do
    return {
      anchorHash := ← arbitrary
      anchorStateRoot := ← arbitrary
      anchorBeefyRoot := ← arbitrary
      lookupAnchorHash := ← arbitrary
      lookupAnchorTimeslot := ← arbitrary
      prerequisites := ← Gen.arrayOf arbitrary
    }

instance : Shrinkable RefinementContext where
  shrink _ := []

instance : Arbitrary WorkReport where
  arbitrary := do
    return {
      availSpec := ← arbitrary
      context := ← arbitrary
      coreIndex := ← arbitrary
      authorizerHash := ← arbitrary
      authOutput := ← arbitrary
      segmentRootLookup := ← arbitrary
      digests := ← Gen.arrayOf arbitrary
      authGasUsed := ← arbitrary
    }

instance : Shrinkable WorkReport where
  shrink _ := []

-- ============================================================================
-- Validator types
-- ============================================================================

instance : Arbitrary ValidatorKey where
  arbitrary := do
    return {
      bandersnatch := ← arbitrary
      ed25519 := ← arbitrary
      bls := ← arbitrary
      metadata := ← arbitrary
    }

instance : Shrinkable ValidatorKey where
  shrink _ := []

instance : Arbitrary Ticket where
  arbitrary := do
    let id ← arbitrary
    let n ← (arbitrary : Gen UInt8)
    return { id, attempt := n.toNat % Jar.N_TICKETS }

instance : Shrinkable Ticket where
  shrink _ := []

instance : Arbitrary SealKeySeries where
  arbitrary := do
    let b ← Gen.chooseAny Bool
    if b then return .tickets (← Gen.arrayOf arbitrary)
    else return .fallback (← Gen.arrayOf arbitrary)

instance : Shrinkable SealKeySeries where
  shrink _ := []

-- ============================================================================
-- Header types
-- ============================================================================

instance : Arbitrary EpochMarker where
  arbitrary := do
    return {
      entropy := ← arbitrary
      entropyPrev := ← arbitrary
      validators := ← Gen.arrayOf (do return (← arbitrary, ← arbitrary) : Gen (_ × _))
    }

instance : Shrinkable EpochMarker where
  shrink _ := []

instance : Arbitrary Judgment where
  arbitrary := do
    return {
      isValid := ← arbitrary
      validatorIndex := ← arbitrary
      signature := ← arbitrary
    }

instance : Shrinkable Judgment where
  shrink _ := []

instance : Arbitrary Verdict where
  arbitrary := do
    return {
      reportHash := ← arbitrary
      age := ← arbitrary
      judgments := ← Gen.arrayOf arbitrary
    }

instance : Shrinkable Verdict where
  shrink _ := []

instance : Arbitrary Culprit where
  arbitrary := do
    return {
      reportHash := ← arbitrary
      validatorKey := ← arbitrary
      signature := ← arbitrary
    }

instance : Shrinkable Culprit where
  shrink _ := []

instance : Arbitrary Fault where
  arbitrary := do
    return {
      reportHash := ← arbitrary
      isValid := ← arbitrary
      validatorKey := ← arbitrary
      signature := ← arbitrary
    }

instance : Shrinkable Fault where
  shrink _ := []

instance : Arbitrary TicketProof where
  arbitrary := do
    let n ← (arbitrary : Gen UInt8)
    return {
      attempt := n.toNat % Jar.N_TICKETS
      proof := ← arbitrary
    }

instance : Shrinkable TicketProof where
  shrink _ := []

instance : Arbitrary Assurance where
  arbitrary := do
    return {
      anchor := ← arbitrary
      bitfield := ← arbitrary
      validatorIndex := ← arbitrary
      signature := ← arbitrary
    }

instance : Shrinkable Assurance where
  shrink _ := []

instance : Arbitrary DisputesExtrinsic where
  arbitrary := do
    return {
      verdicts := ← Gen.arrayOf arbitrary
      culprits := ← Gen.arrayOf arbitrary
      faults := ← Gen.arrayOf arbitrary
    }

instance : Shrinkable DisputesExtrinsic where
  shrink _ := []

instance : Arbitrary Guarantee where
  arbitrary := do
    return {
      report := ← arbitrary
      timeslot := ← arbitrary
      credentials := ← Gen.arrayOf (do return (← arbitrary, ← arbitrary) : Gen (_ × _))
    }

instance : Shrinkable Guarantee where
  shrink _ := []

instance : Arbitrary PendingReport where
  arbitrary := do
    return {
      report := ← arbitrary
      timeslot := ← arbitrary
    }

instance : Shrinkable PendingReport where
  shrink _ := []

-- ============================================================================
-- Account types
-- ============================================================================

instance : Arbitrary BalanceEcon where
  arbitrary := do return { balance := ← arbitrary, gratis := ← arbitrary }

instance : Arbitrary QuotaEcon where
  arbitrary := do return { quotaItems := ← arbitrary, quotaBytes := ← arbitrary }

instance : Arbitrary BalanceTransfer where
  arbitrary := do return { amount := ← arbitrary }

instance : Arbitrary QuotaTransfer where
  arbitrary := return {}

instance [Arbitrary JarConfig.EconType] : Arbitrary ServiceAccount where
  arbitrary := do
    return {
      storage := ← arbitrary
      preimages := ← arbitrary
      preimageInfo := ⟨[]⟩  -- complex key type, keep empty
      econ := ← arbitrary
      codeHash := ← arbitrary
      minAccGas := ← arbitrary
      minOnTransferGas := ← arbitrary
      itemCount := ← arbitrary
      creationSlot := ← arbitrary
      lastAccumulation := ← arbitrary
    }

instance : Shrinkable ServiceAccount where
  shrink _ := []

instance [Arbitrary JarConfig.TransferType] : Arbitrary DeferredTransfer where
  arbitrary := do
    return {
      source := ← arbitrary
      dest := ← arbitrary
      payload := ← arbitrary
      memo := ← arbitrary
      gas := ← arbitrary
    }

instance : Shrinkable DeferredTransfer where
  shrink _ := []

instance : Arbitrary PrivilegedServices where
  arbitrary := do
    return {
      manager := ← arbitrary
      assigners := ← Gen.arrayOf arbitrary
      designator := ← arbitrary
      registrar := ← arbitrary
      alwaysAccumulate := ← arbitrary
    }

instance : Shrinkable PrivilegedServices where
  shrink _ := []

-- ============================================================================
-- State types
-- ============================================================================

instance : Arbitrary JudgmentsState where
  arbitrary := do
    return {
      good := ← Gen.arrayOf arbitrary
      bad := ← Gen.arrayOf arbitrary
      wonky := ← Gen.arrayOf arbitrary
      offenders := ← Gen.arrayOf arbitrary
    }

instance : Shrinkable JudgmentsState where
  shrink _ := []

instance : Arbitrary ValidatorRecord where
  arbitrary := do
    return {
      blocks := ← Gen.chooseNat
      tickets := ← Gen.chooseNat
      preimageCount := ← Gen.chooseNat
      preimageSize := ← Gen.chooseNat
      guarantees := ← Gen.chooseNat
      assurances := ← Gen.chooseNat
    }

instance : Shrinkable ValidatorRecord where
  shrink _ := []

instance : Arbitrary CoreStatistics where
  arbitrary := do
    return {
      daLoad := ← Gen.chooseNat
      popularity := ← Gen.chooseNat
      imports := ← Gen.chooseNat
      extrinsicCount := ← Gen.chooseNat
      extrinsicSize := ← Gen.chooseNat
      exports := ← Gen.chooseNat
      bundleSize := ← Gen.chooseNat
      gasUsed := ← arbitrary
    }

instance : Shrinkable CoreStatistics where
  shrink _ := []

instance : Arbitrary Entropy where
  arbitrary := do
    return {
      current := ← arbitrary
      previous := ← arbitrary
      twoBack := ← arbitrary
      threeBack := ← arbitrary
    }

instance : Shrinkable Entropy where
  shrink _ := []

instance : Arbitrary SafroleState where
  arbitrary := do
    return {
      pendingKeys := ← Gen.arrayOf arbitrary
      ringRoot := ← arbitrary
      sealKeys := ← arbitrary
      ticketAccumulator := ← Gen.arrayOf arbitrary
    }

instance : Shrinkable SafroleState where
  shrink _ := []

end Jar.Test.Arb
