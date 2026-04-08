import Jar.Notation
import Jar.Types
import Jar.Crypto

/-!
# Preimages Sub-Transition Test Harness

Tests the §12.35-12.38 preimage integration: validation, sorted ordering,
"needed" checks, and state updates (blobs, requests).
-/

namespace Jar.Test.Preimages

open Jar Jar.Crypto

variable [JarConfig]

-- ============================================================================
-- Types
-- ============================================================================

/-- A preimage request: (hash, length) → timeslots when provided. -/
structure TPRequest where
  hash : Hash
  length : Nat
  timeslots : Array Nat
  deriving BEq, Inhabited

/-- Per-service preimage state. -/
structure TPServiceAccount where
  serviceId : Nat
  blobHashes : Array Hash          -- sorted hashes of stored blobs
  requests : Array TPRequest       -- sorted by (hash, length)
  deriving BEq, Inhabited

/-- State for preimages sub-transition. -/
structure TPState where
  accounts : Array TPServiceAccount
  deriving BEq

/-- A preimage to provide. -/
structure TPPreimage where
  requester : Nat
  blob : ByteArray
  deriving Inhabited

/-- Input to the preimages sub-transition. -/
structure TPInput where
  preimages : Array TPPreimage
  slot : Nat

-- ============================================================================
-- Result type
-- ============================================================================

inductive TPResult where
  | ok
  | err (msg : String)
  deriving BEq

-- ============================================================================
-- Helpers
-- ============================================================================

def compareByteArrays (a b : ByteArray) : Ordering := Id.run do
  let len := min a.size b.size
  for i in [:len] do
    if a.data[i]! < b.data[i]! then return .lt
    if a.data[i]! > b.data[i]! then return .gt
  compare a.size b.size

def findAccount (accts : Array TPServiceAccount) (sid : Nat) : Option (Nat × TPServiceAccount) :=
  accts.findIdx? (·.serviceId == sid) |>.bind fun idx => some (idx, accts[idx]!)

def hashIn (h : Hash) (arr : Array Hash) : Bool := arr.any (· == h)

def findRequest (reqs : Array TPRequest) (h : Hash) (len : Nat) : Option (Nat × TPRequest) :=
  reqs.findIdx? (fun r => r.hash == h && r.length == len) |>.bind fun idx => some (idx, reqs[idx]!)

def insertSortedHash (arr : Array Hash) (h : Hash) : Array Hash :=
  let sortKey (a b : Hash) : Bool := compareByteArrays a.data b.data == .lt
  (arr.push h).qsort sortKey

-- ============================================================================
-- Preimages Sub-Transition (§12.35-12.38)
-- ============================================================================

def preimagesTransition
    (pre : TPState) (inp : TPInput)
    : (TPResult × TPState) := Id.run do
  -- Hash all preimage blobs
  let hashed := inp.preimages.map fun p =>
    let h := blake2b p.blob
    (p.requester, h, p.blob.size)

  -- eq 12.37: Each preimage must be "needed"
  for (sid, h, len) in hashed do
    match findAccount pre.accounts sid with
    | none => return (.err "preimage_unneeded", pre)
    | some (_, acct) =>
      match findRequest acct.requests h len with
      | none => return (.err "preimage_unneeded", pre)
      | some _ =>
        if hashIn h acct.blobHashes then
          return (.err "preimage_unneeded", pre)

  -- eq 12.36: Sorted by (service_id, hash(blob)), no duplicates
  for i in [1:hashed.size] do
    let (s0, h0, _) := hashed[i - 1]!
    let (s1, h1, _) := hashed[i]!
    if s0 > s1 then return (.err "preimages_not_sorted_unique", pre)
    if s0 == s1 then
      if compareByteArrays h0.data h1.data != .lt then
        return (.err "preimages_not_sorted_unique", pre)

  -- eq 12.38: Apply changes
  let mut accounts := pre.accounts
  for i in [:inp.preimages.size] do
    let p := inp.preimages[i]!
    let (sid, h, _len) := hashed[i]!
    match findAccount accounts sid with
    | none => pure ()  -- shouldn't happen after validation
    | some (acctIdx, acct) =>
      -- Store blob hash
      let newBlobs := insertSortedHash acct.blobHashes h
      -- Update request: set timeslots to [current_slot]
      let newReqs := acct.requests.map fun r =>
        if r.hash == h && r.length == p.blob.size then
          { r with timeslots := #[inp.slot] }
        else r
      let newAcct := { acct with blobHashes := newBlobs, requests := newReqs }
      accounts := accounts.set! acctIdx newAcct

  (.ok, { accounts })

-- ============================================================================
-- Test Runner
-- ============================================================================

def runTest (name : String) (pre : TPState) (inp : TPInput)
    (expectedResult : TPResult) (postState : TPState)
    : IO Bool := do
  let (result, newState) := preimagesTransition pre inp
  let mut ok := true

  if result != expectedResult then
    ok := false
    match result, expectedResult with
    | .err got, .err expected =>
      IO.println s!"  result: expected err '{expected}', got err '{got}'"
    | .err got, .ok =>
      IO.println s!"  result: expected ok, got err '{got}'"
    | .ok, .err expected =>
      IO.println s!"  result: expected err '{expected}', got ok"
    | .ok, .ok => pure ()

  if newState != postState then
    ok := false
    IO.println s!"  state mismatch:"
    for i in [:newState.accounts.size] do
      if i < postState.accounts.size then
        let got := newState.accounts[i]!
        let exp := postState.accounts[i]!
        if got.blobHashes.size != exp.blobHashes.size then
          IO.println s!"    account[{i}] blobs: expected {exp.blobHashes.size}, got {got.blobHashes.size}"
        if got.requests != exp.requests then
          IO.println s!"    account[{i}] requests mismatch"

  if ok then
    IO.println s!"  ✓ {name}"
  else
    IO.println s!"  ✗ {name}"
  return ok

end Jar.Test.Preimages
