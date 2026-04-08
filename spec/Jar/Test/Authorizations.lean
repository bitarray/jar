import Jar.Notation
import Jar.Types

/-!
# Authorization Pool Sub-Transition Test Harness

Tests the §8 authorization pool rotation: remove used authorizer,
append from queue, keep last O entries.
-/

namespace Jar.Test.Authorizations

open Jar

variable [JarConfig]

-- ============================================================================
-- Flattened Authorization State (matches test vector JSON shape)
-- ============================================================================

/-- Flattened state: per-core authorization pools and queues. -/
structure FlatAuthState where
  authPools : Array (Array Hash)
  authQueues : Array (Array Hash)
  deriving BEq

-- ============================================================================
-- Input
-- ============================================================================

/-- A single used authorization: (core_index, auth_hash). -/
structure AuthUsed where
  core : Nat
  authHash : Hash

/-- Input for the authorization sub-transition. -/
structure AuthInput where
  slot : Nat
  auths : Array AuthUsed

-- ============================================================================
-- Authorization Sub-Transition (§8)
-- ============================================================================

/-- Compute the authorization pool rotation.
    For each core c:
      1. Remove used authorizer (from auths) if any
      2. Append queue[slot % Q]
      3. Keep only last O entries -/
def authorizationTransition
    (pre : FlatAuthState) (inp : AuthInput) : FlatAuthState :=
  let pools := pre.authPools.mapIdx fun (c : Nat) pool =>
    -- Step 1: remove used auth for this core
    let pool := match inp.auths.find? (fun a => a.core == c) with
      | some a => pool.filter (· != a.authHash)
      | none => pool
    -- Step 2: append from queue
    let pool := if c < pre.authQueues.size then
      let queue := pre.authQueues[c]!
      let idx := inp.slot % Q_QUEUE
      if idx < queue.size then pool.push queue[idx]!
      else pool
    else pool
    -- Step 3: keep last O entries
    if pool.size > O_POOL then
      pool.extract (pool.size - O_POOL) pool.size
    else pool
  { authPools := pools
    authQueues := pre.authQueues }

-- ============================================================================
-- Test Runner
-- ============================================================================

/-- Display a Hash as hex for diagnostics. -/
def hashToHex (h : Hash) : String :=
  let bytes := h.data.data
  String.join (bytes.toList.map fun b =>
    let hi := b.toNat / 16
    let lo := b.toNat % 16
    let hexChar (n : Nat) : Char :=
      if n < 10 then Char.ofNat (48 + n) else Char.ofNat (87 + n)
    String.ofList [hexChar hi, hexChar lo])

/-- Run a single authorization test case. Returns true on pass. -/
def runTest (name : String) (pre : FlatAuthState) (inp : AuthInput)
    (post : FlatAuthState) : IO Bool := do
  let result := authorizationTransition pre inp
  let mut ok := true

  for c in [:result.authPools.size] do
    let rPool := result.authPools[c]!
    let ePool := post.authPools[c]!
    if rPool != ePool then
      ok := false
      IO.println s!"  Pool[{c}] mismatch:"
      IO.println s!"    expected size={ePool.size}, got size={rPool.size}"
      -- Show first diff
      for i in [:min rPool.size ePool.size] do
        if rPool[i]! != ePool[i]! then
          IO.println s!"    [{i}]: expected {hashToHex ePool[i]!}, got {hashToHex rPool[i]!}"
          break

  if ok then
    IO.println s!"  ✓ {name}"
  else
    IO.println s!"  ✗ {name}"
  return ok

end Jar.Test.Authorizations
