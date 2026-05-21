//! Recursive sub-VM spawn bench guest.
//!
//! Endpoint 0 reads `depth` from φ[7] (a0). If zero, returns 0. Else
//! derive_spawns a child Cap::Instance from the Image at
//! `SLOT_IMAGE_RECURSE` (recursive — same image as the parent),
//! threads `depth - 1` to the child via φ[9] (host_call's
//! arg-passing convention), and CALLs the child at endpoint 0.

#![cfg_attr(target_os = "none", no_std)]

use subsoil as _;
