//! Allocator-aware collections.
//!
//! - [`HashMap<K, V, A>`] — type alias for
//!   `hashbrown::HashMap<K, V, DefaultHashBuilder, A>`. Unordered
//!   iteration; allocator-aware on stable via hashbrown's
//!   `allocator-api2` feature.
//!
//! No allocator-aware `BTreeMap`: there's no stable impl, and no
//! current consumer parameterises BTreeMap by allocator. Callers that
//! want ordered iteration can sort a HashMap iterator at consumption
//! time.

pub use hashbrown::DefaultHashBuilder;

use crate::Global;

/// SwissTable hash map. Re-export of `hashbrown::HashMap<K, V, S, A>`
/// with the upstream parameter order preserved: `K, V, S, A`. The
/// `S` slot lets callers pin a deterministic hasher (e.g.
/// `foldhash::fast::FixedState`) which the shared-memory state cache
/// requires; the heap-backed default `DefaultHashBuilder` is
/// `foldhash::fast::RandomState`.
pub type HashMap<K, V, S = DefaultHashBuilder, A = Global> = hashbrown::HashMap<K, V, S, A>;

#[cfg(test)]
mod hashmap_tests;
