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

/// SwissTable hash map allocated by `A`. Alias for
/// `hashbrown::HashMap<K, V, DefaultHashBuilder, A>` with the
/// parameter order rearranged to put the allocator before the hasher
/// (matching `Box<T, A>` / `Vec<T, A>`).
pub type HashMap<K, V, A = Global> = hashbrown::HashMap<K, V, DefaultHashBuilder, A>;

#[cfg(test)]
mod hashmap_tests;
