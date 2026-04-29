//! Authorization pool rotation sub-transition (Section 8, eq 8.2-8.3).
//!
//! Each block, the authorization pool for each core is updated:
//! 1. Remove used authorizer (if a guarantee was made for this core)
//! 2. Append a new authorizer from the queue
//! 3. Keep only the last O (auth_pool_size) entries

use grey_types::Hash;
use grey_types::config::Config;

/// Input for the authorization sub-transition.
pub struct AuthorizationInput {
    /// The new timeslot.
    pub slot: u32,
    /// Authorizations used by guarantees: (core_index, authorizer_hash).
    pub auths: Vec<(u16, Hash)>,
}

/// Apply the authorization pool rotation.
///
/// For each core c (eq 8.2-8.3):
///   F(c) = `α[c]` \ {auth_hash} if auth was used for core c, else `α[c]`
///   `α'[c]` = ←O (F(c) ⌢ `ϕ[c][slot mod Q]`)
pub fn update_authorizations(
    config: &Config,
    auth_pools: &mut [Vec<Hash>],
    auth_queues: &[Vec<Hash>],
    input: &AuthorizationInput,
) {
    let pool_max = config.auth_pool_size;
    let queue_size = config.auth_queue_size;

    for core in 0..auth_pools.len() {
        // Step 1: Remove used authorizer if this core had a guarantee
        if let Some((_, auth_hash)) = input.auths.iter().find(|(c, _)| *c as usize == core)
            && let Some(pos) = auth_pools[core].iter().position(|h| h == auth_hash)
        {
            auth_pools[core].remove(pos);
        }

        // Step 2: Append new authorizer from queue
        if core < auth_queues.len() && !auth_queues[core].is_empty() {
            let queue = &auth_queues[core];
            let idx = input.slot as usize % queue_size;
            if idx < queue.len() {
                auth_pools[core].push(queue[idx]);
            }
        }

        // Step 3: Keep only last O entries
        while auth_pools[core].len() > pool_max {
            auth_pools[core].remove(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grey_types::config::Config;

    fn h(n: u8) -> Hash {
        Hash([n; 32])
    }

    #[test]
    fn test_append_from_queue() {
        let config = Config::tiny(); // O=8, Q=80
        let mut pools = vec![vec![h(1)]; 2];
        let queues = vec![vec![h(10); 80], vec![h(20); 80]];
        let input = AuthorizationInput {
            slot: 0,
            auths: vec![],
        };
        update_authorizations(&config, &mut pools, &queues, &input);
        // Each pool should have original + new from queue
        assert_eq!(pools[0].len(), 2);
        assert_eq!(pools[0][1], h(10));
        assert_eq!(pools[1][1], h(20));
    }

    #[test]
    fn test_remove_used_auth() {
        let config = Config::tiny();
        let mut pools = vec![vec![h(1), h(2), h(3)]];
        let queues = vec![vec![h(10); 80]];
        let input = AuthorizationInput {
            slot: 0,
            auths: vec![(0, h(2))], // remove h(2) from core 0
        };
        update_authorizations(&config, &mut pools, &queues, &input);
        // h(2) removed, h(10) appended: [h(1), h(3), h(10)]
        assert!(!pools[0].contains(&h(2)));
        assert!(pools[0].contains(&h(1)));
        assert!(pools[0].contains(&h(3)));
        assert!(pools[0].contains(&h(10)));
    }

    #[test]
    fn test_pool_capped_at_o() {
        let config = Config::tiny(); // O=8
        let mut pools = vec![(0..8u8).map(h).collect::<Vec<_>>()]; // full pool
        let queues = vec![vec![h(99); 80]];
        let input = AuthorizationInput {
            slot: 0,
            auths: vec![],
        };
        update_authorizations(&config, &mut pools, &queues, &input);
        // Pool was 8, added 1 = 9, trimmed to 8
        assert_eq!(pools[0].len(), 8);
        // Oldest removed, newest kept
        assert_eq!(*pools[0].last().unwrap(), h(99));
    }

    #[test]
    fn test_queue_index_wraps() {
        let config = Config::tiny(); // Q=80
        let mut pools = vec![vec![]];
        let mut queue = vec![h(0); 80];
        queue[5] = h(55); // slot 5 mod 80 = 5
        let queues = vec![queue];
        let input = AuthorizationInput {
            slot: 5,
            auths: vec![],
        };
        update_authorizations(&config, &mut pools, &queues, &input);
        assert_eq!(pools[0], vec![h(55)]);
    }

    #[test]
    fn test_empty_queues_no_append() {
        let config = Config::tiny();
        let mut pools = vec![vec![h(1)]];
        let queues: Vec<Vec<Hash>> = vec![vec![]]; // empty queue
        let input = AuthorizationInput {
            slot: 0,
            auths: vec![],
        };
        update_authorizations(&config, &mut pools, &queues, &input);
        assert_eq!(pools[0], vec![h(1)]); // unchanged
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use grey_types::Hash;
    use grey_types::config::Config;
    use grey_types::testing::arb_hash;
    use proptest::prelude::*;

    proptest! {
        /// Pool size never exceeds auth_pool_size (O) after any update.
        #[test]
        fn pool_size_bounded(
            initial_pool_len in 0usize..12,
            slot in any::<u32>(),
            use_auth in any::<bool>(),
        ) {
            let config = Config::tiny(); // O=8, Q=80
            let pool: Vec<Hash> = (0..initial_pool_len as u8).map(|i| Hash([i; 32])).collect();
            let mut pools = vec![pool];
            let queue = vec![Hash([0xAA; 32]); config.auth_queue_size];
            let queues = vec![queue];

            let auths = if use_auth && !pools[0].is_empty() {
                vec![(0u16, pools[0][0])]
            } else {
                vec![]
            };

            let input = AuthorizationInput { slot, auths };
            update_authorizations(&config, &mut pools, &queues, &input);

            prop_assert!(
                pools[0].len() <= config.auth_pool_size,
                "pool len {} > auth_pool_size {}",
                pools[0].len(),
                config.auth_pool_size
            );
        }

        /// Using an auth removes exactly that hash from the pool.
        #[test]
        fn used_auth_removed(
            pool_hashes in proptest::collection::vec(arb_hash(), 1..8),
            remove_idx in any::<prop::sample::Index>(),
            slot in any::<u32>(),
        ) {
            let config = Config::tiny();
            let mut pools = vec![pool_hashes.clone()];
            let queues = vec![vec![Hash([0xFF; 32]); config.auth_queue_size]];

            let idx = remove_idx.index(pool_hashes.len());
            let target = pool_hashes[idx];

            let input = AuthorizationInput {
                slot,
                auths: vec![(0, target)],
            };
            update_authorizations(&config, &mut pools, &queues, &input);

            // The target hash should appear one fewer time than before
            let before_count = pool_hashes.iter().filter(|h| **h == target).count();
            let after_count = pools[0].iter().filter(|h| **h == target).count();
            // Note: pool may be trimmed, so after_count could be less
            // But at minimum, one instance was removed (before trimming added the queue entry)
            prop_assert!(
                after_count < before_count || pools[0].len() < pool_hashes.len(),
                "target should have been removed"
            );
        }

        /// The queue entry at slot % queue_size is the one appended.
        #[test]
        fn correct_queue_entry_appended(
            slot in 0u32..1000,
        ) {
            let config = Config::tiny(); // Q=80
            let mut pools = vec![vec![]]; // empty pool
            let mut queue = vec![Hash::ZERO; config.auth_queue_size];
            let expected_idx = slot as usize % config.auth_queue_size;
            let expected_hash = Hash([expected_idx as u8; 32]);
            queue[expected_idx] = expected_hash;
            let queues = vec![queue];

            let input = AuthorizationInput {
                slot,
                auths: vec![],
            };
            update_authorizations(&config, &mut pools, &queues, &input);

            prop_assert_eq!(pools[0].len(), 1);
            prop_assert_eq!(pools[0][0], expected_hash);
        }

        /// Multiple cores are updated independently.
        #[test]
        fn multi_core_independence(
            num_cores in 2usize..6,
            slot in any::<u32>(),
        ) {
            let config = Config::tiny();
            let mut pools: Vec<Vec<Hash>> = (0..num_cores)
                .map(|c| vec![Hash([c as u8; 32])])
                .collect();
            let queues: Vec<Vec<Hash>> = (0..num_cores)
                .map(|c| vec![Hash([100 + c as u8; 32]); config.auth_queue_size])
                .collect();

            // Only remove from core 0
            let input = AuthorizationInput {
                slot,
                auths: vec![(0, Hash([0; 32]))],
            };
            update_authorizations(&config, &mut pools, &queues, &input);

            // Core 0: removed its hash, added queue entry → should have 1 entry (the queue one)
            prop_assert!(pools[0].contains(&Hash([100; 32])));
            // Core 1+: kept original + added queue entry → should have 2 entries
            for (c, pool) in pools.iter().enumerate().skip(1) {
                prop_assert!(pool.contains(&Hash([c as u8; 32])));
                prop_assert!(pool.contains(&Hash([100 + c as u8; 32])));
            }
        }
    }
}
