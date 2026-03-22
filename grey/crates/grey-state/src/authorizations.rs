//! Authorization pool rotation sub-transition (Section 8, eq 8.2-8.3).
//!
//! Each block, the authorization pool for each core is updated:
//! 1. Remove used authorizer (if a guarantee was made for this core)
//! 2. Append a new authorizer from the queue
//! 3. Keep only the last O (auth_pool_size) entries

use grey_types::config::Config;
use grey_types::Hash;

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
///   F(c) = α[c] \ {auth_hash} if auth was used for core c, else α[c]
///   α'[c] = ←O (F(c) ⌢ ϕ[c][slot mod Q])
pub fn update_authorizations(
    config: &Config,
    auth_pools: &mut Vec<Vec<Hash>>,
    auth_queues: &[Vec<Hash>],
    input: &AuthorizationInput,
) {
    let pool_max = config.auth_pool_size;
    let queue_size = config.auth_queue_size;

    for core in 0..auth_pools.len() {
        // Step 1: Remove used authorizer if this core had a guarantee
        if let Some((_, auth_hash)) = input.auths.iter().find(|(c, _)| *c as usize == core) {
            if let Some(pos) = auth_pools[core].iter().position(|h| h == auth_hash) {
                auth_pools[core].remove(pos);
            }
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
