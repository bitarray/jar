//! Service accounts, accumulation, and refinement (Sections 9, 12, 14).
//!
//! Services are the core computational units in JAM, analogous to smart contracts.
//! Each service has:
//! - Code (split into Refine and Accumulate entry points)
//! - Storage (key-value dictionary)
//! - Balance
//! - Preimage lookups

pub mod accumulation;

use grey_types::state::ServiceAccount;
use grey_types::Balance;

/// Compute the minimum balance for a service account (eq 9.8).
///
/// BS + BI * items + BL * total_octets
pub fn minimum_balance(account: &ServiceAccount) -> Balance {
    use grey_types::constants::*;
    let items = account.storage.len() as u64
        + account.preimage_lookup.len() as u64
        + account.preimage_info.len() as u64;

    let mut total_octets = 0u64;
    for v in account.storage.values() {
        total_octets += v.len() as u64;
    }
    for v in account.preimage_lookup.values() {
        total_octets += v.len() as u64;
    }

    BALANCE_SERVICE_MINIMUM + BALANCE_PER_ITEM * items + BALANCE_PER_OCTET * total_octets
}

/// Check if a service account has sufficient balance.
pub fn is_solvent(account: &ServiceAccount) -> bool {
    account.balance >= minimum_balance(account)
}

/// Create a new empty service account with the given code hash.
pub fn new_service_account(
    code_hash: grey_types::Hash,
    balance: Balance,
    min_accumulate_gas: grey_types::Gas,
    min_on_transfer_gas: grey_types::Gas,
) -> ServiceAccount {
    ServiceAccount {
        code_hash,
        balance,
        min_accumulate_gas,
        min_on_transfer_gas,
        storage: Default::default(),
        preimage_lookup: Default::default(),
        preimage_info: Default::default(),
        free_storage_offset: 0,
        total_footprint: 0,
        accumulation_counter: 0,
        last_accumulation: 0,
        last_activity: 0,
        preimage_count: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grey_types::Hash;

    #[test]
    fn test_minimum_balance_empty() {
        let account = new_service_account(Hash::ZERO, 1000, 0, 0);
        assert_eq!(
            minimum_balance(&account),
            grey_types::constants::BALANCE_SERVICE_MINIMUM
        );
    }

    #[test]
    fn test_is_solvent() {
        let account = new_service_account(Hash::ZERO, 1000, 0, 0);
        assert!(is_solvent(&account));

        let poor_account = new_service_account(Hash::ZERO, 0, 0, 0);
        assert!(!is_solvent(&poor_account));
    }
}
