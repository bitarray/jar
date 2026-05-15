//! Chain genesis: σ initialization + kernel-cap injection.
//!
//! `genesis` takes a chain `Image` and constructs:
//! - An empty σ (`State`) with the chain Image registered.
//! - The chain Instance's root cnode pre-populated with kernel-
//!   issued caps at the well-known slots ([`crate::abi`]).
//! - The chain `InstanceCap` itself.
//!
//! Per architecture.md Stage 4, kernel-issued caps comprise:
//! - Root `Gas{0}` and `Quota{0}` handles (one each — chain spec
//!   pulls per-instruction gas debits from `Gas{0}`).
//! - Factory caps: SetGasMeter, SetStorageQuota, MintGas, MintQuota,
//!   CreateYieldCatcher.
//! - HostOpen / HostSave entry handles.
//! - A `YieldCatcher` pre-populated with OogMarker and
//!   StorageExhaustedMarker so the chain catches OOG/Storage faults
//!   by default.

use jar_cap::{
    CNodeBackend, Cap, InMemoryCNode, InstanceCap,
    image::{Image, image_content_hash},
};
use javm::{KernelImage, kernel_image_hash};

use crate::abi;
use crate::state::State;

/// Output of `genesis`: the initial σ, the chain Instance, and the
/// chain's root cnode (256 slots, populated with kernel-issued caps
/// at the abi::BARE_* slots).
pub struct Genesis {
    pub state: State,
    pub chain_instance: InstanceCap,
    pub chain_cnode: Box<dyn CNodeBackend<Cap> + Send + Sync>,
}

/// Mint a kernel-issued unit handle: a `Cap::Instance` whose
/// `image_hash_chain` matches the well-known kernel image, with
/// `content_hash` carrying the `id` in its low 8 bytes (so a
/// running guest can decode the id without going through σ).
fn kernel_unit_cap(image: KernelImage, id: u64) -> Cap {
    let mut content_hash = [0u8; 32];
    content_hash[..8].copy_from_slice(&id.to_le_bytes());
    Cap::Instance(InstanceCap {
        image_hash_chain: kernel_image_hash(image),
        content_hash,
    })
}

/// Mint a stateless kernel-issued cap (no unique id; same value
/// for all chain Instances). The `content_hash` is just zeros.
fn kernel_stateless_cap(image: KernelImage) -> Cap {
    Cap::Instance(InstanceCap {
        image_hash_chain: kernel_image_hash(image),
        content_hash: [0u8; 32],
    })
}

/// Construct chain genesis from a chain Image.
///
/// `chain_image` is registered in `state.code_blobs` keyed by its
/// content hash (used as `code_id` for now — Stage C may refine).
/// The chain `Instance` is registered in `state.vaults` under
/// `VaultId(0)`.
///
/// The chain's `image_hash_chain` is the image's content_hash
/// directly (genesis case — no prior chain).
pub fn genesis(chain_image: Image) -> Genesis {
    let mut state = State::new();

    // 1. Register the chain Image in σ.code_blobs. The image's
    //    content_hash drives identity; CodeId is just a σ-side
    //    monotonic alias.
    let image_hash = image_content_hash::<jar_cap::Blake2b256>(&chain_image);
    let code_id = state.counters.allocate_code_id();
    state.code_blobs.insert(code_id, chain_image.code.clone());

    // 2. Construct the chain InstanceCap. content_hash is a Stage 3
    //    placeholder (Stage 4 will canonicalize via state digest).
    let chain_instance = InstanceCap {
        image_hash_chain: image_hash,
        content_hash: [0u8; 32],
    };

    // 3. Register the chain in σ.vaults.
    let vault_id = state.counters.allocate_vault_id();
    state.vaults.insert(vault_id, chain_instance.into());

    // 4. Build the chain's root cnode (8-slot log2 = 256 slots).
    let mut cnode = InMemoryCNode::<Cap>::new(8).expect("256-slot cnode");

    // 5. Inject kernel-issued caps at well-known slots.
    cnode
        .set(
            abi::BARE_GAS_SLOT,
            Some(kernel_unit_cap(KernelImage::Gas, 0)),
        )
        .expect("BARE_GAS_SLOT in-range");
    cnode
        .set(
            abi::BARE_QUOTA_SLOT,
            Some(kernel_unit_cap(KernelImage::Quota, 0)),
        )
        .expect("BARE_QUOTA_SLOT in-range");
    cnode
        .set(
            abi::BARE_YIELD_CATCHER_SLOT,
            Some(kernel_stateless_cap(KernelImage::YieldCatcher)),
        )
        .expect("BARE_YIELD_CATCHER_SLOT in-range");
    cnode
        .set(
            abi::BARE_SET_GAS_METER_SLOT,
            Some(kernel_stateless_cap(KernelImage::SetGasMeter)),
        )
        .expect("BARE_SET_GAS_METER_SLOT in-range");
    cnode
        .set(
            abi::BARE_SET_STORAGE_QUOTA_SLOT,
            Some(kernel_stateless_cap(KernelImage::SetStorageQuota)),
        )
        .expect("BARE_SET_STORAGE_QUOTA_SLOT in-range");
    cnode
        .set(
            abi::BARE_MINT_GAS_SLOT,
            Some(kernel_stateless_cap(KernelImage::MintGas)),
        )
        .expect("BARE_MINT_GAS_SLOT in-range");
    cnode
        .set(
            abi::BARE_MINT_QUOTA_SLOT,
            Some(kernel_stateless_cap(KernelImage::MintQuota)),
        )
        .expect("BARE_MINT_QUOTA_SLOT in-range");
    cnode
        .set(
            abi::BARE_CREATE_YIELD_CATCHER_SLOT,
            Some(kernel_stateless_cap(KernelImage::CreateYieldCatcher)),
        )
        .expect("BARE_CREATE_YIELD_CATCHER_SLOT in-range");
    cnode
        .set(
            abi::BARE_HOST_OPEN_SLOT,
            Some(kernel_stateless_cap(KernelImage::HostOpen)),
        )
        .expect("BARE_HOST_OPEN_SLOT in-range");
    cnode
        .set(
            abi::BARE_HOST_SAVE_SLOT,
            Some(kernel_stateless_cap(KernelImage::HostSave)),
        )
        .expect("BARE_HOST_SAVE_SLOT in-range");

    let _ = (vault_id, code_id);

    Genesis {
        state,
        chain_instance,
        chain_cnode: Box::new(cnode),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jar_cap::image::Image;

    fn empty_chain_image() -> Image {
        Image {
            code: vec![10u8, 0],
            endpoints: core::array::from_fn(|_| None),
            memory_mappings: Vec::new(),
            gas_slots: vec![abi::BARE_GAS_SLOT],
            quota_slots: vec![abi::BARE_QUOTA_SLOT],
            pinned_slots: std::collections::BTreeMap::new(),
            yield_marker_slot: Some(abi::BARE_YIELD_CATCHER_SLOT),
        }
    }

    #[test]
    fn genesis_populates_known_slots() {
        let g = genesis(empty_chain_image());
        assert!(g.chain_cnode.get(abi::BARE_GAS_SLOT).unwrap().is_some());
        assert!(g.chain_cnode.get(abi::BARE_QUOTA_SLOT).unwrap().is_some());
        assert!(
            g.chain_cnode
                .get(abi::BARE_YIELD_CATCHER_SLOT)
                .unwrap()
                .is_some()
        );
        assert!(
            g.chain_cnode
                .get(abi::BARE_HOST_OPEN_SLOT)
                .unwrap()
                .is_some()
        );
        assert!(
            g.chain_cnode
                .get(abi::BARE_HOST_SAVE_SLOT)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn genesis_registers_chain_in_vaults() {
        let g = genesis(empty_chain_image());
        assert!(g.state.vaults.contains_key(&0));
        assert!(g.state.code_blobs.contains_key(&0));
    }

    #[test]
    fn chain_instance_image_hash_matches_content_hash() {
        let img = empty_chain_image();
        let g = genesis(img.clone());
        let expected = jar_cap::image::image_content_hash::<jar_cap::Blake2b256>(&img);
        assert_eq!(g.chain_instance.image_hash_chain, expected);
    }
}
