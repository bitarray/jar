//! Legacy identity-only Cap shape, kept temporarily while jar-kernel
//! and javm migrate to the content-bearing `javm_cap::Cap<A>`.
//!
//! Everything in this module is scheduled for deletion in Commit 4 of
//! the "consolidate to a single Cap type" plan. Do not add new callers.

pub mod cap;
pub mod cnode;
pub mod ops;

pub use cap::{
    CNodeCap, Cap, CapHash, CapKind, DataCap, ImageCap, InstanceCap, TypeCap,
};
pub use cnode::{CNodeBackend, CnodeHash, InMemoryCNode, SlotHasher};
pub use ops::{mgmt_cnode_mint, mgmt_cnode_swap, mgmt_copy, mgmt_drop, mgmt_move};
