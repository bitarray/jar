use jar_kernel::kernel_assist::SigmaKernelAssist;
use javm::kernel_assist::KernelAssist;
use javm_cap::CapHashOrRef;

#[test]
fn host_save_debits_quota_and_allocates_file_id() {
    let mut ka = SigmaKernelAssist::new();
    ka.seed_root_quota(1000);
    let file_id = ka.host_save(CapHashOrRef::Hash([0u8; 32]), 0, 32).unwrap();
    assert_eq!(file_id, 1); // first allocation
    assert_eq!(ka.storage_quota_get(0), 968);
    assert_eq!(ka.host_open(file_id), Some(CapHashOrRef::Hash([0u8; 32])));
}

#[test]
fn host_save_exhausted_quota_returns_none() {
    let mut ka = SigmaKernelAssist::new();
    // Quota 0 starts empty; any save should fail.
    assert!(ka.host_save(CapHashOrRef::Hash([0u8; 32]), 0, 1).is_none());
}

#[test]
fn reset_block_state_clears_ephemeral_tables() {
    let mut ka = SigmaKernelAssist::new();
    ka.seed_root_gas(1000);
    ka.seed_root_quota(2000);
    ka.reset_block_state();
    assert_eq!(ka.gas_meter_get(0), 0);
    assert_eq!(ka.storage_quota_get(0), 0);
}

#[test]
fn yield_catcher_round_trip() {
    let mut ka = SigmaKernelAssist::new();
    let yc = ka.yield_catcher_new();
    let marker = [0xAA; 32];
    ka.yield_catcher_add(yc, marker);
    assert_eq!(ka.yield_catcher_markers(yc), vec![marker]);
    ka.yield_catcher_remove(yc, marker);
    assert!(ka.yield_catcher_markers(yc).is_empty());
}
