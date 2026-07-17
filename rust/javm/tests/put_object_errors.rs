//! `put_object` decode-failure paths: garbage bytes must never mint a
//! hash, on either backend.
//!
//! - Local: `JavmLocal::put_object` (the host-side mirror of the guest
//!   decode) surfaces a typed error through the generic
//!   `nub::Nub::put_object` surface.
//! - Hyperlight: the guest's put handler replies with the all-`0xFF`
//!   sentinel hash, which `MultiUseSandbox::put_object` converts to a
//!   typed error host-side; the raw RPC shows the sentinel itself.

use javm_cap::Cap;

/// Valid rkyv-encoded caps decode + hash identically through the
/// generic byte surface and the typed surface.
#[test]
fn local_put_object_roundtrip_matches_put_cap() {
    let cap = Cap::empty_cnode();

    let typed = javm::Nub::local().put_cap(&cap).expect("typed put_cap");

    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&cap).expect("rkyv encode");
    let generic = nub::Nub::<javm::Javm>::new_local()
        .put_object(bytes.as_slice())
        .expect("generic put_object");

    assert_eq!(typed, generic);
}

#[test]
fn local_put_object_garbage_errors() {
    let nub = nub::Nub::<javm::Javm>::new_local();
    let err = nub
        .put_object(b"garbage bytes, not an rkyv-archived Cap")
        .expect_err("garbage must not mint a hash");
    assert!(
        format!("{err:#}").contains("put_object"),
        "error should name the failing operation: {err:#}"
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn hyperlight_put_object_garbage_returns_sentinel() {
    let nub = javm::Nub::hyperlight().expect("hyperlight sandbox");
    let resp = nub
        .call_raw(
            nub_arch_x86_abi::FN_ID_NUB_PUT_CAP,
            b"garbage bytes, not an rkyv-archived Cap",
        )
        .expect("raw put_cap rpc");
    assert_eq!(
        resp,
        vec![0xFFu8; 32],
        "guest decode failure must reply with the all-0xFF sentinel hash"
    );
}
