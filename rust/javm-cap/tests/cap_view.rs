//! Tests for `DataViewCap` — the copy-on-write overlay over an immutable
//! Backing DataCap. Property-based (no golden hashes).

use javm_cap::cap::data::PageResolution;
use javm_cap::{Cap, CapHashOrRef, DataCap, DataViewCap, PAGE_SIZE};

/// Build a 2-page backing whose page 0 is nonzero (`marker`) and page 1 zero.
fn backing_2pages(marker: &[u8]) -> DataCap {
    DataCap::from_bytes_sized(marker, 2 * PAGE_SIZE as u64)
}

/// `CapHashOrRef::Hash` identifying a backing DataCap in the cache.
fn backing_ref(b: &DataCap) -> CapHashOrRef {
    CapHashOrRef::Hash(Cap::Data(b.clone()).cap_hash())
}

fn view_over(b: &DataCap) -> DataViewCap {
    DataViewCap::new(backing_ref(b), b.content_len())
}

fn page_bytes(res: PageResolution<'_>) -> Vec<u8> {
    let mut out = vec![0u8; PAGE_SIZE];
    match res {
        PageResolution::Bytes(b) => {
            let n = b.len().min(PAGE_SIZE);
            out[..n].copy_from_slice(&b[..n]);
        }
        PageResolution::Zero => {}
        PageResolution::Missing(_) => panic!("unexpected Missing"),
    }
    out
}

#[test]
fn clean_view_effective_matches_backing() {
    let b = backing_2pages(b"hello-backing");
    let v = view_over(&b);
    for i in 0..2 {
        assert!(!v.is_dirty(i), "clean view page {i} must be clean");
        assert_eq!(
            page_bytes(v.effective_page_at(i, &b)),
            page_bytes(b.page_at(i as u64 * PAGE_SIZE as u64)),
            "clean view page {i} must defer to backing"
        );
    }
}

#[test]
fn write_page_shadows_backing() {
    let b = backing_2pages(b"hello-backing");
    let mut v = view_over(&b);
    let mut content = vec![0u8; PAGE_SIZE];
    content[..6].copy_from_slice(b"WRITE!");
    v.write_page(0, &content);

    assert!(v.is_dirty(0));
    assert!(!v.is_dirty(1));
    assert_eq!(&page_bytes(v.effective_page_at(0, &b))[..6], b"WRITE!");
    // Page 1 still defers to the (zero) backing.
    assert_eq!(page_bytes(v.effective_page_at(1, &b)), vec![0u8; PAGE_SIZE]);
}

#[test]
fn zero_write_shadows_nonzero_backing_and_is_binding() {
    // The binding edge case: a zero-write must shadow a nonzero backing page,
    // and must change the View's identity (provenance root).
    let b = backing_2pages(b"nonzero-page-0");
    let clean = view_over(&b);

    let mut shadowed = view_over(&b);
    shadowed.write_page(0, &[0u8; PAGE_SIZE]);

    // Effective content differs (clean sees the backing's nonzero page 0;
    // shadowed sees zero).
    assert_ne!(
        page_bytes(clean.effective_page_at(0, &b)),
        page_bytes(shadowed.effective_page_at(0, &b)),
    );
    assert_eq!(
        page_bytes(shadowed.effective_page_at(0, &b)),
        vec![0u8; PAGE_SIZE]
    );
    assert!(shadowed.is_dirty(0));

    // ...so their cap hashes must differ (binding: different effective content
    // ⇒ different root).
    assert_ne!(
        Cap::DataView(clean).cap_hash(),
        Cap::DataView(shadowed).cap_hash(),
    );
}

#[test]
fn view_root_is_order_independent() {
    let b = backing_2pages(b"order-test");
    let mut a_content = vec![0u8; PAGE_SIZE];
    a_content[0] = 0xAA;
    let mut b_content = vec![0u8; PAGE_SIZE];
    b_content[0] = 0xBB;

    let mut v1 = view_over(&b);
    v1.write_page(0, &a_content);
    v1.write_page(PAGE_SIZE as u64, &b_content);

    let mut v2 = view_over(&b);
    v2.write_page(PAGE_SIZE as u64, &b_content);
    v2.write_page(0, &a_content);

    assert_eq!(Cap::DataView(v1).cap_hash(), Cap::DataView(v2).cap_hash());
}

#[test]
fn view_root_differs_from_backing() {
    // A clean View and its backing are distinct cap identities (different union
    // selectors + container shapes), even though their effective content is
    // identical.
    let b = backing_2pages(b"distinct");
    let v = view_over(&b);
    assert_ne!(Cap::DataView(v).cap_hash(), Cap::Data(b).cap_hash());
}

#[test]
fn settle_clean_view_equals_backing() {
    let b = backing_2pages(b"settle-clean");
    let v = view_over(&b);
    let settled = v.settle(&b);
    // Settling a clean View reproduces the backing exactly.
    assert_eq!(Cap::Data(settled).cap_hash(), Cap::Data(b).cap_hash(),);
}

#[test]
fn settle_reflects_writes() {
    let b = backing_2pages(b"settle-writes");
    let mut v = view_over(&b);
    let mut content = vec![0u8; PAGE_SIZE];
    content[..4].copy_from_slice(b"NEW!");
    v.write_page(0, &content);
    let settled = v.settle(&b);

    // The settled DataCap holds the written page-0 content...
    let mut out = vec![0u8; PAGE_SIZE];
    settled.copy_into(0, &mut out);
    assert_eq!(&out[..4], b"NEW!");

    // ...and equals a from-scratch DataCap of the same effective content
    // (canonical: settle == rebuild).
    let mut effective = vec![0u8; 2 * PAGE_SIZE];
    effective[..4].copy_from_slice(b"NEW!");
    let rebuilt = DataCap::from_bytes_sized(&effective, 2 * PAGE_SIZE as u64);
    assert_eq!(Cap::Data(settled).cap_hash(), Cap::Data(rebuilt).cap_hash(),);
}

#[test]
fn settle_zero_write_canonicalizes() {
    // A zero-write is stored explicitly in the overlay (binding), but settling
    // folds it canonically: a zeroed page-0 over a zero backing settles to the
    // empty DataCap.
    let b = DataCap::from_bytes_sized(&[], PAGE_SIZE as u64); // all-zero backing
    let mut v = view_over(&b);
    v.write_page(0, &[0u8; PAGE_SIZE]);
    let settled = v.settle(&b);
    assert_eq!(Cap::Data(settled).cap_hash(), Cap::Data(b).cap_hash());
}
