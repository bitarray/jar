//! Tests for `DataCap`'s copy-on-write overlay (the unified backing+overlay
//! model — `DataViewCap == DataCap`). Property-based (no golden hashes).
//!
//! A clean cap (empty overlay) *is* its backing and is hashable; a cap with a
//! live overlay is the mutable working form and is **not** hashable until
//! [`DataCap::flush`] folds the overlay into a fresh backing.

use javm_cap::cap::data::PageResolution;
use javm_cap::{Cap, DataCap, PAGE_SIZE};

/// Build a 2-page cap whose page 0 is nonzero (`marker`) and page 1 zero.
fn cap_2pages(marker: &[u8]) -> DataCap {
    DataCap::from_bytes_sized(marker, 2 * PAGE_SIZE as u64)
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

fn page_at(cap: &DataCap, i: usize) -> Vec<u8> {
    page_bytes(cap.page_at(i as u64 * PAGE_SIZE as u64))
}

#[test]
fn clean_cap_has_no_dirty_pages() {
    let c = cap_2pages(b"hello-backing");
    for i in 0..2 {
        assert!(!c.is_dirty(i), "clean cap page {i} must be clean");
    }
}

#[test]
fn write_page_shadows_backing() {
    let mut c = cap_2pages(b"hello-backing");
    let mut content = vec![0u8; PAGE_SIZE];
    content[..6].copy_from_slice(b"WRITE!");
    c.write_page(0, &content);

    assert!(c.is_dirty(0));
    assert!(!c.is_dirty(1));
    assert_eq!(&page_at(&c, 0)[..6], b"WRITE!");
    // Page 1 still defers to the (zero) backing.
    assert_eq!(page_at(&c, 1), vec![0u8; PAGE_SIZE]);
}

#[test]
fn zero_write_shadows_nonzero_backing_and_is_binding() {
    // A zero-write must shadow a nonzero backing page, and must change the cap's
    // (flushed) identity.
    let clean = cap_2pages(b"nonzero-page-0");

    let mut shadowed = cap_2pages(b"nonzero-page-0");
    shadowed.write_page(0, &[0u8; PAGE_SIZE]);

    // Effective content differs (clean keeps the nonzero page 0; shadowed zero).
    assert_ne!(page_at(&clean, 0), page_at(&shadowed, 0));
    assert_eq!(page_at(&shadowed, 0), vec![0u8; PAGE_SIZE]);
    assert!(shadowed.is_dirty(0));

    // ...so their flushed cap hashes differ (binding: different effective
    // content ⇒ different content root).
    assert_ne!(
        Cap::Data(clean.flush()).cap_hash(),
        Cap::Data(shadowed.flush()).cap_hash(),
    );
}

#[test]
fn flush_is_order_independent() {
    let mut a_content = vec![0u8; PAGE_SIZE];
    a_content[0] = 0xAA;
    let mut b_content = vec![0u8; PAGE_SIZE];
    b_content[0] = 0xBB;

    let mut v1 = cap_2pages(b"order-test");
    v1.write_page(0, &a_content);
    v1.write_page(PAGE_SIZE as u64, &b_content);

    let mut v2 = cap_2pages(b"order-test");
    v2.write_page(PAGE_SIZE as u64, &b_content);
    v2.write_page(0, &a_content);

    assert_eq!(
        Cap::Data(v1.flush()).cap_hash(),
        Cap::Data(v2.flush()).cap_hash(),
    );
}

#[test]
fn flush_clean_equals_self() {
    let c = cap_2pages(b"flush-clean");
    // Flushing a clean cap reproduces it exactly.
    assert_eq!(
        Cap::Data(c.flush()).cap_hash(),
        Cap::Data(c.clone()).cap_hash(),
    );
}

#[test]
fn flush_reflects_writes() {
    let mut c = cap_2pages(b"settle-writes");
    let mut content = vec![0u8; PAGE_SIZE];
    content[..4].copy_from_slice(b"NEW!");
    c.write_page(0, &content);
    let settled = c.flush();

    // The flushed DataCap holds the written page-0 content...
    let mut out = vec![0u8; PAGE_SIZE];
    settled.copy_into(0, &mut out);
    assert_eq!(&out[..4], b"NEW!");

    // ...and equals a from-scratch DataCap of the same effective content
    // (canonical: flush == rebuild).
    let mut effective = vec![0u8; 2 * PAGE_SIZE];
    effective[..4].copy_from_slice(b"NEW!");
    let rebuilt = DataCap::from_bytes_sized(&effective, 2 * PAGE_SIZE as u64);
    assert_eq!(Cap::Data(settled).cap_hash(), Cap::Data(rebuilt).cap_hash(),);
}

#[test]
fn flush_zero_write_canonicalizes() {
    // A zero-write is stored explicitly in the overlay (binding), but flushing
    // folds it canonically: a zeroed page-0 over a zero backing flushes to the
    // empty-content DataCap.
    let b = DataCap::from_bytes_sized(&[], PAGE_SIZE as u64); // all-zero backing
    let mut v = DataCap::from_bytes_sized(&[], PAGE_SIZE as u64);
    v.write_page(0, &[0u8; PAGE_SIZE]);
    assert_eq!(Cap::Data(v.flush()).cap_hash(), Cap::Data(b).cap_hash(),);
}

#[test]
fn overlay_bearing_cap_is_not_hashable() {
    // Hashing a cap with a live overlay is a usage error (must flush first).
    let mut c = cap_2pages(b"unflushed");
    c.write_page(0, &[0xEE; PAGE_SIZE]);
    let r = std::panic::catch_unwind(|| Cap::Data(c).cap_hash());
    assert!(r.is_err(), "overlay-bearing cap must not be hashable");
}
