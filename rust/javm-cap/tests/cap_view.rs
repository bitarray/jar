//! Tests for `DataCap`'s copy-on-write overlay (the unified backing+overlay
//! model — `DataViewCap == DataCap`). Property-based (no golden hashes).
//!
//! A clean cap (empty overlay) *is* its backing and is hashable; a cap with a
//! live overlay is the mutable working form and is **not** hashable until
//! [`DataCap::flush`] folds the overlay into a fresh backing.

use javm_cap::cap::data::PageResolution;
use javm_cap::{Cap, DataCap, PAGE_SIZE, PageSlot};

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

#[test]
fn place_shared_composes_and_shares_pages() {
    use std::sync::Arc;
    // A 4-page destination; place a 1-page RO source at page 0 and a 1-page RW
    // source at page 2 (byte offset 2*PAGE).
    let ro = DataCap::from_bytes_sized(b"read-only-data", PAGE_SIZE as u64);
    let rw = DataCap::from_bytes_sized(b"writable-data", PAGE_SIZE as u64);
    let mut mem = DataCap::from_bytes_sized(&[], 4 * PAGE_SIZE as u64);
    mem.place_shared(0, &ro);
    mem.place_shared(2 * PAGE_SIZE as u64, &rw);

    // Effective bytes match the sources at their offsets; the gap reads zero.
    assert_eq!(&page_at(&mem, 0)[..14], b"read-only-data");
    assert!(page_at(&mem, 1).iter().all(|&b| b == 0));
    assert_eq!(&page_at(&mem, 2)[..13], b"writable-data");

    // Page-sharing: `mem`'s placed page is the SAME Arc allocation as the
    // source's — a clone bumped the refcount rather than copying bytes.
    let (javm_cap::PageSlot::Loaded(ro_pg), javm_cap::PageSlot::Loaded(mem_pg)) =
        (ro.page_slot(0), mem.page_slot(0))
    else {
        panic!("expected Loaded pages");
    };
    assert!(
        Arc::ptr_eq(ro_pg, mem_pg),
        "place_shared must Arc-share the source page, not copy it",
    );
}

#[test]
fn place_shared_clamps_to_extent() {
    // A source larger than the destination's remaining extent is clamped.
    let src = DataCap::from_bytes_sized(&[0x55u8; 3 * PAGE_SIZE], 3 * PAGE_SIZE as u64);
    let mut mem = DataCap::from_bytes_sized(&[], 2 * PAGE_SIZE as u64);
    mem.place_shared(PAGE_SIZE as u64, &src); // base page 1; only page 1 fits
    assert_eq!(page_at(&mem, 0)[0], 0); // page 0 untouched
    assert_eq!(page_at(&mem, 1)[0], 0x55); // page 1 placed
    assert_eq!(mem.page_count(), 2); // extent unchanged
}

/// `DataCap::from_sparse_pages` (the Image-arena wire-decode constructor) must
/// produce a cap byte- and hash-identical to the contiguous `from_bytes_sized`
/// for the same logical content. This is the load-bearing invariant of the
/// arena format: a sparse blob (zero pages elided) decodes to the *same*
/// `DataCap` — and thus the same cap hash — the old inline form produced, so
/// the conformance oracle and both engines never fork. Pinned here (incl.
/// `size == 0`, a partial last page, and interior/trailing zero pages) so a
/// future change to either constructor cannot silently diverge.
#[test]
fn from_sparse_pages_matches_from_bytes_sized() {
    let p = PAGE_SIZE;
    // page0 nonzero, page1 ALL-ZERO (must be elided), page2 nonzero.
    let mut interior = vec![0x11u8; p];
    interior.extend(core::iter::repeat_n(0u8, p));
    interior.extend(core::iter::repeat_n(0x22u8, p));

    let cases: &[(Vec<u8>, u64)] = &[
        (vec![], 0),                        // degenerate: floors to one empty page
        (vec![], p as u64),                 // pure zero page
        (vec![0x7u8; 10], p as u64),        // content < size (partial page)
        (vec![0x7u8; p], p as u64),         // exactly one page
        (vec![0x9u8; 5000], 2 * p as u64),  // spans two pages, partial last
        (vec![0x3u8; 3 * p], 3 * p as u64), // three full pages
        (interior.clone(), 3 * p as u64),   // interior zero page (elided)
        (vec![0x4u8; p], 4 * p as u64),     // one page + trailing zero pages
    ];

    for (content, target_size) in cases {
        let inline = DataCap::from_bytes_sized(content, *target_size);
        // Reconstruct sparsely from inline's NON-ZERO pages only — exactly
        // what the wire decode does (omitted pages are the canonical zero).
        let pages: Vec<(u32, Vec<u8>)> = (0..inline.backing.page_count())
            .filter_map(|i| match inline.backing.page(i) {
                PageSlot::Loaded(pb) => Some((i as u32, pb.bytes.clone())),
                _ => None,
            })
            .collect();
        let inline_clen = inline.content_len();
        let sparse =
            DataCap::from_sparse_pages(inline_clen, pages.iter().map(|(i, b)| (*i, b.as_slice())));
        let sparse_clen = sparse.content_len();
        assert_eq!(
            Cap::Data(inline).cap_hash(),
            Cap::Data(sparse).cap_hash(),
            "sparse vs inline cap hash mismatch (content.len()={}, size={target_size})",
            content.len(),
        );
        assert_eq!(inline_clen, sparse_clen, "content_len mismatch");
    }

    // `size == 0` specifically: both floor to a single canonical empty page.
    assert_eq!(
        Cap::Data(DataCap::from_sparse_pages(
            0,
            core::iter::empty::<(u32, &[u8])>()
        ))
        .cap_hash(),
        Cap::Data(DataCap::from_bytes_sized(&[], 0)).cap_hash(),
    );

    // A `len`-trimmed page (trailing zeros within the page dropped) zero-pads
    // back to the identical page — so the wire trim is hash-invisible.
    let mut full_page = vec![0u8; p];
    full_page[..3].copy_from_slice(&[1, 2, 3]);
    assert_eq!(
        Cap::Data(DataCap::from_sparse_pages(
            p as u64,
            [(0u32, &full_page[..3])]
        ))
        .cap_hash(),
        Cap::Data(DataCap::from_sparse_pages(
            p as u64,
            [(0u32, full_page.as_slice())]
        ))
        .cap_hash(),
        "trimmed page must zero-pad to the same cap as the full page",
    );
}
