//! Throwaway diagnostic: decode each bench Image blob and break down where
//! its bytes go, focusing on the page-granular arena (named vs elided pages).
//! Run: cargo run -p javm-bench --release --example blob_anatomy

use javm_cap::PAGE_SIZE;
use javm_cap::image::{DataDesc, Image, PinnedCap};
use ssz::{Decode, Encode};

/// Stats on one data slot's page-granular [`DataDesc`].
struct Anat {
    /// Logical extent in bytes (`size`).
    size: u64,
    /// Logical page count (`size / PAGE_SIZE`).
    logical_pages: u64,
    /// Non-zero pages actually stored in the arena (`pages.len()`).
    named_pages: usize,
    /// Pages elided because they are all-zero (`logical - named`).
    elided_pages: u64,
    /// Bytes actually stored in the arena (sum of each named page's `len`).
    stored_bytes: usize,
}

fn anat(desc: &DataDesc) -> Anat {
    let logical_pages = desc.page_count();
    let named_pages = desc.pages.len();
    let elided_pages = logical_pages.saturating_sub(named_pages as u64);
    let stored_bytes = desc.pages.iter().map(|pr| pr.len as usize).sum();
    Anat {
        size: desc.size,
        logical_pages,
        named_pages,
        elided_pages,
        stored_bytes,
    }
}

fn report(label: &str, blob: &[u8]) {
    let img = Image::from_ssz_bytes(blob).expect("decode Image");
    println!("\n== {label} ==  full blob = {} B", blob.len());
    println!(
        "   arena = {} B (tightly packed); code = {} B",
        img.arena.len(),
        img.code.len,
    );

    let mut elided_pages = 0u64;
    let mut named_pages = 0usize;

    let print_slot = |kind: &str, k: &javm_cap::Key, a: &Anat| {
        println!(
            "   {kind:<7} slot={:>3?} size={:>7} logical_pages={:>5} named={:>5} elided={:>5} stored={:>6}B",
            k, a.size, a.logical_pages, a.named_pages, a.elided_pages, a.stored_bytes,
        );
    };

    for (k, p) in &img.pinned_slots {
        if let PinnedCap::Data { desc } = p {
            let a = anat(desc);
            print_slot("pinned", k, &a);
            elided_pages += a.elided_pages;
            named_pages += a.named_pages;
        }
    }
    for (k, desc) in &img.initial_slots {
        let a = anat(desc);
        print_slot("initial", k, &a);
        elided_pages += a.elided_pages;
        named_pages += a.named_pages;
    }
    println!(
        "   >>> {} named pages stored, {} all-zero pages elided ({} B not inlined)",
        named_pages,
        elided_pages,
        elided_pages * PAGE_SIZE as u64,
    );
    // sanity: serialized size of just initial_slots / pinned_slots / arena
    println!(
        "   (initial_slots ssz = {} B, pinned_slots ssz = {} B, arena ssz = {} B)",
        img.initial_slots.as_ssz_bytes().len(),
        img.pinned_slots.as_ssz_bytes().len(),
        img.arena.as_ssz_bytes().len(),
    );
}

fn main() {
    report("prime_sieve", include_bytes!(env!("PRIME_SIEVE_BLOB")));
    report("keccak", include_bytes!(env!("KECCAK_BLOB")));
    report("blake2b", include_bytes!(env!("BLAKE2B_BLOB")));
    report(
        "goldilocks_mul",
        include_bytes!(env!("GOLDILOCKS_MUL_BLOB")),
    );
    report(
        "sub_vm_recurse",
        include_bytes!(env!("SUB_VM_RECURSE_BLOB")),
    );
    report(
        "sub_vm_data_recurse",
        include_bytes!(env!("SUB_VM_DATA_RECURSE_BLOB")),
    );
    report("ed25519", include_bytes!(env!("ED25519_BLOB")));
    report("ecrecover", include_bytes!(env!("ECRECOVER_BLOB")));
    report(
        "poseidon2_perm",
        include_bytes!(env!("POSEIDON2_PERM_BLOB")),
    );
    report("mini_verifier", include_bytes!(env!("MINI_VERIFIER_BLOB")));
    report("poly_eval", include_bytes!(env!("POLY_EVAL_BLOB")));
    report("fri_fold_tree", include_bytes!(env!("FRI_FOLD_TREE_BLOB")));
}
