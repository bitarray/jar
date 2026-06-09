# Image wire format — the payload arena

Status: **implemented** 2026-06-08, branch `image-arena-format`.

The `Image` is the smallest unit of program specification: code, endpoints,
memory layout, and the data that backs each memory region. It is the
untrusted SSZ wire form that the kernel "deblobs" into an
[`ImageCap`](https://github.com/jarchain/jar/blob/master/rust/javm-cap/src/cap/image.rs) and a set of
content-addressed [`DataCap`](https://github.com/jarchain/jar/blob/master/rust/javm-cap/src/cap/data.rs)s.

This doc describes the **payload-arena** encoding adopted to stop the wire
form from serializing zero bytes it never needed to carry.

Source of truth: [`rust/javm-cap/src/image.rs`](https://github.com/jarchain/jar/blob/master/rust/javm-cap/src/image.rs).

## The problem: inlined zero pages

The previous wire form stored each data region as one contiguous buffer:

```rust
struct Image { code: Vec<u8>, /* … */ pinned_slots, initial_slots }
enum  PinnedCap   { Data { content: Vec<u8>, size: u64 }, Image { content_hash } }
struct InitialDataCap { content: Vec<u8>, size: u64 }
```

`content` was the full byte image of the region, zeros and all, so two
distinct sources of zeros got baked verbatim into every blob:

1. **Leading / interior gaps.** The transpiler's ELF loader lays each
   writable region's bytes into a buffer spanning `[rw_base, rw_max)`,
   where `rw_base = min(rw_pvm_base, rw_min)`. When the guest links its
   data *above* `rw_pvm_base` (the common case), the entire
   `[rw_pvm_base, rw_min)` gap is zero-filled into `content`. Example:
   `sub_vm_recurse` has **16 bytes** of real writable data at vaddr
   `0x121d0` but `rw_pvm_base = 0x4000`, so a **57,808-byte zero gap**
   was inlined — a 58 KB blob for 16 bytes of data.
2. **Trailing `.bss`.** NOBITS sections contribute their size (extending
   `rw_max`) but no file bytes; the contiguous buffer zero-filled them.
   `fri_fold_tree` carried **262 KB** of trailing `.bss` zeros;
   `poly_eval` **65 KB**.

Across the 12 bench Images the `initial_slots` field was 60–99.8 % of the
blob, almost all of it zeros. (Measured with
[`rust/javm-bench/examples/blob_anatomy.rs`](https://github.com/jarchain/jar/blob/master/rust/javm-bench/examples/blob_anatomy.rs).)

The irony: the *runtime* `DataCap` never materializes these zeros — its
backing `PageSlab` stores an all-zero page as the canonical
`PageSlot::Empty` (no allocation, hashes to `[0u8; 32]`). Only the wire
form paid for them.

## The format: one arena + page-granular descriptors

All payload bytes move into a single trailing byte pool, `arena`. Every
byte-carrying field becomes a small *descriptor* indexing tightly packed
windows of it:

```rust
struct Image {
    code: CodeRef,                          // was Vec<u8>
    endpoints: BTreeMap<Key, EndpointDef>,  // unchanged (structural)
    memory_mappings: Vec<MemoryMapping>,    // unchanged
    pinned_slots: BTreeMap<Key, PinnedCap>,
    initial_slots: BTreeMap<Key, DataDesc>, // InitialDataCap = DataDesc alias
    yield_receiver_slot: Option<Key>,       // unchanged
    gas_slots: Vec<Key>,                    // unchanged
    quota_slots: Vec<Key>,                  // unchanged
    arena: Vec<u8>,                         // NEW — page-granular payload pool
}

struct CodeRef     { arena_off: u32, len: u32 }       // contiguous code slice
struct ArenaPageRef { page_index: u32, arena_off: u32, len: u32 } // a page's non-zero prefix
struct DataDesc    { size: u64, pages: Vec<ArenaPageRef> }
enum   PinnedCap   { Data { desc: DataDesc }, Image { content_hash: [u8; 32] } }
```

- **`CodeRef`** names the contiguous code region: `arena[arena_off ..
  arena_off + len]`. `len` is the *exact* (non-page-rounded) code length —
  the recompiler iterates exactly `len` bytes — while the arena window
  itself is page-rounded. `CodeRef::default()` (`{0, 0}`) is a codeless
  image.
- **`DataDesc`** is **page-granular sparse** content. `size` is the full
  logical extent (a `PAGE_SIZE` multiple); `pages` names *only the
  non-zero pages*. Logical page `pr.page_index` is backed by
  `arena[pr.arena_off .. pr.arena_off + pr.len]` — only the page's non-zero
  *prefix* is stored (`len` ∈ `1..=PAGE_SIZE`; trailing zeros within the page
  are dropped and zero-padded back at decode). Any page **not** named is the
  canonical zero page. A pure-zero region (stack, heap, `.bss`) is
  `DataDesc { size, pages: [] }` — carrying no bytes at all. Windows are
  packed tightly (no `arena_off` alignment).

Structural fields stay inline and tiny (36–120 B total), so the header
decodes without touching the payload — preserving the
structure-eager / semantics-lazy validation model. `arena` is the last
field; in SSZ container order the cheap structure precedes the bulk.

## Zero elision is the whole point

The leading gap, interior gaps, and trailing `.bss` are all just *unnamed
pages*. The producer never writes them to the arena, and the decoder
leaves them `PageSlot::Empty`. No special case for "leading" vs "trailing"
zeros — page omission handles every shape uniformly, which is why this
beats a trailing-only trim. Zeros *within* a stored page are dropped too:
only the prefix up to the last non-zero byte (`ArenaPageRef::len`) is
written, so a sub-page-dense region (a small `.data`, a partial last page)
costs `len` bytes, not a full `PAGE_SIZE`.

## Sharing (dedup)

Two `ArenaPageRef`s — in the same or different data caps — may point at the
**same** `arena_off`. The producer deduplicates byte-identical pages
(keyed by page-content hash) so a repeated page costs one arena slot.
Sharing is purely a producer-side size optimization and is **invisible to
identity** (see below); the decoder reads the window once per reference.

## Identity invariants

Two distinct hashes are in play, and the split is load-bearing:

- **`DataCap` identity** (cache key, bound into the Image's
  `pinned_hashes`/`initial_hashes`) is `merkleize{ size, pages_root }`,
  where each `PageSlot::Loaded` page hashes to its content digest and each
  `Empty` to `[0u8; 32]`
  ([`data.rs`](https://github.com/jarchain/jar/blob/master/rust/javm-cap/src/cap/data.rs)). It is a function
  of **logical `{size, page_index → content}` only** — it never sees
  `arena_off`, page ordering, or sharing. Therefore eliding zero pages and
  deduplicating identical pages **cannot change any `DataCap` hash**, and
  the decoded cap is bit-identical to the old contiguous build. Execution,
  gas, and consensus are unaffected.
- **`image_content_hash`** (the chain identity) is the SSZ
  `hash_tree_root` of the whole wire `Image`, so it legitimately depends on
  the arena *contents*. To keep it deterministic for equal *logical*
  images, the arena is packed by a single **canonical** algorithm (below):
  equal logical content → equal arena → equal hash, regardless of builder
  call order.

## Producer: `ImageBuilder` (one canonical packer)

[`ImageBuilder`](https://github.com/jarchain/jar/blob/master/rust/javm-cap/src/image.rs) is the single place
that packs an arena. Callers hand it logical content exactly as before the
redesign — contiguous `content: Vec<u8>` + `size` per data slot, plus the
code bytes — and `build()`:

1. walks the slots in `Key` order (pinned then initial) and, for each,
   reuses `DataCap::from_bytes_sized(content, size)` to get the *exact*
   canonical page decomposition (all-zero pages elided, the `size`
   formula), then appends each non-zero page's `PAGE_SIZE` slab to the
   arena, deduplicating by content hash.
2. appends the code contiguously after the data pages at its exact
   byte length (not page-rounded).

Because packing is a pure function of the (sorted) logical content, the
transpiler and any test builder emit byte-identical arenas for the same
image. The transpiler ([`linker.rs`](https://github.com/jarchain/jar/blob/master/rust/javm-transpiler/src/linker.rs))
routes through this builder, so the `[rw_pvm_base, rw_min)` gap and
trailing `.bss` simply never reach the arena. Region geometry
(`MemoryMapping.start`/`size`, `ProgramLayout`, `stack_top`, the
`MAX_CODE_SIZE`/4 GiB bounds) is unchanged — each region's `size` is still
`page_count * PAGE_SIZE`.

## Consumer: `DataDesc::to_data_cap` (one materialization point)

[`DataDesc::to_data_cap(&arena)`](https://github.com/jarchain/jar/blob/master/rust/javm-cap/src/image.rs) is
the single decode: it calls `DataCap::from_sparse_pages(size, …)`, placing
each named page's arena window at its `page_index` and leaving the rest
`Empty`. The result is guaranteed byte- and hash-identical to
`DataCap::from_bytes_sized(equivalent_contiguous_content, size)` — the two
constructors share the canonical fold (`put_page_idx`).
`Image::instance_mem_backing()` folds the same per-page windows into the
dense Instance memory. The kernel-side recompiler path
(`compose_instance_mem`) is downstream of the published `DataCap` and needs
no change.

> Note: `PageBytes::from_content` copies each arena window into a fresh
> `PAGE_SIZE`-aligned slab (the recompiler direct-maps slab physical
> addresses into ring-3 page tables), so the deblob copies every page
> regardless of arena layout. The arena is therefore **tightly packed**
> (`len`-sized, unaligned windows) to minimize wire size. This deliberately
> trades away the page-aligned-arena option for a future zero-copy mmap
> (which would have needed full, aligned page windows) — with no current
> loss, since decode copies into an aligned slab today either way.

## Validation (eager, at deblob)

The wire decode (`from_ssz_bytes`) does not bounds-check the arena — like
source-path depth, structural soundness is validated eagerly in
[`image_cap`](https://github.com/jarchain/jar/blob/master/rust/javm-cap/src/cap/image.rs), failing loud
(`ImageConvertError`) on untrusted input rather than panicking later:

- `CodeRef`: `arena_off + len ≤ arena.len()`, and `len ≤ MAX_CODE_SIZE`.
- every `DataDesc` (`DataDesc::validate`): `size` is a `PAGE_SIZE` multiple;
  each `ArenaPageRef` has `1 <= len <= PAGE_SIZE`, its byte window
  `arena_off + len <= arena.len()` is in bounds, and `page_index < size /
  PAGE_SIZE`; pages are strictly ascending by `page_index` (canonical, no
  duplicates).

The materialization paths (`instance_mem_backing`, `DataDesc::to_data_cap`)
slice the arena by raw `arena_off` and therefore **assume a deblob-validated
Image** — a documented precondition. Producers (`ImageBuilder`) always emit
in-bounds page-refs, and `image_cap` rejects malformed ones loudly before any
slice. A residual hardening (follow-up, not a consensus concern, surfaced by
the adversarial review) is to also bind each slot's `DataDesc.size` /
`page_index` to its `MemoryMapping` extent at deblob, and to guard the
pre-existing `mem_extent` `u32` sum against overflow.

## Results

(Blob sizes in bytes; measured with `blob_anatomy`.)

Total `.pvm` blob size across the 12 bench Images, before (inline content)
vs after (arena: data pages trailing-zero-trimmed and tightly packed, code
stored last at exact length):

| workload | before (B) | after (B) | Δ |
|---|---:|---:|---:|
| sub_vm_recurse | 58,118 | 781 | −99% |
| fri_fold_tree | 276,989 | 6,668 | −98% |
| poly_eval | 72,301 | 2,684 | −96% |
| prime_sieve | 158,346 | 11,198 | −93% |
| sub_vm_data_recurse | 75,069 | 13,856 | −82% |
| goldilocks_mul | 5,485 | 1,412 | −74% |
| poseidon2_perm | 13,287 | 5,118 | −61% |
| mini_verifier | 15,517 | 7,348 | −53% |
| ecrecover | 198,631 | 100,311 | −49% |
| ed25519 | 91,621 | 46,587 | −49% |
| keccak | 9,255 | 5,182 | −44% |
| blake2b | 19,223 | 11,054 | −43% |
| **total** | **993,842** | **212,199** | **−79%** |

Every workload shrinks. The compute-heavy crypto blobs (`ecrecover`,
`ed25519`) are now dominated by their irreducible **code** (96 KB, 41 KB) —
their data zeros are gone, but the code is real. (An earlier full-page
variant regressed the two small dense blobs — keccak +12 %, goldilocks
+57 % — because a sub-page region rounded up to a full `PAGE_SIZE` window;
the per-page `len` trim turned those into −44 % / −74 %.)

> **Code last, data trimmed.** Code is appended to the arena *after* the data
> pages at its exact (non-page-rounded) length; each data page stores only
> its non-zero prefix (`ArenaPageRef::len`), packed tightly. Both exploit the
> fact that the deblob re-copies every page/code into a fresh aligned slab
> anyway — so the wire form owes nothing to page alignment.

## Scope

This is a **rust-kernel-local** wire-format change: the Lean `Jar.*` spec
has no `Image` of this shape, there is no Genesis `CommitIndex` coupling,
no JSON conformance vectors mirror it, and no golden blobs are checked in
(the bench blobs are regenerated by `build.rs`). The runtime `DataCap`,
its hash, and all execution are byte-for-byte unchanged; only the wire
encoding shrinks.
