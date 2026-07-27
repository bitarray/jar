//! The guest-side program store.
//!
//! Publication is permanent — see [`GuestStore::put_object`]. This map
//! is only ever inserted into, and holds an `Arc` per program so a live
//! frame keeps its program (and the physical pages its page table
//! points at) alive regardless of what else happens to the store.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use nub_arch_x86::jit_cache::{CompiledImage, JitSlot};
use nub_arch_x86::page_alloc::PageBuf;
use nub_arch_x86::personality::GuestStore;
use nub_arch_x86::personality::ObjHash;
use nub_flat::hash::content_hash;
use nub_program::ProgramBlob;
use spin::Mutex as SpinMutex;

use crate::mem::Page;

/// Diagnostic error codes. The RPC wrapper discards them and ships the
/// all-`0xFF` sentinel, so they exist only for debugging.
pub const ERR_DECODE: u32 = 1;

/// A published program: the decoded blob, a page-aligned copy of its
/// code, and its compiled-JIT slot.
pub struct PublishedProgram {
    pub blob: ProgramBlob,
    /// The program's initial data image, page-aligned, built once here
    /// and shared read-only by every frame. Per-frame isolation is the
    /// CoW overlay's job — see [`crate::mem::FlatMem`].
    data: Vec<Box<Page>>,
    /// Page-aligned, page-rounded copy of `blob.code`.
    ///
    /// The frame's page table maps the code region directly at its
    /// physical address, and a PTE can only point at a page boundary —
    /// so the bytes cannot simply be borrowed out of the `Vec` inside
    /// the blob. The zero-padded tail is what the region's last page
    /// reads as, matching what the interpreter sees.
    code: PageBuf,
    /// Compiled artifact for this program, built on first entry.
    jit: SpinMutex<Option<Box<CompiledImage>>>,
}

/// SAFETY: `blob` and `code` are immutable once published — nothing
/// mutates them again, so sharing them across execution lanes is a
/// plain read. The one mutable field, `jit`, is behind a spin mutex.
/// The raw pointers inside `PageBuf`/`CompiledImage` are what make the
/// auto-impls unavailable; they are owning pointers to heap pages that
/// live as long as the program, not borrows.
unsafe impl Send for PublishedProgram {}
/// SAFETY: same synchronization and immutability invariant as `Send`.
unsafe impl Sync for PublishedProgram {}

impl PublishedProgram {
    fn new(blob: ProgramBlob) -> Option<Self> {
        let mut code = PageBuf::new(blob.code.len().max(1))?;
        code.as_mut_slice()[..blob.code.len()].copy_from_slice(&blob.code);
        let data = Page::split(&blob.memory_image());
        Some(PublishedProgram {
            blob,
            data,
            code,
            jit: SpinMutex::new(None),
        })
    }

    /// The shared, immutable initial data image.
    pub fn data_pages(&self) -> &[Box<Page>] {
        &self.data
    }

    /// The page-aligned code region and its physical address.
    pub fn code(&self) -> (&[u8], u64) {
        // The slice is page-rounded, matching what the PTE maps.
        let len = self.code.size() as usize;
        let bytes = unsafe { core::slice::from_raw_parts(self.code.kva() as *const u8, len) };
        (bytes, self.code.pa())
    }
}

/// The JIT cache for one program.
///
/// The [`JitSlot`] contract requires the artifact to stay put while any
/// `FrameRuntime` borrows into it. That holds here because a program is
/// only ever inserted, never evicted, and the frame holds an `Arc`.
impl JitSlot for PublishedProgram {
    fn with_image<R>(
        &self,
        compile: impl FnOnce() -> CompiledImage,
        f: impl FnOnce(&mut CompiledImage) -> R,
    ) -> R {
        let mut slot = self.jit.lock();
        if slot.is_none() {
            *slot = Some(Box::new(compile()));
        }
        f(slot.as_mut().expect("installed above"))
    }
}

/// Content-hash → program.
pub struct FlatStore {
    programs: SpinMutex<BTreeMap<ObjHash, Arc<PublishedProgram>>>,
}

pub static FLAT_STORE: FlatStore = FlatStore {
    programs: SpinMutex::new(BTreeMap::new()),
};

impl FlatStore {
    pub fn get(&self, hash: &ObjHash) -> Option<Arc<PublishedProgram>> {
        self.programs.lock().get(hash).cloned()
    }
}

impl GuestStore for FlatStore {
    fn put_object(&self, bytes: &[u8]) -> Result<ObjHash, u32> {
        let blob = ProgramBlob::from_bytes(bytes).map_err(|_| ERR_DECODE)?;
        let hash = content_hash(bytes);
        let program = PublishedProgram::new(blob).ok_or(ERR_DECODE)?;
        self.programs.lock().insert(hash, Arc::new(program));
        Ok(hash)
    }

    /// Nothing derived to reclaim: a flat invocation leaves no
    /// per-instance state behind.
    fn sweep(&self) {}

    /// Drop every compiled artifact. Bench-only — the next entry pays a
    /// full recompile. Safe between invocations, when no `FrameRuntime`
    /// is live to borrow into a slot.
    fn evict_jit(&self) {
        for program in self.programs.lock().values() {
            *program.jit.lock() = None;
        }
    }
}
