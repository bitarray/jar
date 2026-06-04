//! IDT + GDT manipulation for the in-kernel JIT path.
//!
//! Hyperlight's guest-bin pre-installs a 256-entry IDT covering CPU
//! exceptions (vectors 0–30) plus stubs for everything else, and a
//! 5-entry GDT containing only null + kernel CS + kernel DS + TSS.
//! For the nub kernel we need a few things on top of this:
//!
//! * Vector `0x81` (ring-3 exit) to be invocable from ring 3 — and
//!   it must use IST=1 so the handler runs on the exception stack
//!   that Hyperlight already maintains for #PF / #GP / etc., rather
//!   than relying on TSS.RSP0 (A4).
//! * User code (DPL=3 code segment) and user data (DPL=3 data
//!   segment) selectors for the iretq frame that drops us into ring 3
//!   (A4).
//!
//! For both the IDT extensions, we copy Hyperlight's current IDT into
//! a heap-allocated buffer, patch the new entry, and `lidt` the new
//! buffer. The original IDT in `.data` stays untouched. The GDT
//! extension writes user selectors into the unused padding bytes that
//! Hyperlight reserves after its 5-entry GDT (the `PADDING_BEFORE_TSS`
//! region) and re-loads GDTR with a larger limit.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::mem::size_of;

/// Long-mode IDT entry (16 bytes; interrupt or trap gate).
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct IdtEntry {
    pub offset_lo: u16,
    pub selector: u16,
    /// IST in low 3 bits; rest reserved.
    pub ist: u8,
    /// type(4) | 0 | DPL(2) | P(1).
    pub type_attr: u8,
    pub offset_mid: u16,
    pub offset_hi: u32,
    pub _reserved: u32,
}

impl IdtEntry {
    /// Set the handler offset (full 64-bit address split across the
    /// three offset fields).
    pub fn set_offset(&mut self, va: u64) {
        self.offset_lo = (va & 0xFFFF) as u16;
        self.offset_mid = ((va >> 16) & 0xFFFF) as u16;
        self.offset_hi = (va >> 32) as u32;
    }
}

/// 10-byte IDT descriptor for `lidt` / `sidt`.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct IdtDescriptor {
    pub limit: u16,
    pub base: u64,
}

/// Number of entries in the IDT (256 vectors).
const IDT_ENTRIES: usize = 256;

/// Total IDT size in bytes.
const IDT_BYTES: usize = IDT_ENTRIES * size_of::<IdtEntry>();

/// Read the current IDTR into an `IdtDescriptor`.
///
/// # Safety
/// Issues `sidt`, which is harmless. Caller must ensure the returned
/// descriptor is consumed before any later change to IDTR.
pub unsafe fn sidt() -> IdtDescriptor {
    let mut descriptor = IdtDescriptor { limit: 0, base: 0 };
    // SAFETY: sidt writes 10 bytes to the supplied address.
    unsafe {
        core::arch::asm!("sidt [{0}]", in(reg) &mut descriptor, options(nostack, preserves_flags));
    }
    descriptor
}

/// Load a new IDT via `lidt`.
///
/// # Safety
/// `descriptor` must point at a valid IDT whose entries cover at
/// least vectors `0..=descriptor.limit/16`. The descriptor itself
/// must outlive the next `lidt` (the CPU re-reads it on every
/// interrupt-table lookup, so the *base* it points at must remain
/// valid for the IDT's lifetime).
pub unsafe fn lidt(descriptor: &IdtDescriptor) {
    // SAFETY: descriptor address is valid for the duration of the
    // asm; lidt reads 10 bytes.
    unsafe {
        core::arch::asm!("lidt [{0}]", in(reg) descriptor, options(nostack, preserves_flags));
    }
}

/// Patch IDT entry `vector` to install a new handler at DPL=3
/// (callable from ring 3) with the given IST index (0 = use TSS.RSP0,
/// 1..=7 = use TSS.istN). Returns a leak'd `Box` holding the new
/// IDT buffer — stored in a static so the lidt'd memory survives.
///
/// # Safety
/// `handler_va` must be a valid kernel-mode code entry point that
/// preserves CPU state and ends in `iretq` (or otherwise unwinds the
/// interrupt frame). The current IDT (whose base is reported by
/// `sidt`) must be readable for `IDT_BYTES` bytes.
pub unsafe fn install_dpl3_handler(vector: u8, handler_va: u64, ist: u8) -> &'static IdtDescriptor {
    // 1. Snapshot the existing IDT.
    // SAFETY: sidt is harmless; result is a copy.
    let old = unsafe { sidt() };

    // 2. Allocate a new IDT buffer, copy the existing entries.
    let mut new_idt: Vec<IdtEntry> = Vec::with_capacity(IDT_ENTRIES);
    for i in 0..IDT_ENTRIES {
        // SAFETY: caller asserted the old IDT covers IDT_ENTRIES
        // entries; reading is sequential.
        let entry: IdtEntry =
            unsafe { core::ptr::read_unaligned((old.base as *const IdtEntry).add(i)) };
        new_idt.push(entry);
    }

    // 3. Patch entry `vector`.
    let e = &mut new_idt[vector as usize];
    e.set_offset(handler_va);
    e.selector = 0x08; // kernel code segment (Hyperlight default)
    e.ist = ist & 0x7;
    e.type_attr = 0xEE; // interrupt gate, DPL=3, present

    // 4. Leak the Vec into a Box<[IdtEntry]> for stable storage.
    let leaked: &'static mut [IdtEntry] = Box::leak(new_idt.into_boxed_slice());

    // 5. Build a leak'd descriptor pointing at the new IDT and return it.
    let descriptor = IdtDescriptor {
        limit: (IDT_BYTES - 1) as u16,
        base: leaked.as_ptr() as u64,
    };
    let descriptor_box: &'static IdtDescriptor = Box::leak(Box::new(descriptor));

    // 6. lidt.
    // SAFETY: descriptor + IDT memory both have 'static lifetime.
    unsafe { lidt(descriptor_box) };

    descriptor_box
}

// === GDT: user-mode segment selectors ===================================

/// 8-byte GDT entry layout (matches `hyperlight_guest_bin`'s internal
/// `GdtEntry`).
///
/// In long mode, the base/limit fields are ignored for code/data
/// segments — only access/flags matter.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct GdtEntry {
    limit_low: u16,
    base_low: u16,
    base_middle: u8,
    access: u8,
    flags_limit: u8,
    base_high: u8,
}

impl GdtEntry {
    const fn new(access: u8, flags: u8) -> Self {
        Self {
            limit_low: 0,
            base_low: 0,
            base_middle: 0,
            access,
            flags_limit: (flags & 0x0f) << 4,
            base_high: 0,
        }
    }
}

/// 10-byte GDT descriptor for `lgdt` / `sgdt`.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct GdtDescriptor {
    pub limit: u16,
    pub base: u64,
}

/// Ring-3 code selector (`USER_CS | RPL=3`).
pub const USER_CODE_SEL: u16 = 0x28 | 3;
/// Ring-3 data/stack selector (`USER_DS | RPL=3`).
pub const USER_DATA_SEL: u16 = 0x30 | 3;

/// Read the current GDTR.
///
/// # Safety
/// Issues `sgdt`, which is harmless.
pub unsafe fn sgdt() -> GdtDescriptor {
    let mut descriptor = GdtDescriptor { limit: 0, base: 0 };
    // SAFETY: sgdt writes 10 bytes to the supplied address.
    unsafe {
        core::arch::asm!(
            "sgdt [{0}]",
            in(reg) &mut descriptor,
            options(nostack, preserves_flags),
        );
    }
    descriptor
}

/// Load a new GDT via `lgdt`.
///
/// # Safety
/// `descriptor` must point at a valid GDT whose base outlives the
/// next `lgdt`. The current CS/DS/SS selectors must still describe
/// valid entries within the new GDT (we don't reload selectors here).
pub unsafe fn lgdt(descriptor: &GdtDescriptor) {
    // SAFETY: descriptor is valid; lgdt reads 10 bytes.
    unsafe {
        core::arch::asm!(
            "lgdt [{0}]",
            in(reg) descriptor,
            options(nostack, preserves_flags),
        );
    }
}

/// Append `USER_CS` (selector 0x28, DPL=3 code) and `USER_DS`
/// (selector 0x30, DPL=3 data) to the existing Hyperlight GDT, then
/// reload GDTR with the larger limit. Returns the user-CS selector.
///
/// Hyperlight reserves 24 bytes of padding after its 5-entry GDT
/// (`PADDING_BEFORE_TSS`) before the TSS proper, so writing two more
/// 8-byte entries at offsets 0x28 / 0x30 is safe and doesn't overlap
/// the TSS that begins at offset 64 within `ProcCtrl`.
///
/// Calling this multiple times is idempotent; the user entries are
/// rewritten in place.
///
/// # Safety
/// Caller must not be running with a DPL>0 segment loaded — we only
/// extend the GDT, we don't reload segment registers. The patched
/// GDT bytes must remain mapped + writable (they live at
/// `PROC_CONTROL_GVA`, which is identity- pinned by Hyperlight).
pub unsafe fn install_user_segments() {
    // SAFETY: sgdt is harmless.
    let gdtr = unsafe { sgdt() };
    let base = gdtr.base;

    // User code: present, DPL=3, S=1 (code), code/exec/readable.
    let user_code = GdtEntry::new(0xFA, 0xA);
    // User data: present, DPL=3, S=1 (data), data/RW. D/B=1, granularity=1.
    let user_data = GdtEntry::new(0xF2, 0xC);

    // SAFETY: GDT region has at least 0x40 - 0x28 = 24 bytes of
    // padding after the 5-entry default. Writing 16 bytes at offset
    // 0x28 fits comfortably.
    unsafe {
        core::ptr::write_unaligned((base + 0x28) as *mut GdtEntry, user_code);
        core::ptr::write_unaligned((base + 0x30) as *mut GdtEntry, user_data);
    }

    // New limit = 7 entries (null, kernel_code, kernel_data, tss_lo,
    // tss_hi, user_code, user_data) × 8 - 1 = 0x37.
    let new_gdtr = GdtDescriptor { limit: 0x37, base };
    // SAFETY: new_gdtr is on the kernel stack and consumed before return.
    unsafe { lgdt(&new_gdtr) };
}
