//! IDT manipulation for the in-kernel JIT path.
//!
//! Hyperlight's guest-bin pre-installs a 256-entry IDT covering CPU
//! exceptions (vectors 0–30) plus stubs for everything else. For the
//! nub kernel we need vector `0x80` (the PVM ecall trampoline) to be
//! invocable from ring 3, which requires `DPL=3` on the IDT entry.
//! We can't get that with Hyperlight's defaults.
//!
//! This module installs a *patched* IDT: it copies Hyperlight's
//! current IDT into a heap-allocated buffer, overwrites entry 0x80
//! with our own handler at DPL=3, and `lidt`s the new buffer. The
//! original IDT in `.data` stays untouched.
//!
//! GDT + TSS for ring-3 entry land in commit A4 (when we actually
//! drop to ring 3). A2 only needs the IDT change so we can validate
//! the int-0x80 path from ring 0.

#![cfg(target_os = "none")]

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
/// (callable from ring 3). Returns a leak'd `Box` holding the new
/// IDT buffer — the caller is expected to store this in a static so
/// the lidt'd memory survives.
///
/// # Safety
/// `handler_va` must be a valid kernel-mode code entry point that
/// preserves CPU state and ends in `iretq`. The current IDT (whose
/// base is reported by `sidt`) must be readable for `IDT_BYTES`
/// bytes.
pub unsafe fn install_dpl3_handler(vector: u8, handler_va: u64) -> &'static IdtDescriptor {
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
    e.ist = 0;
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
