//! Pixels JAM service — a 100x100 RGB canvas (like Reddit r/place).
//!
//! - **Refine** (PC=0): echo input payload as output (identity)
//! - **Accumulate**: fetch work item, extract pixel data from
//!   the refinement result, read canvas from storage, apply pixel, write back
//!
//! Storage layout: key `[0x00]` → 30,000 bytes (100x100x3 RGB, row-major).
//! Pixel (x,y) at offset `(y*100 + x) * 3`.
//!
//! Work item result: 5 bytes `[x, y, r, g, b]`.
//!
//! ## v2 capability convention
//!
//! All host call pointer arguments are offsets within the heap DATA cap (cap 68).
//! Heap layout:
//!   0x0000: storage key (1 byte: 0x00)
//!   0x0010: fetch buffer (512 bytes)
//!   0x0220: canvas buffer (30,000 bytes)

#![cfg_attr(target_env = "javm", no_std)]
#![cfg_attr(target_env = "javm", no_main)]

#[cfg(target_env = "javm")]
mod service {
    /// Canvas: 100x100 pixels, 3 bytes each (RGB), row-major.
    const CANVAS_SIZE: u32 = 100 * 100 * 3;

    /// Heap DATA cap index (assigned by the v2 transpiler).
    const HEAP_CAP: u32 = 68;

    /// Heap offsets for I/O buffers.
    const KEY_OFF: u32 = 0x0000;
    const FETCH_OFF: u32 = 0x0010;
    const CANVAS_OFF: u32 = 0x0220;

    // Offset to pixel data in the operand blob (fixed-width encoding):
    // item_disc(1) + package_hash(32) + exports_root(32) +
    // authorizer_hash(32) + payload_hash(32) + gas(u64=8) +
    // result_disc(1) + result_len(u32=4) = 142
    const PIXEL_DATA_OFFSET: u32 = 142;

    // Entry-point: single entrypoint at PC=0.
    // The transpiler emits: load_imm_64 SP; load_imm_64 S0 before the ELF code.
    // φ[7]=op dispatches (0=refine, 1=accumulate).
    //
    // _start checks a0: if != 1, REPLY immediately (refine = identity).
    // If a0 == 1, fall through to accumulate_impl, then REPLY.
    core::arch::global_asm!(
        ".global _start",
        ".type _start, @function",
        "_start:",
        // if a0 != 1, skip accumulate (refine = identity)
        "li t1, 1",
        "bne a0, t1, .Lreply",
        // accumulate
        "jal ra, accumulate_impl",
        ".Lreply:",
        // REPLY to kernel
        "li t0, 255",
        "ecall",
        "unimp",
    );

    #[no_mangle]
    extern "C" fn accumulate_impl() {
        unsafe {
            // 1. Write storage key [0x00] into heap at KEY_OFF
            write_heap_byte(KEY_OFF, 0x00);

            // 2. Fetch work item operand (mode=15, sub=0)
            // FETCH: φ[7]=mode, φ[8]=sub, φ[9]=out_off, φ[10]=max_len, φ[12]=data_cap
            let total_len = host_call_1(15, 0, FETCH_OFF, 512, HEAP_CAP);

            if total_len == u32::MAX || total_len < PIXEL_DATA_OFFSET + 5 {
                return;
            }

            // 3. Read pixel data from fetch buffer at PIXEL_DATA_OFFSET
            let fetch_pixel_off = FETCH_OFF + PIXEL_DATA_OFFSET;
            let x = read_heap_byte(fetch_pixel_off) as u32;
            let y = read_heap_byte(fetch_pixel_off + 1) as u32;
            let r = read_heap_byte(fetch_pixel_off + 2);
            let g = read_heap_byte(fetch_pixel_off + 3);
            let b = read_heap_byte(fetch_pixel_off + 4);

            if x >= 100 || y >= 100 {
                return;
            }

            // 4. Read current canvas from storage
            // STORAGE_R: φ[7]=key_off, φ[8]=key_len, φ[9]=out_off, φ[10]=max_len, φ[12]=data_cap
            host_call_3(KEY_OFF, 1, CANVAS_OFF, CANVAS_SIZE, HEAP_CAP);

            // 5. Apply the pixel
            let pixel_off = CANVAS_OFF + (y * 100 + x) * 3;
            write_heap_byte(pixel_off, r);
            write_heap_byte(pixel_off + 1, g);
            write_heap_byte(pixel_off + 2, b);

            // 6. Write canvas back to storage
            // STORAGE_W: φ[7]=key_off, φ[8]=key_len, φ[9]=val_off, φ[10]=val_len, φ[12]=data_cap
            host_call_4(KEY_OFF, 1, CANVAS_OFF, CANVAS_SIZE, HEAP_CAP);
        }
    }

    // --- Host call wrappers ---
    // v2 convention: φ[7]-φ[10] = args, φ[12] = data_cap, return in φ[7]

    #[inline(always)]
    unsafe fn host_call_1(a0: u32, a1: u32, a2: u32, a3: u32, a5: u32) -> u32 {
        let result: u32;
        core::arch::asm!(
            "li t0, 1",  // FETCH
            "ecall",
            in("a0") a0,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a5") a5,
            lateout("a0") result,
            out("t0") _,
            clobber_abi("C"),
        );
        result
    }

    #[inline(always)]
    unsafe fn host_call_3(a0: u32, a1: u32, a2: u32, a3: u32, a5: u32) -> u32 {
        let result: u32;
        core::arch::asm!(
            "li t0, 3",  // STORAGE_R
            "ecall",
            in("a0") a0,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a5") a5,
            lateout("a0") result,
            out("t0") _,
            clobber_abi("C"),
        );
        result
    }

    #[inline(always)]
    unsafe fn host_call_4(a0: u32, a1: u32, a2: u32, a3: u32, a5: u32) -> u32 {
        let result: u32;
        core::arch::asm!(
            "li t0, 4",  // STORAGE_W
            "ecall",
            in("a0") a0,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a5") a5,
            lateout("a0") result,
            out("t0") _,
            clobber_abi("C"),
        );
        result
    }

    // --- Heap memory access via inline asm ---
    // These read/write the heap DATA cap's mapped memory region directly.
    // The heap cap is mapped at its base_page in the CODE window, so
    // heap_base + offset gives the flat PVM address.

    /// Read a byte from the heap at the given offset.
    /// The heap base address is computed from the cap's base_page.
    /// For now, we use a fixed heap base that matches the transpiler's layout:
    /// heap is after stack + ro + rw pages.
    #[inline(always)]
    unsafe fn read_heap_byte(offset: u32) -> u8 {
        let addr = HEAP_BASE_ADDR as usize + offset as usize;
        let val: u8;
        core::arch::asm!(
            "lbu {0}, 0({1})",
            out(reg) val,
            in(reg) addr,
        );
        val
    }

    #[inline(always)]
    unsafe fn write_heap_byte(offset: u32, val: u8) {
        let addr = HEAP_BASE_ADDR as usize + offset as usize;
        core::arch::asm!(
            "sb {0}, 0({1})",
            in(reg) val,
            in(reg) addr,
        );
    }

    /// Heap base address. For this service: stack_pages=4, no RO/RW data,
    /// so heap DATA cap (68) is at base_page=4 → address 0x4000.
    /// This is deterministic from the build_service memory layout.
    const HEAP_BASE_ADDR: u32 = 4 * 4096;

    #[panic_handler]
    fn panic(_: &core::panic::PanicInfo) -> ! {
        loop {}
    }
}

#[cfg(not(target_env = "javm"))]
fn main() {}
