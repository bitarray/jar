//! Pixels JAM service — a 100x100 RGB canvas (like Reddit r/place).
//!
//! - **Refine** (PC=0): echo input payload as output (identity)
//! - **Accumulate** (PC=5): fetch work item, extract pixel data from
//!   the refinement result, read canvas from storage, apply pixel, write back
//!
//! Storage layout: key `[0x00]` → 30,000 bytes (100x100x3 RGB, row-major).
//! Pixel (x,y) at offset `(y*100 + x) * 3`.
//!
//! Work item result: 5 bytes `[x, y, r, g, b]`.

#![cfg_attr(target_env = "javm", no_std)]
#![cfg_attr(target_env = "javm", no_main)]

#[cfg(target_env = "javm")]
mod service {
    use core::arch::global_asm;

    /// Canvas: 100x100 pixels, 3 bytes each (RGB), row-major.
    const CANVAS_SIZE: usize = 100 * 100 * 3;

    /// Storage key for the canvas blob.
    static STORAGE_KEY: [u8; 1] = [0x00];

    /// Canvas buffer in BSS (zero-initialized).
    static mut CANVAS: [u8; CANVAS_SIZE] = [0u8; CANVAS_SIZE];

    /// Fetch buffer for a single work-item operand.
    static mut FETCH_BUF: [u8; 512] = [0u8; 512];

    // Entry-point trampolines (assembly)
    // PC=0 (_start) → refine: just return (echo a0/a1)
    // PC=5 (accumulate) → jump to Rust accumulate_impl
    global_asm!(
        ".global _start",
        ".type _start, @function",
        "_start:",
        "j refine",
        ".global refine",
        ".type refine, @function",
        "refine:",
        "ret",
        ".global accumulate",
        ".type accumulate, @function",
        "accumulate:",
        "j accumulate_impl",
    );

    // Host-call wrappers (inline asm)

    #[inline(always)]
    unsafe fn host_fetch(
        buf_ptr: *mut u8,
        offset: u32,
        max_len: u32,
        mode: u32,
        sub1: u32,
        sub2: u32,
    ) -> u32 {
        let result: u32;
        core::arch::asm!(
            "li t0, 2",
            "ecall",
            in("a0") buf_ptr as usize,
            in("a1") offset,
            in("a2") max_len,
            in("a3") mode,
            in("a4") sub1,
            in("a5") sub2,
            lateout("a0") result,
            out("t0") _,
            clobber_abi("C"),
        );
        result
    }

    #[inline(always)]
    unsafe fn host_read(
        service_id: u32,
        key_ptr: *const u8,
        key_len: u32,
        out_ptr: *mut u8,
        offset: u32,
        max_len: u32,
    ) -> u32 {
        let result: u32;
        core::arch::asm!(
            "li t0, 4",
            "ecall",
            in("a0") service_id,
            in("a1") key_ptr as usize,
            in("a2") key_len,
            in("a3") out_ptr as usize,
            in("a4") offset,
            in("a5") max_len,
            lateout("a0") result,
            out("t0") _,
            clobber_abi("C"),
        );
        result
    }

    #[inline(always)]
    unsafe fn host_write(
        key_ptr: *const u8,
        key_len: u32,
        val_ptr: *const u8,
        val_len: u32,
    ) -> u32 {
        let result: u32;
        core::arch::asm!(
            "li t0, 5",
            "ecall",
            in("a0") key_ptr as usize,
            in("a1") key_len,
            in("a2") val_ptr as usize,
            in("a3") val_len,
            lateout("a0") result,
            out("t0") _,
            clobber_abi("C"),
        );
        result
    }

    // Offset to pixel data in the operand blob (fixed-width encoding):
    // item_disc(1) + package_hash(32) + exports_root(32) +
    // authorizer_hash(32) + payload_hash(32) + gas(u64=8) +
    // result_disc(1) + result_len(u32=4) = 142
    const PIXEL_DATA_OFFSET: usize = 142;

    #[no_mangle]
    extern "C" fn accumulate_impl() {
        unsafe {
            let fetch_ptr = core::ptr::addr_of_mut!(FETCH_BUF) as *mut u8;
            let canvas_ptr = core::ptr::addr_of_mut!(CANVAS) as *mut u8;

            // 1. Fetch work item operand (mode=15, index=0)
            let total_len = host_fetch(fetch_ptr, 0, 512, 15, 0, 0);

            if total_len == u32::MAX || (total_len as usize) < PIXEL_DATA_OFFSET + 5 {
                return;
            }

            // 2. Extract pixel data: [x, y, r, g, b] at known offset
            let x = *fetch_ptr.add(PIXEL_DATA_OFFSET) as usize;
            let y = *fetch_ptr.add(PIXEL_DATA_OFFSET + 1) as usize;
            let r = *fetch_ptr.add(PIXEL_DATA_OFFSET + 2);
            let g = *fetch_ptr.add(PIXEL_DATA_OFFSET + 3);
            let b = *fetch_ptr.add(PIXEL_DATA_OFFSET + 4);

            if x >= 100 || y >= 100 {
                return;
            }

            // 3. Read current canvas from storage
            host_read(
                u32::MAX,
                STORAGE_KEY.as_ptr(),
                STORAGE_KEY.len() as u32,
                canvas_ptr,
                0,
                CANVAS_SIZE as u32,
            );

            // 4. Apply the pixel
            let off = (y * 100 + x) * 3;
            *canvas_ptr.add(off) = r;
            *canvas_ptr.add(off + 1) = g;
            *canvas_ptr.add(off + 2) = b;

            // 5. Write canvas back to storage
            host_write(
                STORAGE_KEY.as_ptr(),
                STORAGE_KEY.len() as u32,
                canvas_ptr as *const u8,
                CANVAS_SIZE as u32,
            );
        }
    }

    #[panic_handler]
    fn panic(_: &core::panic::PanicInfo) -> ! {
        loop {}
    }
}

#[cfg(not(target_env = "javm"))]
fn main() {}
