/*
Copyright 2025  The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */

#[path = "arch/amd64/layout.rs"]
mod arch;

pub use arch::{MAX_GPA, MAX_GVA};

/// Base VA at which the guest's entire memory range is mapped.
/// Both the host (via mmap of snapshot/scratch regions) and the
/// guest (via its page table) use this as the anchor. Configurable
/// via JAR_GUEST_VA_BASE env var (hex string, with or without 0x
/// prefix); default chosen to sit in the practically-never-touched
/// mid-range band of x86_64 user VA space.
pub const GUEST_VA_BASE_DEFAULT: u64 = 0x5000_0000_0000;
/// Total VA range reserved for the guest. Layout inside:
/// [0, 4 GiB) javm program; [4, 5 GiB) JIT scratch;
/// [5 GiB, 7 GiB) kernel (KERNEL_OFFSET); [7 GiB, end) scratch.
pub const GUEST_VA_SIZE: u64 = 0x4_4000_0000;
/// Offset within the reservation where the kernel binary loads.
pub const KERNEL_OFFSET: u64 = 0x1_4000_0000; // 5 GiB

/// Stores the base VA chosen at reservation time on platforms where
/// `guest_va_base()` is determined dynamically (today: macOS, which
/// lacks `MAP_FIXED_NOREPLACE`). On Linux it stays `None` and
/// [`guest_va_base()`] resolves to the env override / default.
#[cfg(all(feature = "std", target_os = "macos"))]
static MACOS_RESERVED_BASE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

#[cfg(feature = "std")]
pub fn guest_va_base() -> u64 {
    #[cfg(target_os = "macos")]
    if let Some(&base) = MACOS_RESERVED_BASE.get() {
        return base;
    }
    if let Ok(s) = std::env::var("JAR_GUEST_VA_BASE") {
        let s = s.trim().trim_start_matches("0x");
        u64::from_str_radix(s, 16).expect("JAR_GUEST_VA_BASE must be hex")
    } else {
        GUEST_VA_BASE_DEFAULT
    }
}

/// One-time process-wide reservation of the [`guest_va_base()`,
/// `guest_va_base() + GUEST_VA_SIZE`) range. Done on host startup so
/// later mmaps of guest-visible regions (snapshot, scratch, kernel
/// shadow) can land at known fixed VAs via `MAP_FIXED` inside this
/// reservation.
///
/// On Linux we use `MAP_FIXED_NOREPLACE` to claim the configured base
/// atomically; failure means something is squatting on the range,
/// which is almost certainly a misconfiguration — error loudly.
///
/// On macOS `MAP_FIXED_NOREPLACE` doesn't exist, so we let the
/// kernel pick a base via plain `mmap`. macOS ASLR almost never
/// places mid-range addresses, but if it does we munmap and retry
/// up to ~10 times; the successful base is then stored so
/// [`guest_va_base()`] returns it.
#[cfg(feature = "std")]
pub fn reserve_guest_va_range() -> Result<(), std::io::Error> {
    use std::sync::OnceLock;
    static RESERVED: OnceLock<Result<(), String>> = OnceLock::new();
    let res = RESERVED.get_or_init(reserve_guest_va_range_inner);
    res.clone().map_err(std::io::Error::other)
}

#[cfg(all(feature = "std", target_os = "linux"))]
fn reserve_guest_va_range_inner() -> Result<(), String> {
    let base = guest_va_base();
    let size = GUEST_VA_SIZE as usize;
    // SAFETY: mmap is a kernel call; we check the result before use.
    let ptr = unsafe {
        libc::mmap(
            base as *mut libc::c_void,
            size,
            libc::PROT_NONE,
            libc::MAP_PRIVATE
                | libc::MAP_ANONYMOUS
                | libc::MAP_FIXED_NOREPLACE
                | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(format!(
            "JAR guest VA reservation failed: mmap({:#x}, {} bytes, MAP_FIXED_NOREPLACE): {}",
            base,
            size,
            std::io::Error::last_os_error()
        ));
    }
    if ptr as u64 != base {
        // Older glibc fallback path: NOREPLACE was ignored and the
        // kernel placed the mapping elsewhere. Unmap and bail —
        // something is squatting on our VA range.
        // SAFETY: ptr came from a successful mmap.
        unsafe {
            libc::munmap(ptr, size);
        }
        return Err(format!(
            "JAR guest VA reservation: requested {:#x}, kernel returned {:#x} — \
             something is squatting on our range",
            base, ptr as u64
        ));
    }
    Ok(())
}

#[cfg(all(feature = "std", target_os = "macos"))]
fn reserve_guest_va_range_inner() -> Result<(), String> {
    // 5 GiB — comfortably above the low region where the loader,
    // heap, and per-process stacks tend to cluster. If macOS hands
    // us anything below this we retry.
    const MIN_BASE: u64 = 0x1_4000_0000;
    let size = GUEST_VA_SIZE as usize;
    for _ in 0..10 {
        // SAFETY: plain mmap with a null hint; result checked below.
        let ptr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                size,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(format!(
                "JAR guest VA reservation failed: mmap({} bytes): {}",
                size,
                std::io::Error::last_os_error()
            ));
        }
        if (ptr as u64) >= MIN_BASE {
            MACOS_RESERVED_BASE
                .set(ptr as u64)
                .expect("MACOS_RESERVED_BASE set once");
            return Ok(());
        }
        // SAFETY: ptr came from a successful mmap.
        unsafe {
            libc::munmap(ptr, size);
        }
    }
    Err("macOS: could not reserve guest VA range outside low 5 GiB after 10 retries".into())
}

#[cfg(all(feature = "std", not(any(target_os = "linux", target_os = "macos"))))]
fn reserve_guest_va_range_inner() -> Result<(), String> {
    Err("JAR guest VA reservation: unsupported host OS (only linux and macos are supported)".into())
}

// offsets down from the top of scratch memory for various things
pub const SCRATCH_TOP_SIZE_OFFSET: u64 = 0x08;
pub const SCRATCH_TOP_ALLOCATOR_OFFSET: u64 = 0x10;
pub const SCRATCH_TOP_SNAPSHOT_PT_GPA_BASE_OFFSET: u64 = 0x18;
pub const SCRATCH_TOP_SNAPSHOT_GENERATION_OFFSET: u64 = 0x20;
pub const SCRATCH_TOP_EXN_STACK_OFFSET: u64 = 0x30;

/// Offset from the top of scratch memory for a shared host-guest u64 counter.
///
/// This is placed at 0x1008 (rather than the next sequential 0x28) so that the
/// counter falls in scratch page 0xffffe000 instead of the very last page
/// 0xfffff000, which on i686 guests would require frame 0xfffff — exceeding the
/// maximum representable frame number.
#[cfg(feature = "guest-counter")]
pub const SCRATCH_TOP_GUEST_COUNTER_OFFSET: u64 = 0x1008;

pub fn scratch_base_gpa(size: usize) -> u64 {
    (MAX_GPA - size + 1) as u64
}
pub fn scratch_base_gva(size: usize) -> u64 {
    (MAX_GVA - size + 1) as u64
}

/// Compute the minimum scratch region size needed for a sandbox.
pub use arch::min_scratch_size;
