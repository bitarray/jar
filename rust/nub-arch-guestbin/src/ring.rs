//! Raw byte pop/push on the shared input/output rings.
//!
//! Upstream `GuestHandle::push_shared_output_data(&[u8])` already
//! handles raw bytes for output. Upstream
//! `try_pop_shared_input_data_into<T: for<'a> TryFrom<&'a [u8]>>` is
//! generic over a typed conversion from a slice that includes a
//! trailing region of unknown length — fine for self-delimited
//! formats like FlatBuffers but unsuitable for raw rkyv envelopes
//! (no length prefix; the ring's back-pointer determines bounds).
//!
//! This module supplies the missing raw-pop primitive.
//!
//! The ring's element layout is:
//!
//! ```text
//! [element bytes ...][u64 LE back-pointer]
//! ```
//!
//! The back-pointer holds the previous stack-pointer (i.e. the
//! offset where this element starts). The current stack pointer
//! lives at the ring's first 8 bytes. So the element size is
//! `stack_pointer - back_pointer - 8`, and we can extract the bytes
//! without any in-band size prefix.

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::slice::from_raw_parts_mut;

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_guest::error::{HyperlightGuestError, Result};
use hyperlight_guest::guest_handle::handle::GuestHandle;

/// Pop the top element of the shared input data ring as raw bytes.
/// The size is recovered from the back-pointer; there is no
/// in-band size prefix.
pub fn pop_shared_input_raw(handle: &GuestHandle) -> Result<Vec<u8>> {
    let peb_ptr = handle.peb().expect("PEB uninitialised");
    let input_stack_size = unsafe { (*peb_ptr).input_stack.size as usize };
    let input_stack_ptr = unsafe { (*peb_ptr).input_stack.ptr as *mut u8 };
    let idb = unsafe { from_raw_parts_mut(input_stack_ptr, input_stack_size) };

    if idb.is_empty() {
        return Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            "pop_shared_input_raw: 0-size buffer".to_string(),
        ));
    }

    let stack_ptr_rel = u64::from_le_bytes(
        idb[..8]
            .try_into()
            .expect("input ring smaller than its stack pointer"),
    ) as usize;

    if stack_ptr_rel > input_stack_size || stack_ptr_rel < 16 {
        return Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            format!("pop_shared_input_raw: invalid stack pointer {stack_ptr_rel}"),
        ));
    }

    let back_ptr = u64::from_le_bytes(
        idb[stack_ptr_rel - 8..stack_ptr_rel]
            .try_into()
            .expect("back-pointer slice"),
    ) as usize;

    if back_ptr < 8 || back_ptr > stack_ptr_rel - 8 {
        return Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            format!(
                "pop_shared_input_raw: invalid back-pointer {back_ptr} (sp={stack_ptr_rel})"
            ),
        ));
    }

    let element_size = stack_ptr_rel - back_ptr - 8;
    let result = idb[back_ptr..back_ptr + element_size].to_vec();

    // Pop: rewind stack pointer to where this element started.
    idb[..8].copy_from_slice(&(back_ptr as u64).to_le_bytes());

    // Zero out the popped element + its back-pointer.
    idb[back_ptr..stack_ptr_rel].fill(0);

    Ok(result)
}
