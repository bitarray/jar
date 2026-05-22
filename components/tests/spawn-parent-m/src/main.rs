#![cfg_attr(target_env = "javm", no_std)]
#![cfg_attr(target_env = "javm", no_main)]

use spawn_parent_m as _;
use subsoil as _;

#[cfg(target_env = "javm")]
mod kernel_abi;

#[cfg(all(target_env = "javm", target_os = "none"))]
const RESULT_BUF_SIZE: usize = 8;
#[cfg(all(target_env = "javm", target_os = "none"))]
static mut RESULT_BUF: [u8; RESULT_BUF_SIZE] = [0u8; RESULT_BUF_SIZE];

/// Slot layout (must match the integration test harness):
/// - `SLOT_IMAGE_S`: pre-published `Cap::Image` for child S.
/// - `SLOT_INPUT_DATA`: pre-published `Cap::Data` input for the CALL.
/// - `SLOT_PREP_CNODE`: prepared CNode the spawn consumes.
/// - `SLOT_CHILD_INSTANCE`: where the spawned `Cap::Instance` lands.
#[cfg(all(target_env = "javm", target_os = "none"))]
const SLOT_IMAGE_S: u8 = 3;
#[cfg(all(target_env = "javm", target_os = "none"))]
const SLOT_INPUT_DATA: u8 = 5;
#[cfg(all(target_env = "javm", target_os = "none"))]
const SLOT_PREP_CNODE: u8 = 4;
#[cfg(all(target_env = "javm", target_os = "none"))]
const SLOT_CHILD_INSTANCE: u8 = 6;
#[cfg(all(target_env = "javm", target_os = "none"))]
const SLOT_SCRATCH: u8 = 0;
#[cfg(all(target_env = "javm", target_os = "none"))]
const CHILD_ENDPOINT: u8 = 0;

#[cfg(all(target_env = "javm", target_os = "none"))]
#[subsoil::endpoint(0)]
fn javm_main(_args_len: u64) -> u64 {
    use kernel_abi::*;

    // 1. Mint a fresh prepared CNode at SLOT_PREP_CNODE. size_log=8
    //    → 256 slots, large enough to hold the child Image's
    //    transpiler-emitted stack/rw/heap slots (65, 67, 68).
    //    Communication is otherwise via slot[0] only.
    unsafe { mgmt_cnode_mint(SLOT_PREP_CNODE, 8) };

    // 2. Move the input DataCap into slot[0]. The CALL transfers
    //    slot[0] to the child as the scratchpad.
    unsafe { mgmt_copy(SLOT_INPUT_DATA, SLOT_SCRATCH) };

    // 3. Derive the child Cap::Instance from Image S + the prepared
    //    CNode. Consumes SLOT_PREP_CNODE; writes the instance hash
    //    to SLOT_CHILD_INSTANCE.
    unsafe { host_derive_spawn(SLOT_IMAGE_S, SLOT_PREP_CNODE, SLOT_CHILD_INSTANCE) };

    // 4. CALL the child. M suspends; on HALT, the child's slot[0]
    //    (the result DataCap) is reflected into M's slot[0].
    unsafe { host_call(SLOT_CHILD_INSTANCE, CHILD_ENDPOINT) };

    // 5. Read the reflected result DataCap into memory.
    let res_ptr = (&raw mut RESULT_BUF) as *mut u8;
    let res_addr = res_ptr as u32;
    let n_read = unsafe { host_read_data_cap(SLOT_SCRATCH, res_addr, RESULT_BUF_SIZE as u64) };

    // 6. Return the first byte of the result (or 0 if empty).
    if n_read == 0 {
        0
    } else {
        unsafe { *res_ptr as u64 }
    }
}

#[cfg(not(target_env = "javm"))]
fn main() {}
