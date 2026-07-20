//! Test guest binary for `javm-guest-x86`.
//!
//! Same kernel modules + production RPCs as the production bin
//! (via `extern crate javm_guest_x86`), plus test-only guest
//! functions whose FN_IDs live in `nub_arch_x86::test_abi`.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
extern crate alloc;
#[cfg(target_os = "none")]
extern crate hyperlight_guest_bin;
#[cfg(target_os = "none")]
extern crate javm_guest_x86;

#[cfg(target_os = "none")]
mod test_fns {
    use alloc::vec::Vec;
    use hyperlight_guest_bin::guest_function;
    use javm_guest_x86::test_abi::FN_ID_TEST_INVOKE_TWO_SERIAL;
    use nub_arch_x86::test_abi::FN_ID_TEST_SMOKE;
    use nub_arch_x86_abi::{InvocationResult, InvokePacket, SCRATCHPAD_HEAD_LEN};

    /// Smoke probe. Returns rkyv-encoded `42u64`. Used by
    /// `nub/tests/test_bin_smoke.rs` to verify the test bin loads
    /// and the RPC plumbing works end-to-end.
    #[guest_function(fn_id = FN_ID_TEST_SMOKE)]
    pub fn nub_smoke(_input: &[u8]) -> Vec<u8> {
        let v: u64 = 42;
        rkyv::to_bytes::<rkyv::rancor::Error>(&v)
            .expect("rkyv-encode u64")
            .into_vec()
    }

    fn encode_result_error(exit_arg: u32) -> InvocationResult {
        InvocationResult {
            exit_reason: u32::MAX,
            exit_arg,
            return_value: 0,
            gas_remaining: 0,
            scratchpad_head: [0u8; SCRATCHPAD_HEAD_LEN],
        }
    }

    /// Scheduler probe. Runs two top-level invokes through one in-guest
    /// `KernelScheduler`, proving phase-1 can host multiple task stacks while
    /// the production RPC stays one invoke in, one result out.
    #[guest_function(fn_id = FN_ID_TEST_INVOKE_TWO_SERIAL)]
    pub fn nub_invoke_two_serial(input: &[u8]) -> Vec<u8> {
        let expected = InvokePacket::SIZE * 2;
        let results = if input.len() == expected {
            let Some(first) = InvokePacket::from_bytes(&input[..InvokePacket::SIZE]) else {
                let results = [encode_result_error(10), encode_result_error(10)];
                return rkyv::to_bytes::<rkyv::rancor::Error>(&results)
                    .expect("rkyv-encode scheduler probe error")
                    .into_vec();
            };
            let Some(second) = InvokePacket::from_bytes(&input[InvokePacket::SIZE..]) else {
                let results = [encode_result_error(10), encode_result_error(10)];
                return rkyv::to_bytes::<rkyv::rancor::Error>(&results)
                    .expect("rkyv-encode scheduler probe error")
                    .into_vec();
            };
            match javm_guest_x86::call_loop::run_two_for_test(&first, &second) {
                Ok((a, b)) => [
                    InvocationResult {
                        exit_reason: a.exit_reason,
                        exit_arg: a.exit_arg,
                        return_value: a.return_value,
                        gas_remaining: a.gas_remaining.max(0) as u64,
                        scratchpad_head: a.scratchpad_head,
                    },
                    InvocationResult {
                        exit_reason: b.exit_reason,
                        exit_arg: b.exit_arg,
                        return_value: b.return_value,
                        gas_remaining: b.gas_remaining.max(0) as u64,
                        scratchpad_head: b.scratchpad_head,
                    },
                ],
                Err(code) => [encode_result_error(code), encode_result_error(code)],
            }
        } else {
            [encode_result_error(10), encode_result_error(10)]
        };
        rkyv::to_bytes::<rkyv::rancor::Error>(&results)
            .expect("rkyv-encode scheduler probe results")
            .into_vec()
    }
}

#[cfg(not(target_os = "none"))]
fn main() {}
