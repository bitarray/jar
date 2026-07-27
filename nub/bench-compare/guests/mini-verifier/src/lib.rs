//! `mini-verifier` entry shim. The kernel is unchanged; see `bench-abi.rs`.

#![cfg_attr(target_os = "none", no_std)]

include!("../../bench-abi.rs");

bench_entry!(kernel::mini_verifier_bench);
