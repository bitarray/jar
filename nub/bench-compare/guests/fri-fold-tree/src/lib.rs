//! `fri-fold-tree` entry shim. The kernel is unchanged; see `bench-abi.rs`.

#![cfg_attr(target_os = "none", no_std)]

include!("../../bench-abi.rs");

bench_entry!(kernel::fri_fold_tree_bench);
