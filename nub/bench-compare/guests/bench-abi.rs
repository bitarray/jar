// The uniform guest ABI, `include!`d verbatim into every wrapper.
//
// One export, no arguments, `u32` out. Every engine's
// `Backend::run` calls exactly this symbol, and the returned value is
// what the cross-engine equality check compares.
//
// The compute kernels themselves are untouched by any of this: they
// live in `nub/programs/*` as plain `pub fn name() -> u32` and are
// consumed here as an ordinary path dependency. That is the whole
// reason a fair comparison is cheap — one kernel, N entry shims.
//
// The PVM2 family does not use this file. There the kernel crate's own
// `#[nub_rt::endpoint(0)]` binary *is* the ABI, so `bench-build`
// builds that directly.

/// Define the `run` export for whichever target we are building.
macro_rules! bench_entry {
    ($kernel:path) => {
        /// The measured entry point.
        ///
        /// `#[no_mangle]` so the native backend can `dlsym` it and the
        /// wasm backend can find it in the export table;
        /// `#[polkavm_export]` additionally registers it in polkavm's
        /// export table, which is how polkavm enters a program (its
        /// `_start` is never used).
        #[cfg_attr(target_env = "polkavm", polkavm_derive::polkavm_export)]
        #[unsafe(no_mangle)]
        pub extern "C" fn run() -> u32 {
            $kernel()
        }
    };
}
