//! Procedural macros for declaring nub_rt guest endpoints.
//!
//! The `#[nub_rt::endpoint(N)]` attribute marks a function as
//! endpoint `N` of a PVM2 program. The macro emits three items
//! into the guest crate:
//!
//! 1. The function definition itself, unchanged.
//! 2. A per-endpoint trampoline `__nub_rt_ep_N_trampoline` in
//!    `.text` that calls the user function, then halts the VM via
//!    a bare `ecall` with no CSR marker, which the linker rewrites
//!    to `custom-0 ecalli imm=0` — the clean-halt convention. The
//!    trampoline lives in regular code; the engine enters it at
//!    `endpoints[N].entry_pc`.
//! 3. A `nub_rt::EndpointDescriptor` static in the
//!    `.nub.endpoints` ELF section whose `fn_ptr` points at
//!    the trampoline (not the user fn). `nub-linker` reads the
//!    section at link time and resolves each `fn_ptr` to a PVM PC.
//!
//! ```ignore
//! #[nub_rt::endpoint(0)]
//! fn process(args_len: u64) -> u64 { ... }
//! ```
//!
//! On host targets the macro emits only the function definition;
//! the trampoline and descriptor are gated behind
//! `cfg(all(target_os = "none", target_arch = "riscv64"))`.

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{ItemFn, LitInt, parse_macro_input};

/// Mark a function as endpoint `N` of a PVM2 program.
///
/// `N` must be a `u8` literal (0..=255). Validates the function
/// signature loosely; the linker does the strict check when it
/// resolves the descriptor against the ELF symbol table.
#[proc_macro_attribute]
pub fn endpoint(attr: TokenStream, item: TokenStream) -> TokenStream {
    let idx = parse_macro_input!(attr as LitInt);
    let idx_value: u8 = match idx.base10_parse::<u8>() {
        Ok(v) => v,
        Err(e) => return e.to_compile_error().into(),
    };

    let func = parse_macro_input!(item as ItemFn);
    let fn_name = &func.sig.ident;
    let descriptor_name = format_ident!("__NUB_RT_ENDPOINT_{}", idx_value);
    let trampoline_ident = format_ident!("__nub_rt_ep_{}_trampoline", idx_value);
    let trampoline_label = format!("__nub_rt_ep_{}_trampoline", idx_value);
    let global_directive = format!(".global {trampoline_label}");
    let trampoline_label_colon = format!("{trampoline_label}:");

    let expanded = quote! {
        #func

        #[cfg(all(target_os = "none", target_arch = "riscv64"))]
        core::arch::global_asm!(
            ".text",
            #global_directive,
            #trampoline_label_colon,
            "call {user_fn}",
            // Bare `ecall` (no CSR marker) -> the linker rewrites it
            // to `custom-0 ecalli imm=0`, the clean-halt convention.
            "li t0, 0",
            "ecall",
            "unimp", // trap if somehow resumed after REPLY
            user_fn = sym #fn_name,
        );

        #[cfg(all(target_os = "none", target_arch = "riscv64"))]
        unsafe extern "Rust" {
            safe fn #trampoline_ident(args_len: u64) -> u64;
        }

        #[cfg(all(target_os = "none", target_arch = "riscv64"))]
        #[doc(hidden)]
        #[unsafe(link_section = ".nub.endpoints")]
        #[used]
        static #descriptor_name: ::nub_rt::EndpointDescriptor =
            ::nub_rt::EndpointDescriptor {
                fn_ptr: #trampoline_ident,
                index: #idx_value,
                arg_registers: 0,
                arg_meta: 0,
                _pad: [0; 5],
            };
    };

    expanded.into()
}
