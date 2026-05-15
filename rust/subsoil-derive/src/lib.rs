//! Procedural macros for declaring subsoil guest endpoints.
//!
//! The `#[subsoil::endpoint(N)]` attribute marks a function as
//! endpoint `N` of a JAR chain Image. The macro:
//!
//! 1. Leaves the function definition unchanged.
//! 2. Emits a `subsoil::EndpointDescriptor` static into the
//!    `.subsoil.endpoints` ELF section. The transpiler reads this
//!    section at link time to populate the chain Image's
//!    `endpoints: BTreeMap<u8, EndpointDef>` field.
//!
//! ```ignore
//! #[subsoil::endpoint(0)]
//! fn process(args_len: u64) -> u64 { ... }
//! ```
//!
//! On host targets the attribute is a no-op (the descriptor is
//! emitted only under `cfg(all(target_env = "javm", target_os =
//! "none"))`).

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{ItemFn, LitInt, parse_macro_input};

/// Mark a function as endpoint `N` of a JAR chain Image.
///
/// `N` must be a `u8` literal (0..=255). Validates the function
/// signature loosely; the transpiler does the strict check when it
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
    let descriptor_name = format_ident!("__SUBSOIL_ENDPOINT_{}", idx_value);

    let expanded = quote! {
        #func

        #[cfg(all(target_env = "javm", target_os = "none"))]
        #[doc(hidden)]
        #[unsafe(link_section = ".subsoil.endpoints")]
        #[used]
        static #descriptor_name: ::subsoil::EndpointDescriptor =
            ::subsoil::EndpointDescriptor {
                fn_ptr: #fn_name,
                index: #idx_value,
                arg_registers: 0,
                arg_cnode_size: 0,
                _pad: [0; 5],
            };
    };

    expanded.into()
}
