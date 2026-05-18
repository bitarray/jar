//! Proc macros for the nub guest runtime.
//!
//! Forked from `hyperlight-guest-macro 0.15.0` (Apache-2.0), stripped
//! of name-based + parameter-polymorphic registration. The single
//! attribute `#[guest_function(fn_id = N)]` registers a guest
//! function under an integer `fn_id` chosen at compile time. The
//! dispatcher in `nub-arch-guestbin` matches on `fn_id` and calls
//! into the registered function pointer.
//!
//! The function being annotated must have signature
//! `fn(&[u8]) -> Vec<u8>` (the request payload bytes → response
//! payload bytes). Typed encode/decode is the caller's job — the
//! macro stays out of the codec layer.
//!
//! `#[host_function]` is forked too: the wrapper around
//! `nub_arch_guestbin::host_comm::call_host_raw(fn_id, &bytes)` for
//! guest→host RPC. The `#[main]` and `#[dispatch]` upstream
//! attributes are dropped; we use the weak-linkage default for
//! `hyperlight_main` and hand-wire the dispatcher.

use proc_macro::TokenStream;
use proc_macro2::Span;
use proc_macro_crate::{FoundCrate, crate_name};
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;
use syn::{Error, ItemFn, LitInt, Token, parse_macro_input};

/// Parses `fn_id = N` from the attribute args.
struct FnIdArg(u32);

impl Parse for FnIdArg {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let ident: syn::Ident = input.parse()?;
        if ident != "fn_id" {
            return Err(Error::new(
                ident.span(),
                "expected `fn_id = N`, where N is a u32 literal",
            ));
        }
        let _eq: Token![=] = input.parse()?;
        let lit: LitInt = input.parse()?;
        let value: u32 = lit.base10_parse()?;
        Ok(FnIdArg(value))
    }
}

fn resolve_crate(name: &str) -> proc_macro2::TokenStream {
    match crate_name(name).unwrap_or_else(|_| panic!("`{name}` must be a dependency")) {
        FoundCrate::Itself => quote! { crate },
        FoundCrate::Name(found) => {
            let ident = syn::Ident::new(&found, Span::call_site());
            quote! { ::#ident }
        }
    }
}

/// Register a guest function under a compile-time `fn_id`.
///
/// ```ignore
/// use nub_host_guest_macro::guest_function;
///
/// #[guest_function(fn_id = 1)]
/// pub fn nub_invoke(input: &[u8]) -> Vec<u8> {
///     // ...
/// }
/// ```
///
/// Expands to the original function plus a `linkme` distributed-slice
/// entry that the guestbin's `dispatch` function iterates at call
/// time. The function signature is fixed: `fn(&[u8]) -> Vec<u8>`.
#[proc_macro_attribute]
pub fn guest_function(attr: TokenStream, item: TokenStream) -> TokenStream {
    let crate_name = resolve_crate("hyperlight-guest-bin");
    let FnIdArg(fn_id) = parse_macro_input!(attr as FnIdArg);
    let fn_declaration = parse_macro_input!(item as ItemFn);

    let ident = fn_declaration.sig.ident.clone();

    // Sanity: reject receiver args and async functions.
    if let Some(syn::FnArg::Receiver(arg)) = fn_declaration.sig.inputs.first() {
        return Error::new(arg.span(), "receiver (self) argument not allowed")
            .to_compile_error()
            .into();
    }
    if fn_declaration.sig.asyncness.is_some() {
        return Error::new(
            fn_declaration.sig.asyncness.span(),
            "async guest functions not allowed",
        )
        .to_compile_error()
        .into();
    }

    let registration_ident = syn::Ident::new(
        &format!("__NUB_GUEST_FN_{fn_id}_ENTRY"),
        Span::call_site(),
    );

    quote! {
        #fn_declaration

        #[#crate_name::__private::linkme::distributed_slice(
            #crate_name::__private::GUEST_FUNCTION_TABLE
        )]
        #[linkme(crate = #crate_name::__private::linkme)]
        static #registration_ident:
            #crate_name::guest_function::register::GuestFnEntry =
            #crate_name::guest_function::register::GuestFnEntry {
                fn_id: #fn_id,
                dispatcher: #ident,
            };
    }
    .into()
}

/// Generate a host-function wrapper that issues a guest→host RPC.
///
/// ```ignore
/// use nub_host_guest_macro::host_function;
///
/// #[host_function(fn_id = 10)]
/// pub fn read_block(block_id: &[u8]) -> Vec<u8>;
/// ```
///
/// Expands the foreign-item-function declaration into a real
/// function whose body calls
/// `nub_arch_guestbin::host_comm::call_host_raw(fn_id, payload)`.
/// Like `#[guest_function]`, the signature must be
/// `fn(&[u8]) -> Vec<u8>` — typed encode/decode is the caller's job.
#[proc_macro_attribute]
pub fn host_function(attr: TokenStream, item: TokenStream) -> TokenStream {
    let crate_name = resolve_crate("hyperlight-guest-bin");
    let FnIdArg(fn_id) = parse_macro_input!(attr as FnIdArg);
    let fn_declaration = parse_macro_input!(item as syn::ForeignItemFn);

    let syn::ForeignItemFn {
        attrs, vis, sig, ..
    } = fn_declaration;
    let ident = sig.ident.clone();

    // Validate signature: one `&[u8]` arg, `Vec<u8>` return.
    if sig.inputs.len() != 1 {
        return Error::new(
            sig.inputs.span(),
            "expected exactly one `&[u8]` parameter",
        )
        .to_compile_error()
        .into();
    }

    quote! {
        #(#attrs)*
        #vis #sig {
            #crate_name::host_comm::call_host_raw(#fn_id, #ident)
                .expect(concat!("host function call (fn_id=", stringify!(#fn_id), ") failed"))
        }
    }
    .into()
}
