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
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::Span;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;
use syn::{Error, Expr, ItemFn, Token, parse_macro_input};

/// Parses `fn_id = <expr>` from the attribute args. The expression
/// is forwarded verbatim into the emitted static initializer, so it
/// can be a `u32` literal, a path to a `const FN_ID_*: u32` (the
/// usual case), or any other const-evaluable u32 expression.
struct FnIdArg(Expr);

impl Parse for FnIdArg {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let ident: syn::Ident = input.parse()?;
        if ident != "fn_id" {
            return Err(Error::new(
                ident.span(),
                "expected `fn_id = <const u32 expression>`",
            ));
        }
        let _eq: Token![=] = input.parse()?;
        let expr: Expr = input.parse()?;
        Ok(FnIdArg(expr))
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
    let FnIdArg(fn_id_expr) = parse_macro_input!(attr as FnIdArg);
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

    let registration_ident =
        syn::Ident::new(&format!("__NUB_GUEST_FN_{ident}_ENTRY"), Span::call_site());

    quote! {
        #fn_declaration

        #[#crate_name::__private::linkme::distributed_slice(
            #crate_name::__private::GUEST_FUNCTION_TABLE
        )]
        #[linkme(crate = #crate_name::__private::linkme)]
        static #registration_ident:
            #crate_name::guest_function::register::GuestFnEntry =
            #crate_name::guest_function::register::GuestFnEntry {
                fn_id: (#fn_id_expr),
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
    let FnIdArg(fn_id_expr) = parse_macro_input!(attr as FnIdArg);
    let fn_declaration = parse_macro_input!(item as syn::ForeignItemFn);

    let syn::ForeignItemFn {
        attrs, vis, sig, ..
    } = fn_declaration;

    // Validate signature: one `&[u8]` arg, `Vec<u8>` return.
    if sig.inputs.len() != 1 {
        return Error::new(sig.inputs.span(), "expected exactly one `&[u8]` parameter")
            .to_compile_error()
            .into();
    }

    // The single parameter's pattern (e.g. `payload: &[u8]`) — we
    // need its identifier to forward into `call_host_raw`.
    let arg_ident = match sig.inputs.first().unwrap() {
        syn::FnArg::Typed(pat_type) => match &*pat_type.pat {
            syn::Pat::Ident(pat_ident) => pat_ident.ident.clone(),
            _ => {
                return Error::new(
                    pat_type.pat.span(),
                    "expected a plain identifier pattern (e.g. `payload: &[u8]`)",
                )
                .to_compile_error()
                .into();
            }
        },
        syn::FnArg::Receiver(arg) => {
            return Error::new(arg.span(), "receiver (self) argument not allowed")
                .to_compile_error()
                .into();
        }
    };

    quote! {
        #(#attrs)*
        #vis #sig {
            #crate_name::host_comm::call_host_raw((#fn_id_expr), #arg_ident)
                .expect("host function call failed")
        }
    }
    .into()
}
