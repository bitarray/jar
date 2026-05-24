//! Derive `ssz::Encode`.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DataEnum, DeriveInput, Fields};

use crate::container::{container_bytes_len_expr, container_encode_body};
use crate::parse::{parse_field_attrs, parse_variant_attrs};

pub fn derive_encode_impl(input: &DeriveInput) -> syn::Result<TokenStream> {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    match &input.data {
        Data::Struct(data) => {
            // Check for `#[ssz(transparent)]` on the single field.
            if let Fields::Unnamed(unnamed) = &data.fields
                && unnamed.unnamed.len() == 1
            {
                let field = &unnamed.unnamed[0];
                let attrs = parse_field_attrs(&field.attrs)?;
                if attrs.transparent {
                    let ty = &field.ty;
                    return Ok(quote! {
                        impl #impl_generics ssz::Encode for #name #ty_generics #where_clause {
                            fn is_ssz_fixed_len() -> bool {
                                <#ty as ssz::Encode>::is_ssz_fixed_len()
                            }
                            fn ssz_fixed_len() -> usize {
                                <#ty as ssz::Encode>::ssz_fixed_len()
                            }
                            fn is_basic_type() -> bool {
                                <#ty as ssz::Encode>::is_basic_type()
                            }
                            fn ssz_bytes_len(&self) -> usize {
                                ssz::Encode::ssz_bytes_len(&self.0)
                            }
                            fn ssz_append<__A: ::ssz::allocate::Allocator + Clone>(
                                &self,
                                buf: &mut ::ssz::allocate::vec::Vec<u8, __A>,
                            ) {
                                ssz::Encode::ssz_append(&self.0, buf);
                            }
                        }
                    });
                }
            }
            encode_struct(name, &input.generics, &data.fields)
        }
        Data::Enum(data) => encode_enum(name, &input.generics, data),
        Data::Union(_) => Err(syn::Error::new_spanned(name, "unions not supported")),
    }
}

fn encode_struct(
    name: &syn::Ident,
    generics: &syn::Generics,
    fields: &Fields,
) -> syn::Result<TokenStream> {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    // Collect non-skip field types/accessors. Accessors are reference
    // expressions (`&self.foo` / `&self.0`) so they're directly usable by
    // the shared container helpers.
    let (field_tys, field_accessors): (Vec<TokenStream>, Vec<TokenStream>) = match fields {
        Fields::Named(named) => {
            let mut tys = Vec::new();
            let mut accs = Vec::new();
            for field in &named.named {
                let attrs = parse_field_attrs(&field.attrs)?;
                if attrs.skip {
                    continue;
                }
                let ident = field.ident.as_ref().unwrap();
                let ty = &field.ty;
                tys.push(quote! { #ty });
                accs.push(quote! { &self.#ident });
            }
            (tys, accs)
        }
        Fields::Unnamed(unnamed) => {
            let mut tys = Vec::new();
            let mut accs = Vec::new();
            for (i, field) in unnamed.unnamed.iter().enumerate() {
                let attrs = parse_field_attrs(&field.attrs)?;
                if attrs.skip {
                    continue;
                }
                let idx = syn::Index::from(i);
                let ty = &field.ty;
                tys.push(quote! { #ty });
                accs.push(quote! { &self.#idx });
            }
            (tys, accs)
        }
        Fields::Unit => (Vec::new(), Vec::new()),
    };

    // is_ssz_fixed_len: AND of all field is_ssz_fixed_len.
    let is_fixed = if field_tys.is_empty() {
        quote! { true }
    } else {
        let parts = field_tys.iter().map(|t| {
            quote! { <#t as ssz::Encode>::is_ssz_fixed_len() }
        });
        quote! { #(#parts)&&* }
    };

    // ssz_fixed_len: sum of field-level "fixed slot" sizes (offset-slot for variable).
    let fixed_len = if field_tys.is_empty() {
        quote! { 0usize }
    } else {
        let parts = field_tys.iter().map(|t| {
            quote! {
                if <#t as ssz::Encode>::is_ssz_fixed_len() {
                    <#t as ssz::Encode>::ssz_fixed_len()
                } else {
                    ssz::BYTES_PER_LENGTH_OFFSET
                }
            }
        });
        quote! { 0usize #(+ #parts)* }
    };

    let bytes_len = container_bytes_len_expr(&field_accessors, &field_tys);
    let append_body = container_encode_body(&field_accessors, &field_tys);

    Ok(quote! {
        impl #impl_generics ssz::Encode for #name #ty_generics #where_clause {
            fn is_ssz_fixed_len() -> bool {
                #is_fixed
            }
            fn ssz_fixed_len() -> usize {
                #fixed_len
            }
            fn ssz_bytes_len(&self) -> usize {
                #bytes_len
            }
            fn ssz_append<__A: ::ssz::allocate::Allocator + Clone>(
                &self,
                buf: &mut ::ssz::allocate::vec::Vec<u8, __A>,
            ) {
                #append_body
            }
        }
    })
}

fn encode_enum(
    name: &syn::Ident,
    generics: &syn::Generics,
    data: &DataEnum,
) -> syn::Result<TokenStream> {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let mut bytes_len_arms = Vec::new();
    let mut append_arms = Vec::new();

    for (default_idx, variant) in data.variants.iter().enumerate() {
        let vattrs = parse_variant_attrs(&variant.attrs)?;
        let selector = vattrs.selector.unwrap_or(default_idx as u8);
        let vident = &variant.ident;

        match &variant.fields {
            Fields::Unit => {
                bytes_len_arms.push(quote! { Self::#vident => 1 });
                append_arms.push(quote! {
                    Self::#vident => {
                        buf.push(#selector);
                    }
                });
            }
            Fields::Unnamed(unnamed) => {
                let bindings: Vec<syn::Ident> = (0..unnamed.unnamed.len())
                    .map(|i| format_ident!("f{}", i))
                    .collect();
                let tys: Vec<&syn::Type> = unnamed.unnamed.iter().map(|f| &f.ty).collect();
                let bind_pat = quote! { Self::#vident(#(#bindings),*) };
                let bytes_terms = bindings.iter().zip(tys.iter()).map(|(b, _t)| {
                    quote! { ssz::Encode::ssz_bytes_len(#b) }
                });
                let bytes_terms_clone: Vec<_> = bytes_terms.collect();
                bytes_len_arms.push(quote! {
                    #bind_pat => {
                        1 #(+ #bytes_terms_clone)*
                    }
                });

                let append_stmts = bindings.iter().zip(tys.iter()).map(|(b, _t)| {
                    quote! { ssz::Encode::ssz_append(#b, buf); }
                });
                append_arms.push(quote! {
                    #bind_pat => {
                        buf.push(#selector);
                        #(#append_stmts)*
                    }
                });
            }
            Fields::Named(named) => {
                // Variant payload is encoded as an anonymous SSZ container
                // of its named fields: fixed inline, variable via offset
                // table + appended payloads.
                let idents: Vec<&syn::Ident> = named
                    .named
                    .iter()
                    .map(|f| f.ident.as_ref().unwrap())
                    .collect();
                let tys: Vec<TokenStream> = named
                    .named
                    .iter()
                    .map(|f| {
                        let ty = &f.ty;
                        quote! { #ty }
                    })
                    .collect();
                let accessors: Vec<TokenStream> = idents.iter().map(|id| quote! { #id }).collect();

                let bind_pat = quote! { Self::#vident { #(#idents),* } };

                if idents.is_empty() {
                    // `A {}` — treat like a unit variant: selector only.
                    bytes_len_arms.push(quote! { #bind_pat => 1 });
                    append_arms.push(quote! {
                        #bind_pat => {
                            buf.push(#selector);
                        }
                    });
                    continue;
                }

                let bytes_inner = container_bytes_len_expr(&accessors, &tys);
                bytes_len_arms.push(quote! {
                    #bind_pat => {
                        1 + #bytes_inner
                    }
                });

                let body = container_encode_body(&accessors, &tys);
                append_arms.push(quote! {
                    #bind_pat => {
                        buf.push(#selector);
                        #body
                    }
                });
            }
        }
    }

    Ok(quote! {
        impl #impl_generics ssz::Encode for #name #ty_generics #where_clause {
            fn is_ssz_fixed_len() -> bool {
                false
            }
            fn ssz_fixed_len() -> usize {
                ssz::BYTES_PER_LENGTH_OFFSET
            }
            fn ssz_bytes_len(&self) -> usize {
                match self {
                    #(#bytes_len_arms),*
                }
            }
            fn ssz_append<__A: ::ssz::allocate::Allocator + Clone>(
                &self,
                buf: &mut ::ssz::allocate::vec::Vec<u8, __A>,
            ) {
                match self {
                    #(#append_arms),*
                }
            }
        }
    })
}
