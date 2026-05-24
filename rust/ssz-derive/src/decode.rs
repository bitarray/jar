//! Derive `ssz::Decode`.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DataEnum, DeriveInput, Fields};

use crate::container::container_decode_body;
use crate::parse::{parse_field_attrs, parse_variant_attrs};

pub fn derive_decode_impl(input: &DeriveInput) -> syn::Result<TokenStream> {
    let name = &input.ident;

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
                    let (impl_generics, ty_generics, where_clause) =
                        input.generics.split_for_impl();
                    return Ok(quote! {
                        impl #impl_generics ssz::Decode for #name #ty_generics #where_clause {
                            fn is_ssz_fixed_len() -> bool {
                                <#ty as ssz::Decode>::is_ssz_fixed_len()
                            }
                            fn ssz_fixed_len() -> usize {
                                <#ty as ssz::Decode>::ssz_fixed_len()
                            }
                            fn from_ssz_bytes_in<__A: ::ssz::allocate::Allocator + Clone>(
                                bytes: &[u8],
                                alloc: __A,
                            ) -> Result<Self, ssz::DecodeError> {
                                Ok(#name(<#ty as ssz::Decode>::from_ssz_bytes_in(bytes, alloc)?))
                            }
                        }
                    });
                }
            }
            decode_struct(name, &input.generics, &data.fields)
        }
        Data::Enum(data) => decode_enum(name, &input.generics, data),
        Data::Union(_) => Err(syn::Error::new_spanned(name, "unions not supported")),
    }
}

#[derive(Clone)]
enum Acc {
    Named(syn::Ident),
    Unnamed,
}

fn decode_struct(
    name: &syn::Ident,
    generics: &syn::Generics,
    fields: &Fields,
) -> syn::Result<TokenStream> {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let mut all: Vec<(Acc, syn::Type, bool)> = Vec::new();
    let mut shape_named = true;
    match fields {
        Fields::Named(named) => {
            for f in &named.named {
                let attrs = parse_field_attrs(&f.attrs)?;
                all.push((
                    Acc::Named(f.ident.clone().unwrap()),
                    f.ty.clone(),
                    attrs.skip,
                ));
            }
        }
        Fields::Unnamed(unnamed) => {
            shape_named = false;
            for f in unnamed.unnamed.iter() {
                let attrs = parse_field_attrs(&f.attrs)?;
                all.push((Acc::Unnamed, f.ty.clone(), attrs.skip));
            }
        }
        Fields::Unit => {
            return Ok(quote! {
                impl #impl_generics ssz::Decode for #name #ty_generics #where_clause {
                    fn is_ssz_fixed_len() -> bool { true }
                    fn ssz_fixed_len() -> usize { 0 }
                    fn from_ssz_bytes_in<__A: ::ssz::allocate::Allocator + Clone>(
                        bytes: &[u8],
                        _alloc: __A,
                    ) -> Result<Self, ssz::DecodeError> {
                        if !bytes.is_empty() {
                            return Err(ssz::DecodeError::TrailingBytes {
                                expected: 0, actual: bytes.len(),
                            });
                        }
                        Ok(#name)
                    }
                }
            });
        }
    }

    // Non-skip fields participate in decode.
    let active: Vec<(usize, Acc, syn::Type)> = all
        .iter()
        .enumerate()
        .filter_map(|(i, (a, t, s))| {
            if *s {
                None
            } else {
                Some((i, a.clone(), t.clone()))
            }
        })
        .collect();

    // Compute is_ssz_fixed_len / ssz_fixed_len.
    let is_fixed = if active.is_empty() {
        quote! { true }
    } else {
        let parts = active.iter().map(|(_, _, t)| {
            quote! { <#t as ssz::Decode>::is_ssz_fixed_len() }
        });
        quote! { #(#parts)&&* }
    };
    let fixed_len = if active.is_empty() {
        quote! { 0usize }
    } else {
        let parts = active.iter().map(|(_, _, t)| {
            quote! {
                if <#t as ssz::Decode>::is_ssz_fixed_len() {
                    <#t as ssz::Decode>::ssz_fixed_len()
                } else {
                    ssz::BYTES_PER_LENGTH_OFFSET
                }
            }
        });
        quote! { 0usize #(+ #parts)* }
    };

    let n = active.len();
    let val_idents: Vec<syn::Ident> = (0..n).map(|i| format_ident!("__val_{}", i)).collect();
    let tys: Vec<TokenStream> = active.iter().map(|(_, _, t)| quote! { #t }).collect();

    // Map all-index → val ident (or None for skipped).
    let mut active_to_val: std::collections::BTreeMap<usize, syn::Ident> =
        std::collections::BTreeMap::new();
    for (active_pos, (orig_i, _, _)) in active.iter().enumerate() {
        active_to_val.insert(*orig_i, val_idents[active_pos].clone());
    }

    let init_body: TokenStream = if shape_named {
        let parts: Vec<TokenStream> = all
            .iter()
            .enumerate()
            .map(|(i, (acc, _, _))| match acc {
                Acc::Named(id) => {
                    if let Some(v) = active_to_val.get(&i) {
                        quote! { #id: #v.expect("decoded") }
                    } else {
                        quote! { #id: Default::default() }
                    }
                }
                _ => unreachable!(),
            })
            .collect();
        quote! { #name { #(#parts),* } }
    } else {
        let parts: Vec<TokenStream> = all
            .iter()
            .enumerate()
            .map(|(i, _)| {
                if let Some(v) = active_to_val.get(&i) {
                    quote! { #v.expect("decoded") }
                } else {
                    quote! { Default::default() }
                }
            })
            .collect();
        quote! { #name(#(#parts),*) }
    };

    let decode_body = if active.is_empty() {
        let bind = if shape_named {
            let parts: Vec<TokenStream> = all
                .iter()
                .map(|(a, _, _)| match a {
                    Acc::Named(id) => quote! { #id: Default::default() },
                    _ => unreachable!(),
                })
                .collect();
            quote! { #name { #(#parts),* } }
        } else {
            let parts: Vec<TokenStream> =
                all.iter().map(|_| quote! { Default::default() }).collect();
            quote! { #name(#(#parts),*) }
        };
        quote! {
            let _ = bytes; let _ = alloc;
            Ok(#bind)
        }
    } else {
        let body = container_decode_body(&tys);
        quote! {
            #body
            Ok(#init_body)
        }
    };

    Ok(quote! {
        impl #impl_generics ssz::Decode for #name #ty_generics #where_clause {
            fn is_ssz_fixed_len() -> bool {
                #is_fixed
            }
            fn ssz_fixed_len() -> usize {
                #fixed_len
            }
            fn from_ssz_bytes_in<__A: ::ssz::allocate::Allocator + Clone>(
                bytes: &[u8],
                alloc: __A,
            ) -> Result<Self, ssz::DecodeError> {
                #decode_body
            }
        }
    })
}

fn decode_enum(
    name: &syn::Ident,
    generics: &syn::Generics,
    data: &DataEnum,
) -> syn::Result<TokenStream> {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let mut arms = Vec::new();

    for (default_idx, variant) in data.variants.iter().enumerate() {
        let vattrs = parse_variant_attrs(&variant.attrs)?;
        let selector = vattrs.selector.unwrap_or(default_idx as u8);
        let vident = &variant.ident;

        match &variant.fields {
            Fields::Unit => {
                arms.push(quote! {
                    #selector => {
                        if bytes.len() != 1 {
                            return Err(ssz::DecodeError::TrailingBytes {
                                expected: 1, actual: bytes.len(),
                            });
                        }
                        Ok(#name::#vident)
                    }
                });
            }
            Fields::Unnamed(unnamed) => {
                if unnamed.unnamed.is_empty() {
                    // `A()` — selector only, no payload.
                    arms.push(quote! {
                        #selector => {
                            if bytes.len() != 1 {
                                return Err(ssz::DecodeError::TrailingBytes {
                                    expected: 1, actual: bytes.len(),
                                });
                            }
                            Ok(#name::#vident())
                        }
                    });
                    continue;
                }
                if unnamed.unnamed.len() != 1 {
                    return Err(syn::Error::new_spanned(
                        variant,
                        "SSZ Union variants must have exactly one unnamed field",
                    ));
                }
                let ty = &unnamed.unnamed[0].ty;
                arms.push(quote! {
                    #selector => {
                        let __payload = &bytes[1..];
                        Ok(#name::#vident(
                            <#ty as ssz::Decode>::from_ssz_bytes_in(__payload, alloc)?,
                        ))
                    }
                });
            }
            Fields::Named(named) => {
                let idents: Vec<&syn::Ident> = named
                    .named
                    .iter()
                    .map(|f| f.ident.as_ref().unwrap())
                    .collect();

                if idents.is_empty() {
                    // `A {}` — treat like a unit variant.
                    arms.push(quote! {
                        #selector => {
                            if bytes.len() != 1 {
                                return Err(ssz::DecodeError::TrailingBytes {
                                    expected: 1, actual: bytes.len(),
                                });
                            }
                            Ok(#name::#vident {})
                        }
                    });
                    continue;
                }

                let tys: Vec<TokenStream> = named
                    .named
                    .iter()
                    .map(|f| {
                        let ty = &f.ty;
                        quote! { #ty }
                    })
                    .collect();
                let n = idents.len();
                let val_idents: Vec<syn::Ident> =
                    (0..n).map(|i| format_ident!("__val_{}", i)).collect();
                let body = container_decode_body(&tys);
                let init_parts: Vec<TokenStream> = idents
                    .iter()
                    .zip(val_idents.iter())
                    .map(|(id, v)| quote! { #id: #v.expect("decoded") })
                    .collect();
                arms.push(quote! {
                    #selector => {
                        let bytes = &bytes[1..];
                        #body
                        Ok(#name::#vident { #(#init_parts),* })
                    }
                });
            }
        }
    }

    Ok(quote! {
        impl #impl_generics ssz::Decode for #name #ty_generics #where_clause {
            fn is_ssz_fixed_len() -> bool {
                false
            }
            fn ssz_fixed_len() -> usize {
                ssz::BYTES_PER_LENGTH_OFFSET
            }
            fn from_ssz_bytes_in<__A: ::ssz::allocate::Allocator + Clone>(
                bytes: &[u8],
                alloc: __A,
            ) -> Result<Self, ssz::DecodeError> {
                if bytes.is_empty() {
                    return Err(ssz::DecodeError::UnexpectedEof {
                        expected: 1, actual: 0,
                    });
                }
                match bytes[0] {
                    #(#arms)*
                    v => Err(ssz::DecodeError::InvalidSelector(v)),
                }
            }
        }
    })
}
