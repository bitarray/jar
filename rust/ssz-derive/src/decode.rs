//! Derive `ssz::Decode`.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DataEnum, DeriveInput, Fields};

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
                            fn from_ssz_bytes_in<__A: allocator_api2::alloc::Allocator + Clone>(
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
                    fn from_ssz_bytes_in<__A: allocator_api2::alloc::Allocator + Clone>(
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
    let off_idents: Vec<syn::Ident> = (0..n).map(|i| format_ident!("__off_{}", i)).collect();
    let tys: Vec<syn::Type> = active.iter().map(|(_, _, t)| t.clone()).collect();

    // Pass 1: walk fixed region, store fixed values immediately or offsets
    // for variable fields.
    let fixed_size_terms: Vec<TokenStream> = tys
        .iter()
        .map(|t| {
            quote! {
                if <#t as ssz::Decode>::is_ssz_fixed_len() {
                    <#t as ssz::Decode>::ssz_fixed_len()
                } else {
                    ssz::BYTES_PER_LENGTH_OFFSET
                }
            }
        })
        .collect();

    let pass1: Vec<TokenStream> = tys
        .iter()
        .zip(val_idents.iter())
        .zip(off_idents.iter())
        .map(|((ty, val), off)| {
            quote! {
                let mut #val: ::core::option::Option<#ty> = None;
                let mut #off: ::core::option::Option<usize> = None;
                if <#ty as ssz::Decode>::is_ssz_fixed_len() {
                    let __sz = <#ty as ssz::Decode>::ssz_fixed_len();
                    if __cursor + __sz > bytes.len() {
                        return Err(ssz::DecodeError::UnexpectedEof {
                            expected: __cursor + __sz,
                            actual: bytes.len(),
                        });
                    }
                    #val = Some(<#ty as ssz::Decode>::from_ssz_bytes_in(
                        &bytes[__cursor..__cursor + __sz], alloc.clone(),
                    )?);
                    __cursor += __sz;
                } else {
                    if __cursor + 4 > bytes.len() {
                        return Err(ssz::DecodeError::UnexpectedEof {
                            expected: __cursor + 4,
                            actual: bytes.len(),
                        });
                    }
                    let mut __ob = [0u8; 4];
                    __ob.copy_from_slice(&bytes[__cursor..__cursor + 4]);
                    #off = Some(u32::from_le_bytes(__ob) as usize);
                    __cursor += 4;
                }
            }
        })
        .collect();

    // Push variable offsets into a Vec (preserve declaration order).
    let push_var_offs: Vec<TokenStream> = tys
        .iter()
        .zip(off_idents.iter())
        .enumerate()
        .map(|(i, (ty, off))| {
            quote! {
                if !<#ty as ssz::Decode>::is_ssz_fixed_len() {
                    __var_positions.push((#i, #off.unwrap()));
                }
            }
        })
        .collect();

    // Pass 2: decode variable fields. We need the end of each variable
    // field's slice = next variable offset (or bytes.len()).
    let pass2: Vec<TokenStream> = tys
        .iter()
        .zip(val_idents.iter())
        .zip(off_idents.iter())
        .enumerate()
        .map(|(i, ((ty, val), off))| {
            quote! {
                if !<#ty as ssz::Decode>::is_ssz_fixed_len() {
                    let __start = #off.unwrap();
                    // Find this field in __var_positions and the next one's offset (or bytes.len()).
                    let __idx_in_var = __var_positions
                        .iter()
                        .position(|(j, _)| *j == #i)
                        .expect("variable field in var_positions");
                    let __end = if __idx_in_var + 1 < __var_positions.len() {
                        __var_positions[__idx_in_var + 1].1
                    } else {
                        bytes.len()
                    };
                    if __start > __end {
                        return Err(ssz::DecodeError::OffsetsNotMonotonic {
                            prev: __start, curr: __end,
                        });
                    }
                    #val = Some(<#ty as ssz::Decode>::from_ssz_bytes_in(
                        &bytes[__start..__end], alloc.clone(),
                    )?);
                }
            }
        })
        .collect();

    // Build struct init.
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
            let parts: Vec<TokenStream> = all.iter().map(|_| quote! { Default::default() }).collect();
            quote! { #name(#(#parts),*) }
        };
        quote! {
            let _ = bytes; let _ = alloc;
            Ok(#bind)
        }
    } else {
        quote! {
            let mut __cursor: usize = 0;
            let __fixed_size: usize = 0usize #(+ #fixed_size_terms)*;
            #(#pass1)*
            debug_assert_eq!(__cursor, __fixed_size);

            // Collect variable-field positions in declaration order.
            let mut __var_positions: allocator_api2::vec::Vec<(usize, usize)> = allocator_api2::vec::Vec::new();
            #(#push_var_offs)*
            // Validate monotonic and start at __fixed_size.
            for __pair in __var_positions.windows(2) {
                if __pair[1].1 < __pair[0].1 {
                    return Err(ssz::DecodeError::OffsetsNotMonotonic {
                        prev: __pair[0].1, curr: __pair[1].1,
                    });
                }
            }
            if let Some(&(_, __first)) = __var_positions.first() {
                if __first != __fixed_size {
                    return Err(ssz::DecodeError::InvalidOffset {
                        offset: __first, len: bytes.len(), fixed: __fixed_size,
                    });
                }
            } else {
                // No variable fields; verify no trailing bytes.
                if bytes.len() != __fixed_size {
                    return Err(ssz::DecodeError::TrailingBytes {
                        expected: __fixed_size, actual: bytes.len(),
                    });
                }
            }

            #(#pass2)*

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
            fn from_ssz_bytes_in<__A: allocator_api2::alloc::Allocator + Clone>(
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
            Fields::Named(_) => {
                return Err(syn::Error::new_spanned(
                    variant,
                    "SSZ Union variants with named fields not supported",
                ));
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
            fn from_ssz_bytes_in<__A: allocator_api2::alloc::Allocator + Clone>(
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
