//! Derive Decode implementation.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields};

use crate::parse::{parse_field_attrs, parse_variant_attrs};

pub fn derive_decode_impl(input: &DeriveInput) -> syn::Result<TokenStream> {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let body = match &input.data {
        Data::Struct(data) => decode_struct_body(name, &data.fields)?,
        Data::Enum(data) => decode_enum_body(name, data)?,
        Data::Union(_) => return Err(syn::Error::new_spanned(name, "unions not supported")),
    };

    Ok(quote! {
        impl #impl_generics scale::Decode for #name #ty_generics #where_clause {
            fn decode(__data: &[u8]) -> Result<(Self, usize), scale::DecodeError> {
                let mut off: usize = 0;
                #body
            }
        }
    })
}

fn decode_struct_body(name: &syn::Ident, fields: &Fields) -> syn::Result<TokenStream> {
    match fields {
        Fields::Named(named) => {
            let mut decode_stmts = Vec::new();
            let mut field_inits = Vec::new();

            for (i, field) in named.named.iter().enumerate() {
                let ident = field.ident.as_ref().unwrap();
                let ty = &field.ty;
                let attrs = parse_field_attrs(&field.attrs)?;
                let consumed =
                    syn::Ident::new(&format!("__consumed_{i}"), proc_macro2::Span::call_site());

                if attrs.skip {
                    field_inits.push(quote! { #ident: Default::default() });
                } else {
                    decode_stmts.push(quote! {
                        let (#ident, #consumed) = <#ty as scale::Decode>::decode(&__data[off..])?;
                        off += #consumed;
                    });
                    field_inits.push(quote! { #ident });
                }
            }

            Ok(quote! {
                #(#decode_stmts)*
                Ok((#name { #(#field_inits),* }, off))
            })
        }
        Fields::Unnamed(unnamed) => {
            let mut decode_stmts = Vec::new();
            let mut field_bindings = Vec::new();

            for (i, field) in unnamed.unnamed.iter().enumerate() {
                let binding = syn::Ident::new(&format!("f{i}"), proc_macro2::Span::call_site());
                let ty = &field.ty;
                let attrs = parse_field_attrs(&field.attrs)?;
                let consumed =
                    syn::Ident::new(&format!("__consumed_{i}"), proc_macro2::Span::call_site());

                if attrs.skip {
                    field_bindings.push(quote! { Default::default() });
                } else {
                    decode_stmts.push(quote! {
                        let (#binding, #consumed) = <#ty as scale::Decode>::decode(&__data[off..])?;
                        off += #consumed;
                    });
                    field_bindings.push(quote! { #binding });
                }
            }

            Ok(quote! {
                #(#decode_stmts)*
                Ok((#name(#(#field_bindings),*), off))
            })
        }
        Fields::Unit => Ok(quote! {
            Ok((#name, off))
        }),
    }
}

fn decode_enum_body(name: &syn::Ident, data: &syn::DataEnum) -> syn::Result<TokenStream> {
    let mut arms = Vec::new();

    for (default_idx, variant) in data.variants.iter().enumerate() {
        let vattrs = parse_variant_attrs(&variant.attrs)?;
        let idx = vattrs.index.unwrap_or(default_idx as u8);
        let vident = &variant.ident;

        let body = match &variant.fields {
            Fields::Unit => {
                quote! { Ok((#name::#vident, off)) }
            }
            Fields::Unnamed(unnamed) => {
                let mut decode_stmts = Vec::new();
                let mut field_bindings = Vec::new();

                for (i, field) in unnamed.unnamed.iter().enumerate() {
                    let binding = syn::Ident::new(&format!("f{i}"), proc_macro2::Span::call_site());
                    let ty = &field.ty;
                    let consumed =
                        syn::Ident::new(&format!("__consumed_{i}"), proc_macro2::Span::call_site());
                    decode_stmts.push(quote! {
                        let (#binding, #consumed) = <#ty as scale::Decode>::decode(&__data[off..])?;
                        off += #consumed;
                    });
                    field_bindings.push(quote! { #binding });
                }

                quote! {
                    #(#decode_stmts)*
                    Ok((#name::#vident(#(#field_bindings),*), off))
                }
            }
            Fields::Named(named) => {
                let mut decode_stmts = Vec::new();
                let mut field_inits = Vec::new();

                for (i, field) in named.named.iter().enumerate() {
                    let ident = field.ident.as_ref().unwrap();
                    let ty = &field.ty;
                    let consumed =
                        syn::Ident::new(&format!("__consumed_{i}"), proc_macro2::Span::call_site());
                    decode_stmts.push(quote! {
                        let (#ident, #consumed) = <#ty as scale::Decode>::decode(&__data[off..])?;
                        off += #consumed;
                    });
                    field_inits.push(quote! { #ident });
                }

                quote! {
                    #(#decode_stmts)*
                    Ok((#name::#vident { #(#field_inits),* }, off))
                }
            }
        };

        arms.push(quote! { #idx => { #body } });
    }

    Ok(quote! {
        if __data.is_empty() {
            return Err(scale::DecodeError::UnexpectedEof);
        }
        let discriminant = __data[off];
        off += 1;
        match discriminant {
            #(#arms)*
            v => Err(scale::DecodeError::InvalidDiscriminator(v)),
        }
    })
}
