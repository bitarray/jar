//! Derive Encode implementation.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields};

use crate::parse::{parse_field_attrs, parse_variant_attrs};

pub fn derive_encode_impl(input: &DeriveInput) -> syn::Result<TokenStream> {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let body = match &input.data {
        Data::Struct(data) => encode_struct_body(&data.fields)?,
        Data::Enum(data) => encode_enum_body(data)?,
        Data::Union(_) => return Err(syn::Error::new_spanned(name, "unions not supported")),
    };

    Ok(quote! {
        impl #impl_generics scale::Encode for #name #ty_generics #where_clause {
            fn encode_to(&self, buf: &mut Vec<u8>) {
                #body
            }
        }
    })
}

fn encode_struct_body(fields: &Fields) -> syn::Result<TokenStream> {
    match fields {
        Fields::Named(named) => {
            let mut stmts = Vec::new();
            for field in &named.named {
                let attrs = parse_field_attrs(&field.attrs)?;
                if attrs.skip {
                    continue;
                }
                let ident = field.ident.as_ref().unwrap();
                stmts.push(quote! {
                    scale::Encode::encode_to(&self.#ident, buf);
                });
            }
            Ok(quote! { #(#stmts)* })
        }
        Fields::Unnamed(unnamed) => {
            let mut stmts = Vec::new();
            for (i, field) in unnamed.unnamed.iter().enumerate() {
                let attrs = parse_field_attrs(&field.attrs)?;
                if attrs.skip {
                    continue;
                }
                let idx = syn::Index::from(i);
                stmts.push(quote! {
                    scale::Encode::encode_to(&self.#idx, buf);
                });
            }
            Ok(quote! { #(#stmts)* })
        }
        Fields::Unit => Ok(quote! {}),
    }
}

fn encode_enum_body(data: &syn::DataEnum) -> syn::Result<TokenStream> {
    let mut arms = Vec::new();
    for (default_idx, variant) in data.variants.iter().enumerate() {
        let vattrs = parse_variant_attrs(&variant.attrs)?;
        let idx = vattrs.index.unwrap_or(default_idx as u8);
        let vident = &variant.ident;

        match &variant.fields {
            Fields::Unit => {
                arms.push(quote! {
                    Self::#vident => {
                        buf.push(#idx);
                    }
                });
            }
            Fields::Unnamed(unnamed) => {
                let bindings: Vec<_> = (0..unnamed.unnamed.len())
                    .map(|i| syn::Ident::new(&format!("f{i}"), proc_macro2::Span::call_site()))
                    .collect();
                let encode_stmts: Vec<_> = bindings
                    .iter()
                    .zip(unnamed.unnamed.iter())
                    .filter_map(|(binding, field)| {
                        let attrs = parse_field_attrs(&field.attrs).ok()?;
                        if attrs.skip {
                            return None;
                        }
                        Some(quote! { scale::Encode::encode_to(#binding, buf); })
                    })
                    .collect();
                arms.push(quote! {
                    Self::#vident(#(#bindings),*) => {
                        buf.push(#idx);
                        #(#encode_stmts)*
                    }
                });
            }
            Fields::Named(named) => {
                let field_idents: Vec<_> = named
                    .named
                    .iter()
                    .map(|f| f.ident.as_ref().unwrap())
                    .collect();
                let encode_stmts: Vec<_> = named
                    .named
                    .iter()
                    .filter_map(|f| {
                        let attrs = parse_field_attrs(&f.attrs).ok()?;
                        if attrs.skip {
                            return None;
                        }
                        let ident = f.ident.as_ref().unwrap();
                        Some(quote! { scale::Encode::encode_to(#ident, buf); })
                    })
                    .collect();
                arms.push(quote! {
                    Self::#vident { #(#field_idents),* } => {
                        buf.push(#idx);
                        #(#encode_stmts)*
                    }
                });
            }
        }
    }

    Ok(quote! {
        match self {
            #(#arms)*
        }
    })
}
