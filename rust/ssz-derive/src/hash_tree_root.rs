//! Derive `ssz::HashTreeRoot`.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DataEnum, DeriveInput, Fields};

use crate::container::container_hash_root_expr;
use crate::parse::{parse_field_attrs, parse_variant_attrs};

pub fn derive_hash_tree_root_impl(input: &DeriveInput) -> syn::Result<TokenStream> {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    match &input.data {
        Data::Struct(data) => {
            // Newtype passthrough: forward to the inner field's hash.
            if let Fields::Unnamed(unnamed) = &data.fields
                && unnamed.unnamed.len() == 1
            {
                let field = &unnamed.unnamed[0];
                let attrs = parse_field_attrs(&field.attrs)?;
                if attrs.transparent {
                    let ty = &field.ty;
                    return Ok(quote! {
                        impl #impl_generics ssz::HashTreeRoot for #name #ty_generics #where_clause {
                            fn hash_tree_root<__D: ::digest::Digest<OutputSize = ::digest::typenum::U32>>(
                                &self,
                            ) -> [u8; 32] {
                                <#ty as ssz::HashTreeRoot>::hash_tree_root::<__D>(&self.0)
                            }
                        }
                    });
                }
            }
            hash_struct(name, &input.generics, &data.fields)
        }
        Data::Enum(data) => hash_enum(name, &input.generics, data),
        Data::Union(_) => Err(syn::Error::new_spanned(name, "unions not supported")),
    }
}

fn hash_struct(
    name: &syn::Ident,
    generics: &syn::Generics,
    fields: &Fields,
) -> syn::Result<TokenStream> {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    // Collect non-skip field types/accessors. Accessors are reference
    // expressions (`&self.foo`) so they're directly usable by the shared
    // container hash helper.
    let (accessors, tys): (Vec<TokenStream>, Vec<TokenStream>) = match fields {
        Fields::Named(named) => {
            let mut accs = Vec::new();
            let mut tys = Vec::new();
            for f in &named.named {
                let a = parse_field_attrs(&f.attrs)?;
                if a.skip {
                    continue;
                }
                let id = f.ident.as_ref().unwrap();
                let ty = &f.ty;
                accs.push(quote! { &self.#id });
                tys.push(quote! { #ty });
            }
            (accs, tys)
        }
        Fields::Unnamed(unnamed) => {
            let mut accs = Vec::new();
            let mut tys = Vec::new();
            for (i, f) in unnamed.unnamed.iter().enumerate() {
                let a = parse_field_attrs(&f.attrs)?;
                if a.skip {
                    continue;
                }
                let idx = syn::Index::from(i);
                let ty = &f.ty;
                accs.push(quote! { &self.#idx });
                tys.push(quote! { #ty });
            }
            (accs, tys)
        }
        Fields::Unit => (Vec::new(), Vec::new()),
    };

    let body = container_hash_root_expr(&accessors, &tys);

    Ok(quote! {
        impl #impl_generics ssz::HashTreeRoot for #name #ty_generics #where_clause {
            fn hash_tree_root<__D: ::digest::Digest<OutputSize = ::digest::typenum::U32>>(
                &self,
            ) -> [u8; 32] {
                #body
            }
        }
    })
}

fn hash_enum(
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
                // Unit variant: payload root = zero_hash(0); mix in selector.
                arms.push(quote! {
                    Self::#vident => {
                        ssz::mix_in_selector::<__D>([0u8; 32], #selector)
                    }
                });
            }
            Fields::Unnamed(unnamed) => {
                if unnamed.unnamed.is_empty() {
                    // `A()` — payload root = zero_hash(0).
                    arms.push(quote! {
                        Self::#vident() => {
                            ssz::mix_in_selector::<__D>([0u8; 32], #selector)
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
                    Self::#vident(__inner) => {
                        let __r = <#ty as ssz::HashTreeRoot>::hash_tree_root::<__D>(__inner);
                        ssz::mix_in_selector::<__D>(__r, #selector)
                    }
                });
            }
            Fields::Named(named) => {
                let idents: Vec<&syn::Ident> = named
                    .named
                    .iter()
                    .map(|f| f.ident.as_ref().unwrap())
                    .collect();
                let bind_pat = quote! { Self::#vident { #(#idents),* } };

                if idents.is_empty() {
                    // `A {}` — payload root = zero_hash(0).
                    arms.push(quote! {
                        #bind_pat => {
                            ssz::mix_in_selector::<__D>([0u8; 32], #selector)
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
                let accessors: Vec<TokenStream> = idents.iter().map(|id| quote! { #id }).collect();
                let payload = container_hash_root_expr(&accessors, &tys);
                arms.push(quote! {
                    #bind_pat => {
                        let __r = #payload;
                        ssz::mix_in_selector::<__D>(__r, #selector)
                    }
                });
            }
        }
    }

    Ok(quote! {
        impl #impl_generics ssz::HashTreeRoot for #name #ty_generics #where_clause {
            fn hash_tree_root<__D: ::digest::Digest<OutputSize = ::digest::typenum::U32>>(
                &self,
            ) -> [u8; 32] {
                match self {
                    #(#arms),*
                }
            }
        }
    })
}
