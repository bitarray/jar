//! Derive `ssz::HashTreeRoot`.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DataEnum, DeriveInput, Fields};

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

    // Collect non-skip field accessor expressions.
    let accessors: Vec<TokenStream> = match fields {
        Fields::Named(named) => {
            let mut accs = Vec::new();
            for f in &named.named {
                let a = parse_field_attrs(&f.attrs)?;
                if a.skip {
                    continue;
                }
                let id = f.ident.as_ref().unwrap();
                accs.push(quote! { ssz::HashTreeRoot::hash_tree_root::<__D>(&self.#id) });
            }
            accs
        }
        Fields::Unnamed(unnamed) => {
            let mut accs = Vec::new();
            for (i, f) in unnamed.unnamed.iter().enumerate() {
                let a = parse_field_attrs(&f.attrs)?;
                if a.skip {
                    continue;
                }
                let idx = syn::Index::from(i);
                accs.push(quote! { ssz::HashTreeRoot::hash_tree_root::<__D>(&self.#idx) });
            }
            accs
        }
        Fields::Unit => Vec::new(),
    };

    let n = accessors.len();
    let body = if n == 0 {
        // Empty container → root is `zero_hash(0)`.
        quote! { [0u8; 32] }
    } else {
        quote! {
            let __roots: [[u8; 32]; #n] = [#(#accessors),*];
            ssz::merkleize::<__D>(&__roots, #n)
        }
    };

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
            Fields::Named(_) => {
                return Err(syn::Error::new_spanned(
                    variant,
                    "SSZ Union variants with named fields not supported",
                ));
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
