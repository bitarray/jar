//! Attribute parsing for `#[codec(...)]`.

use syn::{Attribute, Lit};

/// Parsed field attributes.
pub struct FieldAttrs {
    /// Skip this field during encode/decode.
    pub skip: bool,
}

/// Parsed variant attributes.
pub struct VariantAttrs {
    /// Explicit discriminant index.
    pub index: Option<u8>,
}

pub fn parse_field_attrs(attrs: &[Attribute]) -> syn::Result<FieldAttrs> {
    let mut skip = false;
    for attr in attrs {
        if !attr.path().is_ident("codec") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("skip") {
                skip = true;
                Ok(())
            } else {
                Err(meta.error("unknown codec attribute"))
            }
        })?;
    }
    Ok(FieldAttrs { skip })
}

pub fn parse_variant_attrs(attrs: &[Attribute]) -> syn::Result<VariantAttrs> {
    let mut index = None;
    for attr in attrs {
        if !attr.path().is_ident("codec") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("index") {
                let value = meta.value()?;
                let lit: Lit = value.parse()?;
                if let Lit::Int(lit_int) = lit {
                    index = Some(lit_int.base10_parse::<u8>()?);
                    Ok(())
                } else {
                    Err(meta.error("expected integer literal"))
                }
            } else {
                Err(meta.error("unknown codec attribute"))
            }
        })?;
    }
    Ok(VariantAttrs { index })
}
