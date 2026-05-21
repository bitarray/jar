//! Attribute parsing for `#[ssz(...)]`.

use syn::{Attribute, Lit};

/// Parsed field attributes.
pub struct FieldAttrs {
    /// Skip this field during encode/decode/hash.
    pub skip: bool,
    /// Newtype passthrough: forward the wrapping struct's traits to the
    /// single inner field (encoded/hashed identically).
    pub transparent: bool,
}

/// Parsed variant attributes.
pub struct VariantAttrs {
    /// Explicit union selector index.
    pub selector: Option<u8>,
}

pub fn parse_field_attrs(attrs: &[Attribute]) -> syn::Result<FieldAttrs> {
    let mut skip = false;
    let mut transparent = false;
    for attr in attrs {
        if !attr.path().is_ident("ssz") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("skip") {
                skip = true;
                Ok(())
            } else if meta.path.is_ident("transparent") {
                transparent = true;
                Ok(())
            } else {
                Err(meta.error("unknown ssz attribute"))
            }
        })?;
    }
    Ok(FieldAttrs { skip, transparent })
}

pub fn parse_variant_attrs(attrs: &[Attribute]) -> syn::Result<VariantAttrs> {
    let mut selector = None;
    for attr in attrs {
        if !attr.path().is_ident("ssz") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("selector") {
                let value = meta.value()?;
                let lit: Lit = value.parse()?;
                if let Lit::Int(lit_int) = lit {
                    selector = Some(lit_int.base10_parse::<u8>()?);
                    Ok(())
                } else {
                    Err(meta.error("expected integer literal"))
                }
            } else {
                Err(meta.error("unknown ssz attribute"))
            }
        })?;
    }
    Ok(VariantAttrs { selector })
}
