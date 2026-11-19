mod attributes;
mod decode;
mod encode;
mod row;
mod r#type;

pub use decode::expand_derive_decode;
pub use encode::expand_derive_encode;
pub use r#type::expand_derive_type;
pub use row::expand_derive_from_row;

use self::attributes::RenameAll;
use heck::{ToKebabCase, ToLowerCamelCase, ToShoutySnakeCase, ToSnakeCase, ToUpperCamelCase};
use proc_macro2::{Group, Ident, TokenStream, TokenTree};
use quote::{format_ident, quote, ToTokens};
use syn::{punctuated::Punctuated, token::Comma, DeriveInput, Variant};

pub fn expand_derive_type_encode_decode(input: &DeriveInput) -> syn::Result<TokenStream> {
    let encode_tts = expand_derive_encode(input)?;
    let decode_tts = expand_derive_decode(input)?;
    let type_tts = expand_derive_type(input)?;

    let combined = TokenStream::from_iter(encode_tts.into_iter().chain(decode_tts).chain(type_tts));

    Ok(combined)
}

pub(crate) fn rename_all(s: &str, pattern: RenameAll) -> String {
    match pattern {
        RenameAll::LowerCase => s.to_lowercase(),
        RenameAll::SnakeCase => s.to_snake_case(),
        RenameAll::UpperCase => s.to_uppercase(),
        RenameAll::ScreamingSnakeCase => s.to_shouty_snake_case(),
        RenameAll::KebabCase => s.to_kebab_case(),
        RenameAll::CamelCase => s.to_lower_camel_case(),
        RenameAll::PascalCase => s.to_upper_camel_case(),
    }
}

/// Returns an identifier for a field-less enum mirroring the variants of the given
/// `#[repr(..)]` enum, along with its definition.
///
/// This is used when one of the variants carries a payload (as required by `#[sqlx(other)]`):
/// such an enum can no longer be used in `as` casts (`Foo::Bar as i32`), so the discriminant of
/// each variant has to be read from a mirror that is always field-less.
///
/// The mirror repeats the original discriminant expressions verbatim, except that `Self` is
/// replaced by the original enum, as within the mirror `Self` would refer to the mirror itself.
pub(crate) fn enum_discriminants(
    ident: &Ident,
    repr: &Ident,
    variants: &Punctuated<Variant, Comma>,
) -> (Ident, TokenStream) {
    let shadow = format_ident!("__{}Discriminants", ident);

    let variants = variants.iter().map(|variant| {
        let id = &variant.ident;

        match &variant.discriminant {
            Some((_, expr)) => {
                let expr = replace_self(expr.to_token_stream(), ident);

                quote!(#id = #expr)
            }
            None => quote!(#id),
        }
    });

    let definition = quote!(
        #[repr(#repr)]
        #[allow(non_camel_case_types, dead_code)]
        enum #shadow {
            #(#variants),*
        }
    );

    (shadow, definition)
}

/// Replaces `Self` with the given identifier in the tokens of a discriminant expression.
fn replace_self(tokens: TokenStream, replacement: &Ident) -> TokenStream {
    tokens
        .into_iter()
        .map(|token| match token {
            TokenTree::Ident(ident) if ident == "Self" => TokenTree::Ident(replacement.clone()),
            TokenTree::Group(group) => {
                let stream = replace_self(group.stream(), replacement);

                let mut new_group = Group::new(group.delimiter(), stream);
                new_group.set_span(group.span());

                TokenTree::Group(new_group)
            }
            token => token,
        })
        .collect()
}
