use super::attributes::{
    check_strong_enum_attributes, check_struct_attributes, check_transparent_attributes,
    check_weak_enum_attributes, parse_child_attributes, parse_container_attributes,
};
use super::{enum_discriminants, rename_all};
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::punctuated::Punctuated;
use syn::token::Comma;
use syn::{
    parse_quote, Data, DataEnum, DataStruct, DeriveInput, Expr, Field, Fields, FieldsNamed,
    Lifetime, LifetimeParam, Stmt, TypeParamBound, Variant,
};

pub fn expand_derive_encode(input: &DeriveInput) -> syn::Result<TokenStream> {
    let args = parse_container_attributes(&input.attrs)?;

    match &input.data {
        Data::Struct(DataStruct { fields, .. })
            if fields.len() == 1 && (matches!(fields, Fields::Unnamed(_)) || args.transparent) =>
        {
            expand_derive_encode_transparent(input, fields.iter().next().unwrap())
        }
        Data::Enum(DataEnum { variants, .. }) => match args.repr {
            Some(_) => expand_derive_encode_weak_enum(input, variants),
            None => expand_derive_encode_strong_enum(input, variants),
        },
        Data::Struct(DataStruct {
            fields: Fields::Named(FieldsNamed { named, .. }),
            ..
        }) => expand_derive_encode_struct(input, named),
        Data::Union(_) => Err(syn::Error::new_spanned(input, "unions are not supported")),
        Data::Struct(DataStruct {
            fields: Fields::Unnamed(..),
            ..
        }) => Err(syn::Error::new_spanned(
            input,
            "tuple structs may only have a single field",
        )),
        Data::Struct(DataStruct {
            fields: Fields::Unit,
            ..
        }) => Err(syn::Error::new_spanned(
            input,
            "unit structs are not supported",
        )),
    }
}

fn expand_derive_encode_transparent(
    input: &DeriveInput,
    field: &Field,
) -> syn::Result<TokenStream> {
    check_transparent_attributes(input, field)?;

    let ident = &input.ident;
    let ty = &field.ty;

    // extract type generics
    let generics = &input.generics;
    let (_, ty_generics, _) = generics.split_for_impl();

    // add db type for impl generics & where clause
    let lifetime = Lifetime::new("'q", Span::call_site());
    let mut generics = generics.clone();
    generics
        .params
        .insert(0, LifetimeParam::new(lifetime.clone()).into());

    generics
        .params
        .insert(0, parse_quote!(DB: ::sqlx::Database));
    generics
        .make_where_clause()
        .predicates
        .push(parse_quote!(#ty: ::sqlx::encode::Encode<#lifetime, DB>));
    let (impl_generics, _, where_clause) = generics.split_for_impl();

    let field_ident = if let Some(ident) = &field.ident {
        quote! { #ident }
    } else {
        quote! { 0 }
    };

    Ok(quote!(
        #[automatically_derived]
        impl #impl_generics ::sqlx::encode::Encode<#lifetime, DB> for #ident #ty_generics
        #where_clause
        {
            fn encode_by_ref(
                &self,
                buf: &mut <DB as ::sqlx::database::Database>::ArgumentBuffer,
            ) -> ::std::result::Result<::sqlx::encode::IsNull, ::sqlx::error::BoxDynError> {
                <#ty as ::sqlx::encode::Encode<#lifetime, DB>>::encode_by_ref(&self.#field_ident, buf)
            }

            fn produces(&self) -> Option<DB::TypeInfo> {
                <#ty as ::sqlx::encode::Encode<#lifetime, DB>>::produces(&self.#field_ident)
            }

            fn size_hint(&self) -> usize {
                <#ty as ::sqlx::encode::Encode<#lifetime, DB>>::size_hint(&self.#field_ident)
            }
        }
    ))
}

fn expand_derive_encode_weak_enum(
    input: &DeriveInput,
    variants: &Punctuated<Variant, Comma>,
) -> syn::Result<TokenStream> {
    let attr = check_weak_enum_attributes(input, variants)?;
    let repr = attr.repr.unwrap();
    let ident = &input.ident;

    let other_variant = variants
        .iter()
        .find(|variant| parse_child_attributes(&variant.attrs).is_ok_and(|a| a.other));

    // A variant marked `#[sqlx(other)]` carries a payload, which makes the enum ineligible for
    // `as` casts (`Self::Variant as #repr`), so the discriminants are read from a field-less
    // shadow enum mirroring the original's.
    let (discriminants, cast_target) = match other_variant {
        Some(_) => {
            let (shadow, definition) = enum_discriminants(ident, &repr, variants);

            (definition, shadow)
        }
        None => (TokenStream::new(), ident.clone()),
    };

    let mut values = Vec::new();

    for v in variants {
        let id = &v.ident;

        if parse_child_attributes(&v.attrs)?.other {
            // The variant captures an unrecognized value, so it is encoded back verbatim.
            values.push(quote!(#ident :: #id (value) => *value,));
        } else {
            values.push(quote!(#ident :: #id => (#cast_target::#id as #repr),));
        }
    }

    Ok(quote!(
        #[automatically_derived]
        impl<'q, DB: ::sqlx::Database> ::sqlx::encode::Encode<'q, DB> for #ident
        where
            #repr: ::sqlx::encode::Encode<'q, DB>,
        {
            fn encode_by_ref(
                &self,
                buf: &mut <DB as ::sqlx::database::Database>::ArgumentBuffer,
            ) -> ::std::result::Result<::sqlx::encode::IsNull, ::sqlx::error::BoxDynError> {
                #discriminants

                let value = match self {
                    #(#values)*
                };

                <#repr as ::sqlx::encode::Encode<DB>>::encode_by_ref(&value, buf)
            }

            fn size_hint(&self) -> usize {
                <#repr as ::sqlx::encode::Encode<DB>>::size_hint(&Default::default())
            }
        }
    ))
}

fn expand_derive_encode_strong_enum(
    input: &DeriveInput,
    variants: &Punctuated<Variant, Comma>,
) -> syn::Result<TokenStream> {
    let cattr = check_strong_enum_attributes(input, variants)?;

    let ident = &input.ident;

    let mut value_arms = Vec::new();
    let mut has_other = false;

    for v in variants {
        let id = &v.ident;
        let attributes = parse_child_attributes(&v.attrs)?;

        if attributes.other {
            // The variant captures an unrecognized value, so it is encoded back verbatim.
            has_other = true;
            value_arms.push(quote!(
                #ident :: #id (value) => ::std::convert::AsRef::<::std::primitive::str>::as_ref(value),
            ));
        } else if let Some(rename) = attributes.rename {
            value_arms.push(quote!(#ident :: #id => #rename,));
        } else if let Some(pattern) = cattr.rename_all {
            let name = rename_all(&id.to_string(), pattern);

            value_arms.push(quote!(#ident :: #id => #name,));
        } else {
            let name = id.to_string();
            value_arms.push(quote!(#ident :: #id => #name,));
        }
    }

    // Without `#[sqlx(other)]` the payload of every arm is a `&'static str`, so the bound and the
    // call can name `'q` directly, exactly as before. With it, the payload is borrowed from the
    // `self` reference, which doesn't live for `'q`, so both are relaxed to an inference-friendly
    // form.
    let (bound, encode, size_hint) = if has_other {
        (
            quote!(for<'a> &'a ::std::primitive::str: ::sqlx::encode::Encode<'a, DB>,),
            quote!(<&::std::primitive::str as ::sqlx::encode::Encode<'_, DB>>::encode(val, buf)),
            quote!(<&::std::primitive::str as ::sqlx::encode::Encode<'_, DB>>::size_hint(&val)),
        )
    } else {
        (
            quote!(&'q ::std::primitive::str: ::sqlx::encode::Encode<'q, DB>,),
            quote!(<&::std::primitive::str as ::sqlx::encode::Encode<'q, DB>>::encode(val, buf)),
            quote!(<&::std::primitive::str as ::sqlx::encode::Encode<'q, DB>>::size_hint(&val)),
        )
    };

    // Only the `other` arms borrow from `self`, so the annotation is likewise only needed then.
    let val_type = if has_other {
        quote!(: &::std::primitive::str)
    } else {
        TokenStream::new()
    };

    Ok(quote!(
        #[automatically_derived]
        impl<'q, DB: ::sqlx::Database> ::sqlx::encode::Encode<'q, DB> for #ident
        where
            #bound
        {
            fn encode_by_ref(
                &self,
                buf: &mut <DB as ::sqlx::database::Database>::ArgumentBuffer,
            ) -> ::std::result::Result<::sqlx::encode::IsNull, ::sqlx::error::BoxDynError> {
                let val #val_type = match self {
                    #(#value_arms)*
                };

                #encode
            }

            fn size_hint(&self) -> ::std::primitive::usize {
                let val #val_type = match self {
                    #(#value_arms)*
                };

                #size_hint
            }
        }
    ))
}

fn expand_derive_encode_struct(
    input: &DeriveInput,
    fields: &Punctuated<Field, Comma>,
) -> syn::Result<TokenStream> {
    check_struct_attributes(input, fields)?;

    let mut tts = TokenStream::new();

    if cfg!(feature = "postgres") {
        let ident = &input.ident;
        let column_count = fields.len();

        let (_, ty_generics, where_clause) = input.generics.split_for_impl();

        let mut generics = input.generics.clone();

        // add db type for impl generics & where clause
        for type_param in &mut generics.type_params_mut() {
            type_param.bounds.extend::<[TypeParamBound; 2]>([
                parse_quote!(for<'encode> ::sqlx::encode::Encode<'encode, ::sqlx::Postgres>),
                parse_quote!(::sqlx::types::Type<::sqlx::Postgres>),
            ]);
        }

        generics.params.push(parse_quote!('q));

        let (impl_generics, _, _) = generics.split_for_impl();

        let writes = fields.iter().map(|field| -> Stmt {
            let id = &field.ident;

            parse_quote!(
                encoder.encode(&self. #id)?;
            )
        });

        let sizes = fields.iter().map(|field| -> Expr {
            let id = &field.ident;
            let ty = &field.ty;

            parse_quote!(
                <#ty as ::sqlx::encode::Encode<::sqlx::Postgres>>::size_hint(&self. #id)
            )
        });

        tts.extend(quote!(
            #[automatically_derived]
            impl #impl_generics ::sqlx::encode::Encode<'_, ::sqlx::Postgres> for #ident #ty_generics
            #where_clause
            {
                fn encode_by_ref(
                    &self,
                    buf: &mut ::sqlx::postgres::PgArgumentBuffer,
                ) -> ::std::result::Result<::sqlx::encode::IsNull, ::sqlx::error::BoxDynError> {
                    let mut encoder = ::sqlx::postgres::types::PgRecordEncoder::new(buf);

                    #(#writes)*

                    encoder.finish();

                    ::std::result::Result::Ok(::sqlx::encode::IsNull::No)
                }

                fn size_hint(&self) -> ::std::primitive::usize {
                    #column_count * (4 + 4) // oid (int) and length (int) for each column
                        + #(#sizes)+* // sum of the size hints for each column
                }
            }
        ));
    }

    Ok(tts)
}
