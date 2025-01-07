use std::iter;

use heck::ToSnakeCase;
use itertools::Itertools;
use proc_macro::TokenStream;
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{DeriveInput, FieldsNamed, Generics, ItemEnum, Variant};

#[proc_macro_derive(IntoContractError)]
pub fn into_contract_error_derive(input: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(input).unwrap();

    let name = &ast.ident;

    let gen = quote! {
        impl From<#name> for axelar_wasm_std::error::ContractError {
            fn from(error: #name) -> Self {
                use error_stack::report;

                report!(error).into()
            }
        }
    };

    gen.into()
}

/// Derive macro to implement `From` for an enum to convert it into a `cosmwasm_std::Event`.
///
/// # Examples
///
/// ```
/// use std::collections::BTreeMap;
/// use serde::Serialize;
/// use cosmwasm_std::{Empty, Event};
///
/// use axelar_wasm_std_derive::IntoEvent;
///
/// #[derive(Serialize)]
/// struct SomeObject {
///    pub some_option: Option<String>,
///    pub some_other_option: Option<String>,
///    pub some_vec: Vec<String>,
///    pub some_map: BTreeMap<String, String>,
/// }
///
/// #[derive(IntoEvent)]
/// enum SomeEvents<T, U> where
/// T: Serialize,
/// U: Serialize
/// {
///     SomeEmptyEvent,
///     SomeOtherEmptyEvent {},
///     SomeEvent {
///         some_uint: u64,
///         some_string: String,
///         some_bool: bool,
///         some_object: SomeObject,
///     },
///     SomeGenericsEvent {
///         some_generics: T,
///         some_other_generics: U,
///     }
/// }
///
/// let actual = Event::from(SomeEvents::SomeEmptyEvent::<Empty, Empty>);
/// let expected = Event::new("some_empty_event");
/// assert_eq!(actual, expected);
///
/// let actual = Event::from(SomeEvents::SomeOtherEmptyEvent::<Empty, Empty> {});
/// let expected = Event::new("some_other_empty_event");
/// assert_eq!(actual, expected);
///
/// let actual = Event::from(SomeEvents::SomeEvent::<Empty, Empty> {
///     some_uint: 42,
///     some_string: "some string".to_string(),
///     some_bool: true,
///     some_object: SomeObject {
///         some_option: Some("some option".to_string()),
///         some_other_option: None,
///         some_vec: vec!["a".to_string(), "b".to_string()],
///         some_map: [("a".to_string(), "b".to_string()), ("c".to_string(), "d".to_string()), ("e".to_string(), "f".to_string())].into_iter().collect(),
///     },
/// });
/// let expected = Event::new("some_event")
///     .add_attribute("some_uint", "42")
///     .add_attribute("some_string", "\"some string\"")
///     .add_attribute("some_bool", "true")
///     .add_attribute("some_object", "{\"some_option\":\"some option\",\"some_other_option\":null,\"some_vec\":[\"a\",\"b\"],\"some_map\":{\"a\":\"b\",\"c\":\"d\",\"e\":\"f\"}}");
/// assert_eq!(actual, expected);
///
/// let actual = Event::from(SomeEvents::SomeGenericsEvent::<String, u64> {
///     some_generics: "some generics".to_string(),
///     some_other_generics: 42,
/// });
/// let expected = Event::new("some_generics_event")
///     .add_attribute("some_generics", "\"some generics\"")
///     .add_attribute("some_other_generics", "42");
/// assert_eq!(actual, expected);
/// ```
///
/// ```compile_fail
/// # use axelar_wasm_std_derive::IntoEvent;
///
/// # #[derive(IntoEvent)] // should not compile because the event is not an enum
/// # struct SomeStructEvent {
/// #    pub some_uint: u64,
/// # }
/// ```
///
/// ```compile_fail
/// # use axelar_wasm_std_derive::IntoEvent;
///
/// # #[derive(IntoEvent)] // should not compile because the event has some unnamed field
/// # enum SomeEventWithUnnamedField {
/// #     Uint,
/// #     Named { some_uint: u64 },
/// #     Unnamed(u64),
/// # }
/// ```
/// ```compile_fail
/// # use axelar_wasm_std_derive::IntoEvent;
///
/// # #[derive(IntoEvent)] // should not compile because the event enum has no variants
/// # enum SomeEmptyEvent {}
/// ```
#[proc_macro_derive(IntoEvent)]
pub fn into_event(input: TokenStream) -> TokenStream {
    let ItemEnum {
        variants,
        ident: event_enum,
        generics,
        ..
    } = syn::parse_macro_input!(input as syn::ItemEnum);

    try_into_event(event_enum, variants, generics)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn try_into_event(
    event_enum: Ident,
    variants: impl IntoIterator<Item = Variant>,
    generics: Generics,
) -> Result<TokenStream2, syn::Error> {
    let variant_matches: Vec<_> = variants
        .into_iter()
        .map(|variant| match variant.fields {
            syn::Fields::Named(fields) => Ok(match_structured_variant(
                &event_enum,
                &variant.ident,
                fields,
            )),
            syn::Fields::Unit => Ok(match_unit_variant(&event_enum, &variant.ident)),
            syn::Fields::Unnamed(_) => Err(syn::Error::new(
                Span::call_site(),
                "unnamed fields are not supported",
            )),
        })
        .try_collect()?;
    if variant_matches.is_empty() {
        return Err(syn::Error::new(Span::call_site(), "no variants found"));
    }

    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics From<&#event_enum #type_generics> for cosmwasm_std::Event #where_clause {
            fn from(event: &#event_enum #type_generics) -> Self {
                match event {
                    #(#variant_matches),*
                }
            }
        }

        impl #impl_generics From<#event_enum #type_generics> for cosmwasm_std::Event #where_clause {
            fn from(event: #event_enum #type_generics) -> Self {
                (&event).into()
            }
        }
    })
}

fn match_structured_variant(
    event_enum: &Ident,
    variant_name: &Ident,
    fields: FieldsNamed,
) -> TokenStream2 {
    let event_name = variant_name.to_string().to_snake_case();

    // we know these are named fields, so flat_map is a safe operation to get all the identifiers
    let field_names = fields
        .named
        .into_iter()
        .flat_map(|field| field.ident)
        .collect_vec();

    let new_event = quote! {
        #event_enum::#variant_name { #(#field_names), * } => cosmwasm_std::Event::new(#event_name)
    };

    let add_attributes = field_names.iter().map(|field_name| {
        let field_name_str = field_name.to_string();
        let attribute_name = field_name_str.to_snake_case();
        // compute the error message outside the quote! so the resulting string will be baked in at compile time
        let error_message = format!("failed to serialize event field {}", field_name_str);

        quote! {
            add_attribute(#attribute_name, serde_json::to_string(#field_name).expect(#error_message))
        }
    });

    let variant_pattern = iter::once(new_event).chain(add_attributes);

    quote! {
        #(#variant_pattern).*
    }
}

fn match_unit_variant(event_enum: &Ident, variant_name: &Ident) -> TokenStream2 {
    let event_name = variant_name.to_string().to_snake_case();

    quote! {
        #event_enum::#variant_name => cosmwasm_std::Event::new(#event_name)
    }
}
