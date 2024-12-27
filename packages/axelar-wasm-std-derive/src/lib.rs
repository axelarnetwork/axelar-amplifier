use std::iter;

use heck::ToSnakeCase;
use proc_macro::TokenStream;
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{DeriveInput, FieldsNamed, Variant};

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
/// enum SomeEvents {
///     SomeEmptyEvent,
///     SomeOtherEmptyEvent {},
///     SomeEvent {
///         some_uint: u64,
///         some_string: String,
///         some_bool: bool,
///         some_object: SomeObject,
///     },
/// }
///
/// let actual = cosmwasm_std::Event::from(SomeEvents::SomeEmptyEvent);
/// let expected = cosmwasm_std::Event::new("some_empty_event");
/// assert_eq!(actual, expected);
///
/// let actual = cosmwasm_std::Event::from(SomeEvents::SomeOtherEmptyEvent {});
/// let expected = cosmwasm_std::Event::new("some_other_empty_event");
/// assert_eq!(actual, expected);
///
/// let actual = cosmwasm_std::Event::from(SomeEvents::SomeEvent {
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
/// let expected = cosmwasm_std::Event::new("some_event")
///     .add_attribute("some_uint", "42")
///     .add_attribute("some_string", "\"some string\"")
///     .add_attribute("some_bool", "true")
///     .add_attribute("some_object", "{\"some_option\":\"some option\",\"some_other_option\":null,\"some_vec\":[\"a\",\"b\"],\"some_map\":{\"a\":\"b\",\"c\":\"d\",\"e\":\"f\"}}");
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
#[proc_macro_derive(IntoEvent)]
pub fn into_event(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::ItemEnum);
    let event_enum = input.ident.clone();

    let variant_matches: Result<Vec<_>, _> = input
        .variants
        .into_iter()
        .map(|variant| match &variant.fields {
            syn::Fields::Named(fields) => Ok(match_named_field(&event_enum, &variant, fields)),
            syn::Fields::Unit => Ok(match_uint_field(&event_enum, &variant)),
            syn::Fields::Unnamed(_) => Err(syn::Error::new(
                Span::call_site(),
                "unnamed fields are not supported",
            )),
        })
        .collect();
    let variant_matches = match variant_matches {
        Ok(variant_matches) => variant_matches,
        Err(err) => return err.to_compile_error().into(),
    };

    quote! {
        impl From<&#event_enum> for cosmwasm_std::Event {
            fn from(event: &#event_enum) -> Self {
                match event {
                    #(#variant_matches),*
                }
            }
        }

        impl From<#event_enum> for cosmwasm_std::Event {
            fn from(event: #event_enum) -> Self {
                (&event).into()
            }
        }
    }
    .into()
}

fn match_named_field(event_enum: &Ident, variant: &Variant, fields: &FieldsNamed) -> TokenStream2 {
    let variant_name = variant.ident.clone();
    let event_name = variant_name.to_string().to_snake_case();
    let field_names = fields
        .named
        .iter()
        .map(|field| field.ident.clone().expect("field must have a name"));

    let new_event = quote! {
        #event_enum::#variant_name { #(#field_names), * } => cosmwasm_std::Event::new(#event_name)
    };
    let add_attributes = fields.named.iter().map(|field| {
        let field_name = field.ident.clone().expect("field must have a name");
        let field_name_str = field_name.to_string();
        let attribute_name = field_name_str.to_snake_case();

        quote! {
            add_attribute(#attribute_name, serde_json::to_string(#field_name).expect(format!("failed to serialize event field {}", #field_name_str).as_str()))
        }
    });

    let results = iter::once(new_event).chain(add_attributes);

    quote! {
        #(#results).*
    }
}

fn match_uint_field(event_enum: &Ident, variant: &Variant) -> TokenStream2 {
    let variant_name = variant.ident.clone();
    let event_name = variant_name.to_string().to_snake_case();

    quote! {
        #event_enum::#variant_name => cosmwasm_std::Event::new(#event_name)
    }
}
