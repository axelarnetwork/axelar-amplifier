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
/// use cosmwasm_std::Event;
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
/// let actual: Event = SomeEvents::SomeEmptyEvent.non_generic().into();
/// let expected = Event::new("some_empty_event");
/// assert_eq!(actual, expected);
///
/// let actual: Event = SomeEvents::SomeOtherEmptyEvent {}.non_generic().into();
/// let expected = Event::new("some_other_empty_event");
/// assert_eq!(actual, expected);
///
/// let actual: Event = SomeEvents::SomeEvent {
///     some_uint: 42,
///     some_string: "some string".to_string(),
///     some_bool: true,
///     some_object: SomeObject {
///         some_option: Some("some option".to_string()),
///         some_other_option: None,
///         some_vec: vec!["a".to_string(), "b".to_string()],
///         some_map: [("a".to_string(), "b".to_string()), ("c".to_string(), "d".to_string()), ("e".to_string(), "f".to_string())].into_iter().collect(),
///     },
/// }.non_generic().into();
/// let expected = Event::new("some_event")
///     .add_attribute("some_uint", "42")
///     .add_attribute("some_string", "\"some string\"")
///     .add_attribute("some_bool", "true")
///     .add_attribute("some_object", "{\"some_option\":\"some option\",\"some_other_option\":null,\"some_vec\":[\"a\",\"b\"],\"some_map\":{\"a\":\"b\",\"c\":\"d\",\"e\":\"f\"}}");
/// assert_eq!(actual, expected);
///
/// let actual: Event = SomeEvents::SomeGenericsEvent {
///     some_generics: "some generics".to_string(),
///     some_other_generics: 42,
/// }.into();
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
///
/// ```compile_fail
/// # use axelar_wasm_std_derive::IntoEvent;
///
/// # #[derive(IntoEvent)] // should not compile because the event enum has no variants
/// # enum SomeEmptyEvent {}
/// ```
///
/// ```compile_fail
/// # use axelar_wasm_std_derive::IntoEvent;
///
/// # #[derive(IntoEvent)] // should not compile because const generics are not supported
/// # enum SomeConstGenericEvent<const N: usize> {
/// #     SomeConstGenericEvent { some_array: [u8; N] },
/// # }
/// ```
///
/// ```compile_fail
/// # use axelar_wasm_std_derive::IntoEvent;
///
/// # #[derive(IntoEvent)] // should not compile because lifetime generics are not supported
/// # enum SomeLifetimeGenericEvent<'a> {
/// #     SomeLifetimeGenericEvent { some_str: &'a str },
/// # }
/// ```
///
/// ```compile_fail
/// # use axelar_wasm_std_derive::IntoEvent;
///
/// # #[derive(IntoEvent)]
/// # enum SomeEventWithoutGenerics {
/// #     SomeEvent
/// # }
///
/// # let _ = SomeEventWithoutGenerics::SomeEvent.non_generic(); // should not compile because the event enum has no generics
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

    let non_generic = impl_non_generic(&event_enum, &generics)?;
    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();

    Ok(quote! {
        #non_generic

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

fn impl_non_generic(event_enum: &Ident, generics: &Generics) -> Result<TokenStream2, syn::Error> {
    if generics.lifetimes().count() > 0 || generics.const_params().count() > 0 {
        return Err(syn::Error::new(
            Span::call_site(),
            "lifetimes and const generics are not supported",
        ));
    }

    let typed_generic_param_count = generics.type_params().count();
    if typed_generic_param_count == 0 {
        return Ok(quote! {});
    }

    let empties = (0..typed_generic_param_count).map(|_| quote! { cosmwasm_std::Empty });

    Ok(quote! {
        impl #event_enum<#(#empties), *> {
            pub fn non_generic(self) -> Self {
                self
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

#[proc_macro_attribute]
pub fn migrate_from_version(input: TokenStream, item: TokenStream) -> TokenStream {
    let base_version_req = syn::parse_macro_input!(input as syn::LitStr).value();
    let annotated_fn = syn::parse_macro_input!(item as syn::ItemFn);

    let fn_name = &annotated_fn.sig.ident;
    let fn_inputs = &annotated_fn.sig.inputs;
    let fn_output = &annotated_fn.sig.output;
    let fn_block = &annotated_fn.block;

    if fn_name != "migrate" {
        return syn::Error::new(
            fn_name.span(),
            "#[migrate_from_version] can only be applied to a 'migrate' function",
        )
        .to_compile_error()
        .into();
    }

    let deps = match deps_ident(&annotated_fn.sig) {
        Ok(deps) => deps,
        Err(e) => return e.to_compile_error().into(),
    };

    let gen = quote! {
        pub fn #fn_name(#fn_inputs) #fn_output {
            let old_version = semver::Version::parse(&cw2::get_contract_version(#deps.storage)?.version)?;
            let version_requirement = semver::VersionReq::parse(#base_version_req)?;
            assert!(version_requirement.matches(&old_version));

            let result = (|| {
                #fn_block
            })();

            cw2::set_contract_version(#deps.storage, env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))?;

            result
        }
    };

    gen.into()
}

fn deps_ident(sig: &syn::Signature) -> Result<syn::Ident, syn::Error> {
    let first_param = sig
        .inputs
        .first()
        .ok_or_else(|| syn::Error::new(sig.ident.span(), "missing parameters definition"))?;

    if let syn::FnArg::Typed(syn::PatType { ty, pat, .. }) = first_param {
        if let syn::Type::Path(syn::TypePath { path, .. }) = &**ty {
            if path.is_ident("DepsMut") {
                if let syn::Pat::Ident(pat_ident) = &**pat {
                    return Ok(pat_ident.ident.clone());
                }
            }
        }
    }

    Err(syn::Error::new(
        sig.ident.span(),
        "first parameter must be of type DepsMut",
    ))
}
