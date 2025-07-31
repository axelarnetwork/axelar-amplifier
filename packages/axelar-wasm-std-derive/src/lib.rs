use std::iter;

use heck::ToSnakeCase;
use itertools::Itertools;
use proc_macro::TokenStream;
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use quote::quote;
use syn::spanned::Spanned;
use syn::{DeriveInput, FieldsNamed, FieldsUnnamed, Generics, ItemEnum, Variant};

#[proc_macro_derive(IntoContractError)]
pub fn into_contract_error_derive(input: TokenStream) -> TokenStream {
    let ast: DeriveInput =
        syn::parse(input).expect("input for into_contract_error_derive should be valid");

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
///     },
///     SingleUnnamedValue(SomeObject),
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
///
/// // Example with single unnamed struct field
/// #[derive(serde::Serialize)]
/// struct Message {
///     id: String,
///     content: u64,
/// }
///
/// #[derive(IntoEvent)]
/// enum SingleUnnamedEvent {
///     SingleValue(Message),
/// }
///
/// let actual: Event = SingleUnnamedEvent::SingleValue(Message {
///     id: "msg-1".to_string(),
///     content: 42,
/// }).into();
/// let expected = Event::new("single_value")
///     .add_attribute("id", "\"msg-1\"")
///     .add_attribute("content", "42");
/// // Note: Attribute order may vary due to HashMap iteration, so we check individual attributes
/// assert_eq!(actual.ty, expected.ty);
/// assert_eq!(actual.attributes.len(), expected.attributes.len());
/// for attr in &expected.attributes {
///     assert!(actual.attributes.iter().any(|a| a.key == attr.key && a.value == attr.value));
/// }
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
/// # #[derive(IntoEvent)] // should not compile because the event has unnamed fields with multiple elements
/// # enum SomeEventWithUnnamedField {
/// #     Uint,
/// #     Named { some_uint: u64 },
/// #     Unnamed(u64, String), // Multiple unnamed fields not allowed
/// # }
/// ```
///
/// ```compile_fail
/// # use axelar_wasm_std_derive::IntoEvent;
///
/// # #[derive(IntoEvent)] // should not compile because unnamed field must be a struct type
/// # enum SomeEventWithPrimitiveUnnamedField {
/// #     Uint,
/// #     Named { some_uint: u64 },
/// #     Unnamed(u64), // Primitive types not allowed in unnamed fields
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
    let variant_matches: Vec<TokenStream2> =
        variants
            .into_iter()
            .map(|variant| match variant.fields {
                syn::Fields::Named(fields) => Ok::<TokenStream2, syn::Error>(
                    match_structured_variant(&event_enum, &variant.ident, fields),
                ),
                syn::Fields::Unit => {
                    Ok::<TokenStream2, syn::Error>(match_unit_variant(&event_enum, &variant.ident))
                }
                syn::Fields::Unnamed(fields) => {
                    match_unnamed_variant(&event_enum, &variant.ident, fields)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
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

fn match_unnamed_variant(
    event_enum: &Ident,
    variant_name: &Ident,
    fields: FieldsUnnamed,
) -> Result<TokenStream2, syn::Error> {
    let event_name = variant_name.to_string().to_snake_case();

    if fields.unnamed.len() == 1 {
        let field_type = &fields.unnamed[0].ty;
        if !is_struct_type(field_type) {
            return Err(syn::Error::new(
                field_type.span(),
                "unnamed field must be a struct type that can be flattened",
            ));
        }

        let field_pattern = Ident::new("value", Span::call_site());
        let error_message = "failed to serialize event value";

        Ok(quote! {
            #event_enum::#variant_name(#field_pattern) => {
                let mut event = cosmwasm_std::Event::new(#event_name);
                let value_json = serde_json::to_value(#field_pattern).expect(#error_message);
                if let serde_json::Value::Object(map) = value_json {
                    for (key, value) in map {
                        event = event.add_attribute(key, value.to_string());
                    }
                }
                event
            }
        })
    } else {
        Err(syn::Error::new(
            variant_name.span(),
            "unnamed variants must have exactly one field",
        ))
    }
}

fn is_struct_type(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Path(syn::TypePath { path, .. }) => {
            // Check if it's a path that could be a struct
            // This is a simple heuristic - we assume any path type could be a struct
            // In practice, this will catch most struct types
            path.segments
                .last()
                .map(|segment| {
                    let ident = &segment.ident;
                    // Exclude primitive types
                    !matches!(
                        ident.to_string().as_str(),
                        "u8" | "u16"
                            | "u32"
                            | "u64"
                            | "u128"
                            | "usize"
                            | "i8"
                            | "i16"
                            | "i32"
                            | "i64"
                            | "i128"
                            | "isize"
                            | "f32"
                            | "f64"
                            | "bool"
                            | "char"
                            | "str"
                            | "String"
                    )
                })
                .unwrap_or(true)
        }
        syn::Type::Reference(syn::TypeReference { elem, .. }) => {
            // For references, check the inner type
            is_struct_type(elem)
        }
        _ => {
            // For other types (like arrays, tuples, etc.), assume they're not structs
            false
        }
    }
}

fn match_unit_variant(event_enum: &Ident, variant_name: &Ident) -> TokenStream2 {
    let event_name = variant_name.to_string().to_snake_case();

    quote! {
        #event_enum::#variant_name => cosmwasm_std::Event::new(#event_name)
    }
}

/// Attribute macro for handling contract version migrations. Must be applied to the `migrate` contract entry point.
/// Checks if migrating from the current version is supported and sets the new version. The base version must be a valid semver without patch, pre, or build.
///
/// # Example
/// ```
/// use cosmwasm_std::{ DepsMut, Env, Response, Empty};
/// use axelar_wasm_std_derive::migrate_from_version;
///
/// #[migrate_from_version("1.1")]
/// pub fn migrate(
///     deps: DepsMut,
///     _env: Env,
///     _msg: Empty,
/// ) -> Result<Response, axelar_wasm_std::error::ContractError> {
///     // migration logic
///     Ok(Response::default())
/// }
/// ```
///
/// ```compile_fail
/// # use cosmwasm_std::{ DepsMut, Env, Response, Empty};
/// # use axelar_wasm_std_derive::migrate_from_version;
///
/// # #[migrate_from_version("1.1")] // compilation error because the macro is not applied to a function `migrate`
/// # pub fn execute(
/// #     deps: DepsMut,
/// #     _env: Env,
/// #     _msg: Empty,
/// # ) -> Result<Response, axelar_wasm_std::error::ContractError> {
/// #     Ok(Response::default())
/// # }
/// ```
///
/// ```compile_fail
/// # use cosmwasm_std::{ Deps, Env, Response, Empty};
/// # use axelar_wasm_std_derive::migrate_from_version;
///
/// # #[migrate_from_version("1.1")] // compilation error because it cannot parse a `DepsMut` parameter
/// # pub fn migrate(
/// #     deps: Deps,
/// #     _env: Env,
/// #     _msg: Empty,
/// # ) -> Result<Response, axelar_wasm_std::error::ContractError> {
/// #     Ok(Response::default())
/// # }
/// ```
///
/// ```compile_fail
/// # use cosmwasm_std::{ DepsMut, Env, Response, Empty};
/// # use axelar_wasm_std_derive::migrate_from_version;
///
/// # #[migrate_from_version("~1.1.0")] // compilation error because the base version is not formatted correctly
/// # pub fn migrate(
/// #     deps: DepsMut,
/// #     _env: Env,
/// #     _msg: Empty,
/// # ) -> Result<Response, axelar_wasm_std::error::ContractError> {
/// #     Ok(Response::default())
/// # }
/// ```
///
#[proc_macro_attribute]
pub fn migrate_from_version(input: TokenStream, item: TokenStream) -> TokenStream {
    let base_version_req = syn::parse_macro_input!(input as syn::LitStr);
    let annotated_fn = syn::parse_macro_input!(item as syn::ItemFn);

    try_migrate_from_version(base_version_req, annotated_fn)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn try_migrate_from_version(
    base_version: syn::LitStr,
    annotated_fn: syn::ItemFn,
) -> syn::Result<TokenStream2> {
    let fn_name = &annotated_fn.sig.ident;
    let fn_inputs = &annotated_fn.sig.inputs;
    let fn_output = &annotated_fn.sig.output;
    let fn_block = &annotated_fn.block;

    let base_semver_req = base_semver_req(&base_version)?;
    let deps = validate_migrate_signature(&annotated_fn.sig)?;

    let gen = quote! {
        pub fn #fn_name(#fn_inputs) #fn_output {
            let pkg_name = env!("CARGO_PKG_NAME");
            let pkg_version = env!("CARGO_PKG_VERSION");

            let contract_version = cw2::get_contract_version(#deps.storage)?;
            assert_eq!(contract_version.contract, pkg_name, "contract name mismatch: actual {}, expected {}", contract_version.contract, pkg_name);

            let curr_version = semver::Version::parse(&contract_version.version)?;
            let version_requirement = semver::VersionReq::parse(#base_semver_req)?;
            assert!(version_requirement.matches(&curr_version), "base version {} does not match {} version requirement", curr_version, #base_semver_req);

            cw2::set_contract_version(#deps.storage, pkg_name, pkg_version)?;

            #fn_block
        }
    };

    Ok(gen)
}

fn base_semver_req(base_version: &syn::LitStr) -> syn::Result<String> {
    let base_semver = semver::Version::parse(&format!("{}.0", base_version.value()))
        .map_err(|_| syn::Error::new(base_version.span(), "base version format must be semver without patch, pre, or build. Example: '1.2'"))
        .and_then(|version| {
            if version.patch == 0 && version.pre.is_empty() && version.build.is_empty() {
                Ok(version)
            } else {
                Err(syn::Error::new(base_version.span(), "base version format must be semver without patch, pre, or build. Example: '1.2'"))
            }
        })?;

    Ok(format!("~{}.{}.0", base_semver.major, base_semver.minor))
}

fn validate_migrate_signature(sig: &syn::Signature) -> syn::Result<syn::Ident> {
    if sig.ident != "migrate"
        || sig.inputs.len() != 3
        || !matches!(sig.output, syn::ReturnType::Type(_, _))
    {
        return Err(syn::Error::new(
            sig.ident.span(),
            "invalid function signature for 'migrate' entry point",
        ));
    }

    validate_migrate_param(&sig.inputs[1], "Env")?;
    validate_migrate_param(&sig.inputs[0], "DepsMut")
}

fn validate_migrate_param(param: &syn::FnArg, expected_type: &str) -> syn::Result<syn::Ident> {
    let (ty, pat) = match param {
        syn::FnArg::Typed(syn::PatType { ty, pat, .. }) => (ty, pat),
        _ => {
            return Err(syn::Error::new(
                param.span(),
                format!(
                    "parameter for 'migrate' entry point expected to be of type {}",
                    expected_type
                ),
            ));
        }
    };
    match (&**ty, &**pat) {
        (syn::Type::Path(syn::TypePath { path, .. }), syn::Pat::Ident(pat_ident))
            if path.is_ident(expected_type) =>
        {
            Ok(pat_ident.ident.clone())
        }
        _ => Err(syn::Error::new(
            ty.span(),
            format!(
                "parameter for 'migrate' entry point expected to be of type {}",
                expected_type
            ),
        )),
    }
}
