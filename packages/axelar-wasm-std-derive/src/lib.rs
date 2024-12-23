use proc_macro::TokenStream;
use quote::quote;
use syn::DeriveInput;

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

/// Derive macro to implement `From` for a struct to convert it into a `cosmwasm_std::Event`.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use serde::Serialize;
///
/// use axelar_wasm_std_derive::into_event_derive;
///
/// #[derive(Serialize)]
/// struct SomeObject {
///    pub some_option: Option<String>,
///    pub some_other_option: Option<String>,
///    pub some_vec: Vec<String>,
///    pub some_map: HashMap<String, String>,
/// }
///
/// #[derive(Serialize)]
/// #[into_event_derive("some_event")]
/// struct SomeEvent {
///     pub some_uint: u64,
///     pub some_string: String,
///     pub some_bool: bool,
///     pub some_object: SomeObject,
/// }
///
/// let event = SomeEvent {
///     some_uint: 42,
///     some_string: "string".to_string(),
///     some_bool: true,
///     some_object: SomeObject {
///         some_option: Some("some".to_string()),
///         some_other_option: None,
///         some_vec: vec!["a".to_string(), "b".to_string()],
///         some_map: [("a".to_string(), "b".to_string()), ("c".to_string(), "d".to_string()), ("e".to_string(), "f".to_string())].into_iter().collect(),
///     }
/// };
/// let actual_event = cosmwasm_std::Event::from(event);
/// let expected_event = cosmwasm_std::Event::new("some_event")
///     .add_attribute("some_bool", "true")
///     .add_attribute("some_object", r#"{"some_map":{"a":"b","c":"d","e":"f"},"some_option":"some","some_other_option":null,"some_vec":["a","b"]}"#)
///     .add_attribute("some_string", "\"string\"")
///     .add_attribute("some_uint", "42");
///
/// assert_eq!(actual_event, expected_event);
/// ```
#[proc_macro_attribute]
pub fn into_event_derive(arg: TokenStream, input: TokenStream) -> TokenStream {
    let event_name = syn::parse_macro_input!(arg as syn::LitStr);
    let input = syn::parse_macro_input!(input as syn::ItemStruct);

    let event_struct = input.ident.clone();

    TokenStream::from(quote! {
        #input

        impl From<&#event_struct> for cosmwasm_std::Event {
            fn from(event: &#event_struct) -> Self {
                let json_value = serde_json::to_value(event).expect("failed to serialize event");
                let attributes = json_value
                    .as_object()
                    .expect("event must be a json object")
                    .into_iter()
                    .map(|(key, value)| cosmwasm_std::Attribute::new(key, value.to_string()));

                cosmwasm_std::Event::new(#event_name.to_string()).add_attributes(attributes)
            }
        }

        impl From<#event_struct> for cosmwasm_std::Event {
            fn from(event: #event_struct) -> Self {
                (&event).into()
            }
        }
    })
}
