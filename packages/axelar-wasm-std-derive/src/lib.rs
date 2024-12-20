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

#[proc_macro_attribute]
pub fn into_event_derive(arg: TokenStream, input: TokenStream) -> TokenStream {
    let event_name = syn::parse_macro_input!(arg as syn::LitStr);
    let input = syn::parse_macro_input!(input as syn::ItemStruct);

    let event_struct = input.ident.clone();

    TokenStream::from(quote! {
        #input

        impl From<&#event_struct> for cosmwasm_std::Event {
            fn from(event: &#event_struct) -> Self {
                let attributes: Vec<_> = serde_json::to_value(event)
                    .expect("failed to serialize event")
                    .as_object()
                    .expect("event must be a json object")
                    .into_iter()
                    .map(|(key, value)| {
                        cosmwasm_std::Attribute::new(key, value.to_string())
                    })
                    .collect();

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
