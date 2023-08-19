use proc_macro::TokenStream;
use quote::quote;

#[proc_macro_attribute]
pub fn tryfrom(arg: TokenStream, input: TokenStream) -> TokenStream {
    let event_type = syn::parse_macro_input!(arg as syn::LitStr);
    let input = syn::parse_macro_input!(input as syn::ItemStruct);

    let event_struct = input.ident.clone();
    let event_struct_name = event_struct.to_string();

    TokenStream::from(quote! {
        #input

        use error_stack::{IntoReport as _, ResultExt as _};

        impl TryFrom<&events::Event> for #event_struct {
            type Error = error_stack::Report<events::Error>;

            fn try_from(event: &events::Event) -> core::result::Result<Self, Self::Error> {
                match event {
                    events::Event::Abci { event_type, attributes } if event_type.as_str() == #event_type => {
                        let event =
                            TestEvent::deserialize(serde::de::value::MapDeserializer::new(attributes.clone().into_iter()))
                                .into_report()
                                .change_context(events::Error::DeserializationFailed(
                                    #event_type.to_string(),
                                    #event_struct_name.to_string()),
                                )?;
                        Ok(event)
                    }
                    _ => Err(events::Error::EventTypeMismatch(#event_type.to_string())).into_report(),
                }
            }
        }

        impl TryFrom<events::Event> for TestEvent {
            type Error = error_stack::Report<events::Error>;

            fn try_from(event: events::Event) -> core::result::Result<Self, Self::Error> {
                Self::try_from(&event)
            }
        }
    })
}
