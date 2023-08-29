use proc_macro::TokenStream;
use quote::quote;

/// Annotate a struct with this attribute to automatically implement [`TryFrom`][]`<&`[`events::Event`][]`>` and [`TryFrom`][]`<`[`events::Event`][]`>` for it.
/// The attribute must immediately precede the struct definition, i.e. no other attributes or doc comments are allowed in between.
///
/// # Example
/// ```
///use serde::Deserialize;
///
///use events::Event;
///
///#[derive(Deserialize)]
///#[events_derive::try_from("some_event")]
///struct SomeEvent {
///    pub some_field: usize,
///}
///
///# fn main() -> error_stack::Result<(), events::Error> {
///let event = Event::Abci {
///    event_type: "some_event".to_string(),
///    attributes: serde_json::Map::from_iter(
///        [("some_field".to_string(), serde_json::Value::from(5))].into_iter(),
///    ),
///};
///
///let typed_event = SomeEvent::try_from(event)?;
///
///#    Ok::<(), error_stack::Report<events::Error>>(())}
/// ```
#[proc_macro_attribute]
pub fn try_from(arg: TokenStream, input: TokenStream) -> TokenStream {
    let event_type = syn::parse_macro_input!(arg as syn::LitStr);
    let input = syn::parse_macro_input!(input as syn::ItemStruct);

    let event_struct = input.ident.clone();
    let event_struct_name = event_struct.to_string();

    TokenStream::from(quote! {
        #input

        use error_stack::{ResultExt as _};
        use events as _internal_events;
        use core::convert::TryFrom as _internal_TryFrom;

        impl _internal_TryFrom<&_internal_events::Event> for #event_struct {
            type Error = error_stack::Report<_internal_events::Error>;

            fn try_from(event: &_internal_events::Event) -> core::result::Result<Self, Self::Error> {
                match event {
                    _internal_events::Event::Abci { event_type, attributes } if event_type == #event_type => {
                        let event =
                            #event_struct::deserialize(serde::de::value::MapDeserializer::new(attributes.clone().into_iter()))
                                .change_context(_internal_events::Error::DeserializationFailed(
                                    #event_type.to_string(),
                                    #event_struct_name.to_string()),
                                )?;
                        Ok(event)
                    }
                    event => Err(_internal_events::Error::EventTypeMismatch(#event_type.to_string()))
                        .attach_printable(format!("{{ event = {event:?} }}")),
                }
            }
        }

        impl _internal_TryFrom<_internal_events::Event> for #event_struct {
            type Error = error_stack::Report<_internal_events::Error>;

            fn try_from(event: _internal_events::Event) -> core::result::Result<Self, Self::Error> {
                Self::try_from(&event)
            }
        }
    })
}
