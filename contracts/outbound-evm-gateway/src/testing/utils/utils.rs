use cosmwasm_std::Event;
use cw_multi_test::AppResponse;
use serde::de;
use serde_json::from_str;

pub fn get_event<'a>(app_response: &'a AppResponse, event_name: &'a str) -> Option<&'a Event> {
    app_response
        .events
        .iter()
        .find(|event| event.ty == event_name)
}

pub fn get_event_attribute<'a>(event: &'a Event, attribute_name: &'a str) -> Option<&'a str> {
    event
        .attributes
        .iter()
        .find(|attribute| attribute.key == attribute_name)
        .map(|attribute| attribute.value.as_str())
}

pub fn get_event_attribute_value<'a, T>(event: &'a Event, attribute_name: &'a str) -> Option<T>
where
    T: de::Deserialize<'a>,
{
    let attribute = get_event_attribute(event, attribute_name);
    if attribute.is_none() {
        return None;
    }
    Some(from_str(attribute.unwrap()).unwrap())
}
