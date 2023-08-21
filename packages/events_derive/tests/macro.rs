use error_stack::{Result, ResultExt};
use serde::Deserialize;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[events_derive::try_from("test_event")]
struct TestEvent {
    pub number: usize,
    pub text: String,
}

#[test]
fn fail_to_convert_incompatible_event() {
    let mut missing_attributes = serde_json::Map::new();
    missing_attributes.insert("number".to_string(), serde_json::to_value(10).unwrap());

    let incompatible_event = events::Event::Abci {
        event_type: "test_event".to_string(),
        attributes: missing_attributes,
    };

    let res: Result<TestEvent, events::Error> = incompatible_event.try_into();
    assert!(res.is_err_and(|err| matches!(
        err.current_context(),
        events::Error::DeserializationFailed(_, _)
    )));
}

#[test]
fn fail_to_convert_event_with_type_mismatch() {
    let mut complete_attributes = serde_json::Map::new();
    complete_attributes.insert("number".to_string(), serde_json::to_value(5).unwrap());
    complete_attributes.insert(
        "text".to_string(),
        serde_json::to_value("some text").unwrap(),
    );

    let mismatched_event = events::Event::Abci {
        event_type: "some_other_event".to_string(),
        attributes: complete_attributes.clone(),
    };

    let res: Result<TestEvent, events::Error> = mismatched_event.try_into();
    assert!(
        res.is_err_and(|err| matches!(err.current_context(), events::Error::EventTypeMismatch(_)))
    );
}

#[test]
fn convert_matching_event() {
    let mut complete_attributes = serde_json::Map::new();
    complete_attributes.insert("number".to_string(), serde_json::to_value(5).unwrap());
    complete_attributes.insert(
        "text".to_string(),
        serde_json::to_value("some text").unwrap(),
    );

    let correct_event = events::Event::Abci {
        event_type: "test_event".to_string(),
        attributes: complete_attributes,
    };

    let res: Result<TestEvent, events::Error> = correct_event.try_into();
    assert!(res.is_ok());
}
