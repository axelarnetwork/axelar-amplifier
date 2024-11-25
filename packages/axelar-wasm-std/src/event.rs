use cosmwasm_std::Event;

pub trait EventExt {
    fn add_attribute_if_some<K, V>(self, key: K, value: Option<V>) -> Self
    where
        K: Into<String>,
        V: Into<String>;
}

impl EventExt for Event {
    fn add_attribute_if_some<K, V>(self, key: K, value: Option<V>) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        match value {
            Some(value) => self.add_attribute(key, value),
            None => self,
        }
    }
}

#[cfg(test)]
mod test {
    use cosmwasm_std::{Event, Int128};

    use super::EventExt;

    #[test]
    fn add_attribute_if_some() {
        let event = Event::new("test")
            .add_attribute_if_some("foo", Some("bar"))
            .add_attribute_if_some("int", Some(Int128::new(3213)))
            .add_attribute_if_some("baz", None::<String>);

        goldie::assert_json!(event)
    }
}
