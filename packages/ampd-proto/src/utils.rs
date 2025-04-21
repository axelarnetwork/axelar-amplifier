use std::collections::BTreeMap;
use std::fmt::Display;

use crate::proto::Event;

impl Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sorted_map: BTreeMap<_, _> = self.attributes.iter().collect();

        write!(
            f,
            "Event {{ type: {}, contract: {}, attributes: {} }}",
            self.r#type,
            self.contract,
            serde_json::to_string(&sorted_map).expect("attributes must be serializable")
        )
    }
}
