use cosmwasm_std::CustomQuery;
use serde::{Deserialize, Serialize};

use crate::nexus;

#[non_exhaustive]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AxelarQueryMsg {
    Nexus(nexus::query::QueryMsg),
}

impl CustomQuery for AxelarQueryMsg {}

#[cfg(test)]
mod tests {
    use crate::nexus;
    use crate::query::AxelarQueryMsg;

    #[test]
    fn should_serialize_query_msg_correctly() {
        goldie::assert_json!(AxelarQueryMsg::Nexus(
            nexus::query::QueryMsg::TxHashAndNonce {}
        ));
    }
}
