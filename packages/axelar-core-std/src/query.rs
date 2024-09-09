use cosmwasm_std::CustomQuery;
use serde::{Deserialize, Serialize};

use crate::nexus;

#[non_exhaustive]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum QueryMsg {
    Nexus(nexus::query::QueryMsg),
}

impl CustomQuery for QueryMsg {}

#[cfg(test)]
mod tests {
    use crate::nexus;
    use crate::query::QueryMsg;

    #[test]
    fn should_serialize_query_msg_correctly() {
        goldie::assert_json!(QueryMsg::Nexus(nexus::query::QueryMsg::TxHashAndNonce {}));
    }
}
