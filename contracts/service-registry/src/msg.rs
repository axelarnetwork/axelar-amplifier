use axelar_wasm_std::nonempty;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Addr;
use msgs_derive::EnsurePermissions;
use router_api::ChainName;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::Verifier;

#[cw_serde]
pub struct InstantiateMsg {
    pub governance_account: String,
}
