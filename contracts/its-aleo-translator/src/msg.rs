use aleo_gateway::network::NetworkConfig;
use cosmwasm_schema::cw_serde;

#[cw_serde]
pub struct InstantiateMsg {
    pub network: NetworkConfig,
}

pub type MigrateMsg = InstantiateMsg;
