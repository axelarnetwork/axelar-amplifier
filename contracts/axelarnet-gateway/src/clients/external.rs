use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, CosmosMsg, Empty, HexBinary, QuerierWrapper};
use router_api::{Address, CrossChainId};

/// `AxelarExecutableMsg` is a struct containing the args used by the axelarnet gateway to execute a destination contract on Axelar.
/// Each App needs to expose a `ExecuteMsg::Execute(AxelarExecutableMsg)` variant that only the gateway is allowed to call.
#[cw_serde]
pub struct AxelarExecutableMsg {
    pub cc_id: CrossChainId,
    pub source_address: Address,
    pub payload: HexBinary,
}

/// By convention, amplifier-compatible contracts must expose this `Execute` variant.
/// Due to identical json serialization, we can imitate it here so the gateway can call it.
#[cfg_attr(dylint_lib = "amplifier_lints", allow(ensure_msg_has_permissions))]
#[cw_serde]
enum ExecuteMsg {
    /// Execute the message at the destination contract with the corresponding payload.
    Execute(AxelarExecutableMsg),
}

pub struct Client<'a, T = Empty> {
    client: client::ContractClient<'a, ExecuteMsg, (), T>,
}

impl<'a, T> Client<'a, T> {
    pub fn new(querier: QuerierWrapper<'a>, destination: &'a Addr) -> Self {
        Client {
            client: client::ContractClient::new(querier, destination),
        }
    }

    pub fn execute(&self, msg: AxelarExecutableMsg) -> CosmosMsg<T> {
        self.client.execute(&ExecuteMsg::Execute(msg))
    }
}

#[cfg(test)]
mod test {
    use cosmwasm_std::testing::{mock_dependencies, MockApi};
    use cosmwasm_std::{to_json_binary, Empty, HexBinary, WasmMsg};
    use router_api::CrossChainId;

    use crate::clients::external;

    #[test]
    fn execute_message() {
        let deps = mock_dependencies();

        let destination_addr = MockApi::default().addr_make("axelar-executable");

        let executable_msg = external::AxelarExecutableMsg {
            source_address: "source-address".parse().unwrap(),
            payload: HexBinary::from(vec![1, 2, 3]),
            cc_id: CrossChainId::new("source-chain", "message-id").unwrap(),
        };

        let client: external::Client<'_, Empty> =
            external::Client::new(deps.as_ref().querier, &destination_addr);

        assert_eq!(
            client.execute(executable_msg.clone()),
            WasmMsg::Execute {
                contract_addr: destination_addr.to_string(),
                msg: to_json_binary(&external::ExecuteMsg::Execute(executable_msg)).unwrap(),
                funds: vec![],
            }
            .into()
        );
    }
}
