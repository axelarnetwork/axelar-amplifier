use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, HexBinary, QuerierWrapper, WasmMsg};
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
#[cw_serde]
enum ExecuteMsg {
    /// Execute the message at the destination contract with the corresponding payload.
    Execute(AxelarExecutableMsg),
}

pub struct Client<'a> {
    client: client::Client<'a, ExecuteMsg, ()>,
}

impl<'a> Client<'a> {
    pub fn new(querier: QuerierWrapper<'a>, destination: &'a Addr) -> Self {
        Client {
            client: client::Client::new(querier, destination),
        }
    }

    pub fn execute(&self, msg: AxelarExecutableMsg) -> WasmMsg {
        self.client.execute(&ExecuteMsg::Execute(msg))
    }
}

#[cfg(test)]
mod test {
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::{to_json_binary, Addr, HexBinary, WasmMsg};
    use router_api::CrossChainId;

    use crate::clients::external;

    #[test]
    fn execute_message() {
        let deps = mock_dependencies();

        let destination_addr = Addr::unchecked("axelar-executable");

        let executable_msg = external::AxelarExecutableMsg {
            source_address: "source-address".parse().unwrap(),
            payload: HexBinary::from(vec![1, 2, 3]),
            cc_id: CrossChainId::new("source-chain", "message-id").unwrap(),
        };

        let client = external::Client::new(deps.as_ref().querier, &destination_addr);

        assert_eq!(
            client.execute(executable_msg.clone()),
            WasmMsg::Execute {
                contract_addr: destination_addr.to_string(),
                msg: to_json_binary(&external::ExecuteMsg::Execute(executable_msg)).unwrap(),
                funds: vec![],
            }
        );
    }
}
