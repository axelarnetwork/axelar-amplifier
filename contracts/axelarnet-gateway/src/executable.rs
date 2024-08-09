use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, WasmMsg};
use router_api::{Address, CrossChainId};

/// `AxelarExecutableMsg` is a struct containing the args used by the axelarnet gateway to execute a destination contract on Axelar.
/// Each App needs to expose a `ExecuteMsg::Execute(AxelarExecutableMsg)` variant that only the gateway is allowed to call.
#[cw_serde]
pub struct AxelarExecutableMsg {
    pub cc_id: CrossChainId,
    pub source_address: Address,
    pub payload: HexBinary,
}

/// Crate-specific `ExecuteMsg` type wraps the `AxelarExecutableMsg` for the AxelarExecutable client.
#[cw_serde]
pub enum AxelarExecutableExecuteMsg {
    /// Execute the message at the destination contract with the corresponding payload.
    Execute(AxelarExecutableMsg),
}

impl<'a> From<client::Client<'a, AxelarExecutableExecuteMsg, ()>> for AxelarExecutableClient<'a> {
    fn from(client: client::Client<'a, AxelarExecutableExecuteMsg, ()>) -> Self {
        AxelarExecutableClient { client }
    }
}

pub struct AxelarExecutableClient<'a> {
    client: client::Client<'a, AxelarExecutableExecuteMsg, ()>,
}

impl<'a> AxelarExecutableClient<'a> {
    pub fn execute(
        &self,
        cc_id: CrossChainId,
        source_address: Address,
        payload: HexBinary,
    ) -> WasmMsg {
        self.client
            .execute(&AxelarExecutableExecuteMsg::Execute(AxelarExecutableMsg {
                cc_id,
                source_address,
                payload,
            }))
    }
}

#[cfg(test)]
mod test {
    use cosmwasm_std::testing::MockQuerier;
    use cosmwasm_std::{to_json_binary, Addr, QuerierWrapper};

    use super::*;

    #[test]
    fn execute_message() {
        let (querier, addr) = setup();
        let client: AxelarExecutableClient =
            client::Client::new(QuerierWrapper::new(&querier), addr.clone()).into();

        let cc_id = CrossChainId::new("source-chain", "message-id").unwrap();
        let source_address: Address = "source-address".parse().unwrap();
        let payload = HexBinary::from(vec![1, 2, 3]);

        let msg = client.execute(cc_id.clone(), source_address.clone(), payload.clone());

        assert_eq!(
            msg,
            WasmMsg::Execute {
                contract_addr: addr.to_string(),
                msg: to_json_binary(&AxelarExecutableExecuteMsg::Execute(AxelarExecutableMsg {
                    cc_id,
                    source_address,
                    payload,
                }))
                .unwrap(),
                funds: vec![],
            }
        );
    }

    fn setup() -> (MockQuerier, Addr) {
        let addr = Addr::unchecked("axelar-executable");

        let querier = MockQuerier::default();

        (querier, addr)
    }
}
