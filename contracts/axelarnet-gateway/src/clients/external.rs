use axelar_wasm_std::address;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Deps, HexBinary, WasmMsg};
use router_api::{Address, CrossChainId};

/// `AxelarExecutableMsg` is a struct containing the args used by the axelarnet gateway to execute a destination contract on Axelar.
/// Each App needs to expose a `ExecuteMsg::Execute(AxelarExecutableMsg)` variant that only the gateway is allowed to call.
#[cw_serde]
pub struct AxelarExecutableMsg {
    pub cc_id: CrossChainId,
    pub source_address: Address,
    pub payload: HexBinary,
}

pub struct PayloadExecutor<'a> {
    client: client::Client<'a, AxelarExecutableMsg, ()>,
}

impl<'a> From<client::Client<'a, AxelarExecutableMsg, ()>> for PayloadExecutor<'a> {
    fn from(client: client::Client<'a, AxelarExecutableMsg, ()>) -> Self {
        PayloadExecutor { client }
    }
}

impl<'a> PayloadExecutor<'a> {
    pub fn new(deps: Deps<'a>, destination: &str) -> error_stack::Result<Self, address::Error> {
        let destination = address::validate_cosmwasm_address(deps.api, destination)?;
        Ok(PayloadExecutor {
            client: client::Client::new(deps.querier, destination),
        })
    }

    pub fn execute(
        &self,
        cc_id: CrossChainId,
        source_address: Address,
        payload: HexBinary,
    ) -> WasmMsg {
        self.client.execute(&AxelarExecutableMsg {
            cc_id,
            source_address,
            payload,
        })
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
        let client: PayloadExecutor =
            client::Client::new(QuerierWrapper::new(&querier), addr.clone()).into();

        let cc_id = CrossChainId::new("source-chain", "message-id").unwrap();
        let source_address: Address = "source-address".parse().unwrap();
        let payload = HexBinary::from(vec![1, 2, 3]);

        let msg = client.execute(cc_id.clone(), source_address.clone(), payload.clone());

        assert_eq!(
            msg,
            WasmMsg::Execute {
                contract_addr: addr.to_string(),
                msg: to_json_binary(&AxelarExecutableMsg {
                    cc_id,
                    source_address,
                    payload,
                })
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
