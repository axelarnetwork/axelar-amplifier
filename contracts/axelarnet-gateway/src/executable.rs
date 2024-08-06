use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, WasmMsg};
use router_api::{Address, CrossChainId};

#[cw_serde]
pub enum AxelarExecutableMsg {
    /// Execute the message at the destination contract with the corresponding payload, via the gateway.
    Execute {
        cc_id: CrossChainId,
        source_address: Address,
        payload: HexBinary,
    },
}

impl<'a> From<client::Client<'a, AxelarExecutableMsg, ()>> for AxelarExecutableClient<'a> {
    fn from(client: client::Client<'a, AxelarExecutableMsg, ()>) -> Self {
        AxelarExecutableClient { client }
    }
}

pub struct AxelarExecutableClient<'a> {
    client: client::Client<'a, AxelarExecutableMsg, ()>,
}

impl<'a> AxelarExecutableClient<'a> {
    pub fn execute(
        &self,
        cc_id: CrossChainId,
        source_address: Address,
        payload: HexBinary,
    ) -> WasmMsg {
        self.client.execute(&AxelarExecutableMsg::Execute {
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
                msg: to_json_binary(&AxelarExecutableMsg::Execute {
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
