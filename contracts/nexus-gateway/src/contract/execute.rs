use cosmwasm_std::{to_json_binary, Addr, Response, WasmMsg};
use error_stack::report;

use super::Contract;
use crate::error::ContractError;
use crate::nexus;
use crate::state::Store;

type Result<T> = error_stack::Result<T, ContractError>;

impl<S> Contract<S>
where
    S: Store,
{
    pub fn route_to_router(
        self,
        sender: Addr,
        msgs: Vec<nexus::Message>,
    ) -> Result<Response<nexus::Message>> {
        if sender != self.config.nexus {
            return Err(report!(ContractError::Unauthorized));
        }

        let msgs: Vec<_> = msgs
            .into_iter()
            .map(router_api::Message::try_from)
            .collect::<Result<Vec<_>>>()?;
        if msgs.is_empty() {
            return Ok(Response::default());
        }

        Ok(Response::new().add_message(WasmMsg::Execute {
            contract_addr: self.config.router.to_string(),
            msg: to_json_binary(&router_api::msg::ExecuteMsg::RouteMessages(msgs))
                .expect("must serialize route-messages message"),
            funds: vec![],
        }))
    }

    pub fn route_to_nexus(
        mut self,
        sender: Addr,
        msgs: Vec<router_api::Message>,
    ) -> Result<Response<nexus::Message>> {
        if sender != self.config.router {
            return Err(report!(ContractError::Unauthorized));
        }

        let msgs = msgs
            .into_iter()
            .filter_map(|msg| match self.store.is_message_routed(&msg.cc_id) {
                Ok(true) => None,
                Ok(false) => Some(Ok(msg)),
                Err(err) => Some(Err(err)),
            })
            .collect::<Result<Vec<_>>>()?;

        msgs.iter()
            .try_for_each(|msg| self.store.set_message_routed(&msg.cc_id))?;

        let msgs: Vec<nexus::Message> = msgs.into_iter().map(Into::into).collect();

        Ok(Response::new().add_messages(msgs))
    }
}

#[cfg(test)]
mod test {
    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use cosmwasm_std::{from_json, CosmosMsg};
    use hex::decode;
    use router_api::CrossChainId;

    use super::*;
    use crate::state::{Config, MockStore};

    #[test]
    fn route_to_router_unauthorized() {
        let mut store = MockStore::new();
        let config = Config {
            nexus: Addr::unchecked("nexus"),
            router: Addr::unchecked("router"),
        };
        store
            .expect_load_config()
            .returning(move || Ok(config.clone()));
        let contract = Contract::new(store);

        let res = contract.route_to_router(Addr::unchecked("unauthorized"), vec![]);

        assert!(res.is_err_and(|err| matches!(err.current_context(), ContractError::Unauthorized)));
    }

    #[test]
    fn route_to_router_with_no_msg() {
        let mut store = MockStore::new();
        let config = Config {
            nexus: Addr::unchecked("nexus"),
            router: Addr::unchecked("router"),
        };
        store
            .expect_load_config()
            .returning(move || Ok(config.clone()));
        let contract = Contract::new(store);

        let res = contract.route_to_router(Addr::unchecked("nexus"), vec![]);

        assert!(res.is_ok_and(|res| res.messages.is_empty()));
    }

    #[test]
    fn route_to_router_with_msgs() {
        let mut store = MockStore::new();
        let config = Config {
            nexus: Addr::unchecked("nexus"),
            router: Addr::unchecked("router"),
        };
        store
            .expect_load_config()
            .returning(move || Ok(config.clone()));
        let contract = Contract::new(store);

        let msg_ids = [
            HexTxHashAndEventIndex {
                tx_hash: vec![0x2f; 32].try_into().unwrap(),
                event_index: 100,
            },
            HexTxHashAndEventIndex {
                tx_hash: vec![0x23; 32].try_into().unwrap(),
                event_index: 1000,
            },
        ];
        let msgs = vec![
            nexus::Message {
                source_chain: "sourceChain".parse().unwrap(),
                source_address: "0xb860".parse().unwrap(),
                destination_address: "0xD419".parse().unwrap(),
                destination_chain: "destinationChain".parse().unwrap(),
                payload_hash: decode(
                    "bb9b5566c2f4876863333e481f4698350154259ffe6226e283b16ce18a64bcf1",
                )
                .unwrap()
                .try_into()
                .unwrap(),
                source_tx_id: msg_ids[0].tx_hash.to_vec().try_into().unwrap(),
                source_tx_index: msg_ids[0].event_index as u64,
                id: msg_ids[0].to_string(),
            },
            nexus::Message {
                source_chain: "sourceChain".parse().unwrap(),
                source_address: "0xc860".parse().unwrap(),
                destination_address: "0xA419".parse().unwrap(),
                destination_chain: "destinationChain".parse().unwrap(),
                payload_hash: decode(
                    "cb9b5566c2f4876853333e481f4698350154259ffe6226e283b16ce18a64bcf1",
                )
                .unwrap()
                .try_into()
                .unwrap(),
                source_tx_id: msg_ids[1].tx_hash.to_vec().try_into().unwrap(),
                source_tx_index: msg_ids[1].event_index as u64,
                id: msg_ids[1].to_string(),
            },
        ];
        let res = contract.route_to_router(Addr::unchecked("nexus"), msgs);

        assert!(res.is_ok_and(|res| {
            if res.messages.len() != 1 {
                return false;
            }

            match &res.messages[0].msg {
                CosmosMsg::Wasm(WasmMsg::Execute {
                    contract_addr,
                    msg,
                    funds,
                }) => {
                    if let Ok(router_api::msg::ExecuteMsg::RouteMessages(msgs)) = from_json(msg) {
                        return *contract_addr == Addr::unchecked("router")
                            && msgs.len() == 2
                            && funds.is_empty();
                    }

                    false
                }
                _ => false,
            }
        }));
    }

    #[test]
    fn route_to_nexus_unauthorized() {
        let mut store = MockStore::new();
        let config = Config {
            nexus: Addr::unchecked("nexus"),
            router: Addr::unchecked("router"),
        };
        store
            .expect_load_config()
            .returning(move || Ok(config.clone()));
        let contract = Contract::new(store);

        let res = contract.route_to_nexus(Addr::unchecked("unauthorized"), vec![]);

        assert!(res.is_err_and(|err| matches!(err.current_context(), ContractError::Unauthorized)));
    }

    #[test]
    fn route_to_nexus_with_no_msg() {
        let mut store = MockStore::new();
        let config = Config {
            nexus: Addr::unchecked("nexus"),
            router: Addr::unchecked("router"),
        };
        store
            .expect_load_config()
            .returning(move || Ok(config.clone()));
        let contract = Contract::new(store);

        let res = contract.route_to_nexus(Addr::unchecked("router"), vec![]);

        assert!(res.is_ok_and(|res| res.messages.is_empty()));
    }

    #[test]
    fn route_to_nexus_with_msgs_that_have_not_been_routed() {
        let mut store = MockStore::new();
        let config = Config {
            nexus: Addr::unchecked("nexus"),
            router: Addr::unchecked("router"),
        };
        store
            .expect_load_config()
            .returning(move || Ok(config.clone()));
        store
            .expect_is_message_routed()
            .times(2)
            .returning(|_| Ok(false));
        store
            .expect_set_message_routed()
            .times(2)
            .returning(|_| Ok(()));
        let contract = Contract::new(store);

        let msgs = vec![
            router_api::Message {
                cc_id: CrossChainId {
                    chain: "sourceChain".parse().unwrap(),
                    id: "0x2fe4:0".parse().unwrap(),
                },
                source_address: "0xb860".parse().unwrap(),
                destination_address: "0xD419".parse().unwrap(),
                destination_chain: "destinationChain".parse().unwrap(),
                payload_hash: decode(
                    "bb9b5566c2f4876863333e481f4698350154259ffe6226e283b16ce18a64bcf1",
                )
                .unwrap()
                .try_into()
                .unwrap(),
            },
            router_api::Message {
                cc_id: CrossChainId {
                    chain: "sourceChain".parse().unwrap(),
                    id: "0x6b33:10".parse().unwrap(),
                },
                source_address: "0x0725".parse().unwrap(),
                destination_address: "0x7FAD".parse().unwrap(),
                destination_chain: "destinationChain".parse().unwrap(),
                payload_hash: decode(
                    "bb9b5566c2f4876863333e481f4698350154259ffe6226e283b16ce18a64bcf1",
                )
                .unwrap()
                .try_into()
                .unwrap(),
            },
        ];
        let res = contract.route_to_nexus(Addr::unchecked("router"), msgs);

        assert!(res.is_ok_and(|res| res.messages.len() == 2));
    }

    #[test]
    fn route_to_nexus_with_msgs_that_have_been_routed() {
        let mut store = MockStore::new();
        let config = Config {
            nexus: Addr::unchecked("nexus"),
            router: Addr::unchecked("router"),
        };
        store
            .expect_load_config()
            .returning(move || Ok(config.clone()));
        store
            .expect_is_message_routed()
            .once()
            .returning(|_| Ok(false));
        store
            .expect_is_message_routed()
            .once()
            .returning(|_| Ok(true));
        store
            .expect_set_message_routed()
            .once()
            .returning(|_| Ok(()));
        let contract = Contract::new(store);

        let msgs = vec![
            router_api::Message {
                cc_id: CrossChainId {
                    chain: "sourceChain".parse().unwrap(),
                    id: "0x2fe4:0".parse().unwrap(),
                },
                source_address: "0xb860".parse().unwrap(),
                destination_address: "0xD419".parse().unwrap(),
                destination_chain: "destinationChain".parse().unwrap(),
                payload_hash: decode(
                    "bb9b5566c2f4876863333e481f4698350154259ffe6226e283b16ce18a64bcf1",
                )
                .unwrap()
                .try_into()
                .unwrap(),
            },
            router_api::Message {
                cc_id: CrossChainId {
                    chain: "sourceChain".parse().unwrap(),
                    id: "0x6b33:10".parse().unwrap(),
                },
                source_address: "0x70725".parse().unwrap(),
                destination_address: "0x7FAD".parse().unwrap(),
                destination_chain: "destinationChain".parse().unwrap(),
                payload_hash: decode(
                    "bb9b5566c2f4876863333e481f4698350154259ffe6226e283b16ce18a64bcf1",
                )
                .unwrap()
                .try_into()
                .unwrap(),
            },
        ];
        let res = contract.route_to_nexus(Addr::unchecked("router"), msgs);

        assert!(res.is_ok_and(|res| res.messages.len() == 1));
    }
}
