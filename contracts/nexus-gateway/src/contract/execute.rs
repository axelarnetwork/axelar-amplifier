use connection_router::state::Message;
use cosmwasm_std::{Addr, Response};
use error_stack::{report, ResultExt};

use crate::error::ContractError;
use crate::nexus;
use crate::state::Store;

use super::Contract;

type Result<T> = error_stack::Result<T, ContractError>;

impl<S> Contract<S>
where
    S: Store,
{
    pub fn route_messages(
        mut self,
        sender: Addr,
        msgs: Vec<Message>,
    ) -> Result<Response<nexus::Message>> {
        match sender {
            sender if sender == self.config.nexus => todo!(),
            sender if sender == self.config.router => self
                .route_to_nexus(msgs)
                .change_context(ContractError::RouteToNexus),
            _ => Err(report!(ContractError::Unauthorized)),
        }
    }

    fn route_to_nexus(&mut self, msgs: Vec<Message>) -> Result<Response<nexus::Message>> {
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

        let msgs = msgs
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<nexus::Message>>>()?;

        Ok(Response::new().add_messages(msgs))
    }
}

#[cfg(test)]
mod test {
    use connection_router::state::{CrossChainId, Message};

    use crate::state::{Config, MockStore};
    use hex::decode;

    use super::*;

    #[test]
    fn route_messages_unauthorized() {
        let store = MockStore::new();
        let config = Config {
            nexus: Addr::unchecked("nexus"),
            router: Addr::unchecked("router"),
        };
        let contract = Contract { store, config };

        let res = contract.route_messages(Addr::unchecked("unauthorized"), vec![]);

        assert!(res.is_err_and(|err| matches!(err.current_context(), ContractError::Unauthorized)));
    }

    #[test]
    fn route_to_nexus_with_no_msg() {
        let store = MockStore::new();
        let config = Config {
            nexus: Addr::unchecked("nexus"),
            router: Addr::unchecked("router"),
        };
        let contract = Contract { store, config };

        let res = contract.route_messages(Addr::unchecked("router"), vec![]);

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
            .expect_is_message_routed()
            .times(2)
            .returning(|_| Ok(false));
        store
            .expect_set_message_routed()
            .times(2)
            .returning(|_| Ok(()));
        let contract = Contract { store, config };

        let msgs = vec![
            Message {
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
            Message {
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
        let res = contract.route_messages(Addr::unchecked("router"), msgs);

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
        let contract = Contract { store, config };

        let msgs = vec![
            Message {
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
            Message {
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
        let res = contract.route_messages(Addr::unchecked("router"), msgs);

        assert!(res.is_ok_and(|res| res.messages.len() == 1));
    }
}
