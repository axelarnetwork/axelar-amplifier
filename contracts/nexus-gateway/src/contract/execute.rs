use connection_router::state::Message;
use cosmwasm_std::{Addr, Response};
use error_stack::ResultExt;

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
            _ => Err(ContractError::Unauthorized)?,
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

        for msg in &msgs {
            self.store.set_message_routed(&msg.cc_id)?;
        }

        let msgs = msgs
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<nexus::Message>>>()?;

        Ok(Response::new().add_messages(msgs))
    }
}

#[cfg(test)]
mod test {
    use hex::decode;

    use connection_router::state::{CrossChainId, Message};

    use crate::state::{Config, MockStore};

    use super::*;

    #[test]
    fn test_route_messages_unauthorized() {
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
    fn test_route_to_nexus_with_no_msg() {
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
    fn test_route_to_nexus_with_msgs_that_have_not_been_routed() {
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
                    id: "0xab550540ea222040733516376bef3b8dd564c1cc35144e123db3dc04d3bd2fe4:0"
                        .parse()
                        .unwrap(),
                },
                source_address: "0x05c0cada09A16b4e665894F688193050b67Cb860"
                    .parse()
                    .unwrap(),
                destination_address: "0xae0Ee0A63A2cE6BaeEFFE56e7714FB4EFE48D419"
                    .parse()
                    .unwrap(),
                destination_chain: "destinationChain".parse().unwrap(),
                payload_hash: decode(
                    "bb9b5566c2f4876863333e481f4698350154259ffe6226e283b16ce18a64bcf1",
                )
                .unwrap()
                .into(),
            },
            Message {
                cc_id: CrossChainId {
                    chain: "sourceChain".parse().unwrap(),
                    id: "0x5c25214402887813674e5be1922a58f60ea14400380ec7840c8c4fa064826b33:10"
                        .parse()
                        .unwrap(),
                },
                source_address: "0x635E6496D51514f0b64265db24e1FC4AEff70725"
                    .parse()
                    .unwrap(),
                destination_address: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD"
                    .parse()
                    .unwrap(),
                destination_chain: "destinationChain".parse().unwrap(),
                payload_hash: decode(
                    "bb9b5566c2f4876863333e481f4698350154259ffe6226e283b16ce18a64bcf1",
                )
                .unwrap()
                .into(),
            },
        ];
        let res = contract.route_messages(Addr::unchecked("router"), msgs);

        assert!(res.is_ok_and(|res| res.messages.len() == 2));
    }

    #[test]
    fn test_route_to_nexus_with_msgs_that_have_been_routed() {
        let mut store = MockStore::new();
        let config = Config {
            nexus: Addr::unchecked("nexus"),
            router: Addr::unchecked("router"),
        };
        store
            .expect_is_message_routed()
            .times(2)
            .returning(|_| Ok(true));
        let contract = Contract { store, config };

        let msgs = vec![
            Message {
                cc_id: CrossChainId {
                    chain: "sourceChain".parse().unwrap(),
                    id: "0xab550540ea222040733516376bef3b8dd564c1cc35144e123db3dc04d3bd2fe4:0"
                        .parse()
                        .unwrap(),
                },
                source_address: "0x05c0cada09A16b4e665894F688193050b67Cb860"
                    .parse()
                    .unwrap(),
                destination_address: "0xae0Ee0A63A2cE6BaeEFFE56e7714FB4EFE48D419"
                    .parse()
                    .unwrap(),
                destination_chain: "destinationChain".parse().unwrap(),
                payload_hash: decode(
                    "bb9b5566c2f4876863333e481f4698350154259ffe6226e283b16ce18a64bcf1",
                )
                .unwrap()
                .into(),
            },
            Message {
                cc_id: CrossChainId {
                    chain: "sourceChain".parse().unwrap(),
                    id: "0x5c25214402887813674e5be1922a58f60ea14400380ec7840c8c4fa064826b33:10"
                        .parse()
                        .unwrap(),
                },
                source_address: "0x635E6496D51514f0b64265db24e1FC4AEff70725"
                    .parse()
                    .unwrap(),
                destination_address: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD"
                    .parse()
                    .unwrap(),
                destination_chain: "destinationChain".parse().unwrap(),
                payload_hash: decode(
                    "bb9b5566c2f4876863333e481f4698350154259ffe6226e283b16ce18a64bcf1",
                )
                .unwrap()
                .into(),
            },
        ];
        let res = contract.route_messages(Addr::unchecked("router"), msgs);

        assert!(res.is_ok_and(|res| res.messages.is_empty()));
    }
}
