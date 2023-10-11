use connection_router::state::Message;
use cosmwasm_std::Response;
use error_stack::Result;

use crate::error::ContractError;
use crate::nexus;

pub fn route_to_nexus(msgs: Vec<Message>) -> Result<Response<nexus::Message>, ContractError> {
    let msgs = msgs
        .into_iter()
        .map(TryInto::try_into)
        .collect::<Result<Vec<nexus::Message>, _>>()?;

    Ok(Response::new().add_messages(msgs))
}

#[cfg(test)]
mod test {
    use hex::decode;

    use connection_router::state::{CrossChainId, Message};

    use super::*;

    #[test]
    fn test_route_to_nexus_with_no_msg() {
        let msgs = vec![];
        let res = route_to_nexus(msgs);

        assert!(res.is_ok_and(|res| res.messages.is_empty()))
    }

    #[test]
    fn test_route_to_nexus_with_msgs() {
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
                payload_hash: decode("deadbeef").unwrap().into(),
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
                payload_hash: decode("deadbeef").unwrap().into(),
            },
        ];
        let res = route_to_nexus(msgs);

        assert!(res.is_ok_and(|res| res.messages.len() == 2))
    }
}
