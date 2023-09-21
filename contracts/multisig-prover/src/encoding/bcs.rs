use bcs::to_bytes;
use cosmwasm_std::{HexBinary, Uint256};
use itertools::Itertools;

use crate::{error::ContractError, types::CommandBatch};

use super::Data;

use sha3::{Digest, Keccak256};

pub fn command_params(
    source_chain: String,
    source_address: String,
    destination_address: String,
    payload_hash: HexBinary,
) -> Result<HexBinary, ContractError> {
    assert!(
        destination_address.len() == 64,
        "destination_address ({}) is not 32 bytes",
        destination_address
    );
    let ret = to_bytes(&(
        source_chain,
        source_address,
        <[u8; 32]>::try_from(&HexBinary::from_hex(&destination_address)?.to_vec()[..32])
            .expect("couldn't convert destination_address to 32 byte array"),
        payload_hash.to_vec(),
    ))?;

    Ok(ret.into())
}

// destination chain id must be u64 for sui
fn chain_id_as_u64(chain_id: Uint256) -> u64 {
    assert!(
        chain_id <= Uint256::from(u64::MAX),
        "chain_id ({}) is greater than u64 max",
        chain_id
    );
    u64::from_le_bytes(
        chain_id.to_le_bytes()[..8]
            .try_into()
            .expect("Couldn't convert u256 to u64"),
    )
}

pub fn encode(data: &Data) -> HexBinary {
    let destination_chain_id = chain_id_as_u64(data.destination_chain_id);

    let (commands_ids, command_types, command_params): (Vec<[u8; 32]>, Vec<String>, Vec<Vec<u8>>) =
        data.commands
            .iter()
            .map(|command| {
                assert!(
                    command.id.len() == 32,
                    "command.id ({}) is not 32 bytes",
                    command.id
                );
                (
                    <[u8; 32]>::try_from(&command.id.to_vec()[..32])
                        .expect("couldn't convert command id to 32 byte array"), // command-ids are fixed length sequences
                    command.ty.to_string(),
                    command.params.to_vec(),
                )
            })
            .multiunzip();

    to_bytes(&(
        destination_chain_id,
        commands_ids,
        command_types,
        command_params,
    ))
    .expect("couldn't encode batch as bcs")
    .into()
}

pub fn msg_digest(command_batch: &CommandBatch) -> HexBinary {
    let msg = Keccak256::digest(encode(&command_batch.data).as_slice());

    // Sui is just mimicking EVM here
    let unsigned = [
        "\x19Sui Signed Message:\n32".as_bytes(), // Keccek256 hash length = 32
        msg.as_slice(),
    ]
    .concat();

    Keccak256::digest(unsigned).as_slice().into()
}

#[cfg(test)]
mod test {

    use std::vec;

    use bcs::from_bytes;
    use connection_router::msg::Message;
    use cosmwasm_std::{HexBinary, Uint256};

    use crate::{encoding::{
        bcs::{chain_id_as_u64, command_params, encode},
        CommandBatchBuilder, Data,
    }, types::Command};

    use super::msg_digest;

    #[test]
    fn test_chain_id_as_u64() {
        let chain_id = 1u64;
        assert_eq!(chain_id, chain_id_as_u64(Uint256::from(chain_id as u128)));
    }
    #[test]
    #[should_panic]
    fn test_chain_id_as_u64_fails() {
        let chain_id = u128::MAX;
        chain_id_as_u64(Uint256::from(chain_id));
    }

    #[test]
    fn test_command_params() {
        let res = command_params(
            "Ethereum".into(),
            "00".into(),
            "01".repeat(32).into(),
            HexBinary::from_hex("02").unwrap(),
        );
        assert!(res.is_ok());

        let res = res.unwrap();
        let params = from_bytes(&res.to_vec());
        assert!(params.is_ok());
        let (source_chain, source_address, destination_address, payload_hash): (
            String,
            String,
            [u8; 32],
            Vec<u8>,
        ) = params.unwrap();
        assert_eq!(source_chain, "Ethereum".to_string());

        assert_eq!(source_address, "00".to_string());

        assert_eq!(
            destination_address.to_vec(),
            HexBinary::from_hex(&"01".repeat(32)).unwrap().to_vec()
        );

        assert_eq!(payload_hash, vec![2]);
    }

    #[test]
    #[should_panic]
    fn test_invalid_destination_address() {
        let _ = command_params(
            "Ethereum".into(),
            "00".into(),
            "01".into(),
            HexBinary::from_hex("02").unwrap(),
        );
    }

    #[test]
    fn test_encode() {
        let source_chain = "Ethereum";
        let source_address = "AA";
        let destination_address = "BB".repeat(32);
        let payload_hash = HexBinary::from_hex("CC").unwrap();
        let destination_chain_id = 1u64;
        let command_id = HexBinary::from_hex(&"FF".repeat(32)).unwrap();
        let data = Data {
            destination_chain_id: destination_chain_id.into(),
            commands: vec![Command {
                id: command_id.clone(),
                ty: crate::types::CommandType::ApproveContractCall,
                params: command_params(
                    source_chain.into(),
                    source_address.into(),
                    destination_address.clone().into(),
                    payload_hash.clone().into(),
                )
                .unwrap(),
            }],
        };
        let encoded = encode(&data);
        let decoded: Result<(u64, Vec<[u8; 32]>, Vec<String>, Vec<Vec<u8>>), _> =
            from_bytes(&encoded.to_vec());
        assert!(decoded.is_ok());
        let (chain_id, command_ids, command_types, params) = decoded.unwrap();

        assert_eq!(chain_id, destination_chain_id);

        assert_eq!(command_ids.len(), 1);
        assert_eq!(command_ids[0].to_vec(), command_id.to_vec());

        assert_eq!(command_types.len(), 1);
        assert_eq!(
            command_types[0],
            crate::types::CommandType::ApproveContractCall.to_string()
        );

        assert_eq!(params.len(), 1);
        let command = from_bytes(&params[0]);
        assert!(command.is_ok());
        let (
            source_chain_decoded,
            source_address_decoded,
            destination_address_decoded,
            payload_hash_decoded,
        ): (String, String, [u8; 32], Vec<u8>) = command.unwrap();

        assert_eq!(source_chain_decoded, source_chain);

        assert_eq!(source_address_decoded, source_address);

        assert_eq!(
            destination_address_decoded.to_vec(),
            HexBinary::from_hex(&destination_address).unwrap().to_vec()
        );

        assert_eq!(payload_hash_decoded, payload_hash.to_vec());
    }

    #[test]
    fn test_msg_to_sign() {
        let mut builder = CommandBatchBuilder::new(1u128.into(), crate::encoding::Encoder::Bcs);
        let _ = builder.add_message(Message {
            id: "ethereum:foobar".into(),
            destination_address: "0F".repeat(32),
            destination_chain: "sui".into(),
            source_chain: "ethereum".into(),
            source_address: "0x00".into(),
            payload_hash: HexBinary::from(vec![0, 1, 0, 1]),
        });
        let batch = builder.build().unwrap();
        let msg = msg_digest(&batch);
        assert_eq!(msg.len(), 32);

        let mut builder = CommandBatchBuilder::new(1u128.into(), crate::encoding::Encoder::Bcs);
        let _ = builder.add_message(Message {
            id: "ethereum:foobar2".into(),
            destination_address: "0F".repeat(32),
            destination_chain: "sui".into(),
            source_chain: "ethereum".into(),
            source_address: "0x00".into(),
            payload_hash: HexBinary::from(vec![0, 1, 0, 1]),
        });

        let batch = builder.build().unwrap();
        let msg2 = msg_digest(&batch);
        assert_ne!(msg, msg2);
    }
}
