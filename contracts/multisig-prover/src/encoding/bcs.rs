use bcs::to_bytes;
use cosmwasm_std::HexBinary;
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
    let ret = to_bytes(&(
        source_chain,
        source_address,
        <[u8; 30]>::try_from(&HexBinary::from_hex(&destination_address)?.to_vec()[..30])
            .expect("couldn't convert destination_address to 30 byte array"), // TODO: is this right? Why are addresses 30 bytes?
        payload_hash.to_vec(),
    ))?;

    Ok(ret.into())
}

pub fn encode(data: &Data) -> Result<HexBinary, ContractError> {
    // destination chain id is u64
    let destination_chain_id = &u64::from_le_bytes(
        data.destination_chain_id.to_le_bytes()[..8]
            .try_into()
            .expect("Couldn't convert u256 to u64"),
    );

    let (commands_ids, command_types, command_params): (Vec<[u8; 32]>, Vec<String>, Vec<Vec<u8>>) =
        data.commands
            .iter()
            .map(|command| {
                (
                    <[u8; 32]>::try_from(&command.id.to_vec()[..32])
                        .expect("couldn't convert command id to 32 byte array"), // command-ids are fixed length sequences
                    command.ty.to_string(),
                    command.params.to_vec(),
                )
            })
            .multiunzip();

    Ok(to_bytes(&(
        destination_chain_id,
        commands_ids,
        command_types,
        command_params,
    ))?
    .into())
}

pub fn msg_to_sign(command_batch: &CommandBatch) -> Result<HexBinary, ContractError> {
    let msg = Keccak256::digest(encode(&command_batch.data)?.as_slice());

    // Sui is just mimicking EVM here
    let unsigned = [
        "\x19Sui Signed Message:\n32".as_bytes(), // Keccek256 hash length = 32
        msg.as_slice(),
    ]
    .concat();

    Ok(Keccak256::digest(unsigned).as_slice().into())
}

#[cfg(test)]
mod test {

    use std::vec;

    use bcs::from_bytes;
    use connection_router::msg::Message;
    use cosmwasm_std::HexBinary;

    use crate::{
        encoding::{
            bcs::{command_params, encode},
            CommandBatchBuilder, Data,
        },
        types::{Command, CommandBatch},
    };

    use super::msg_to_sign;

    #[test]
    fn test_command_params() {
        let res = command_params(
            "Ethereum".into(),
            "00".into(),
            "01".repeat(30).into(),
            HexBinary::from_hex("02").unwrap(),
        );
        assert!(res.is_ok());

        let res = res.unwrap();
        let params = from_bytes(&res.to_vec());
        assert!(params.is_ok());
        let (source_chain, source_address, destination_address, payload_hash): (
            String,
            String,
            [u8; 30],
            Vec<u8>,
        ) = params.unwrap();
        assert_eq!(source_chain, "Ethereum".to_string());

        assert_eq!(source_address, "00".to_string());

        assert_eq!(
            destination_address.to_vec(),
            HexBinary::from_hex(&"01".repeat(30)).unwrap().to_vec()
        );

        assert_eq!(payload_hash, vec![2]);
    }

    #[test]
    fn test_encode() {
        let source_chain = "Ethereum";
        let source_address = "AA";
        let destination_address = "BB".repeat(30);
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
        let res = encode(&data);
        assert!(res.is_ok());
        let encoded = res.unwrap();
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
        ): (String, String, [u8; 30], Vec<u8>) = command.unwrap();

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
            destination_address: "0F".repeat(30),
            destination_chain: "sui".into(),
            source_chain: "ethereum".into(),
            source_address: "0x00".into(),
            payload_hash: HexBinary::from(vec![0, 1, 0, 1]),
        });
        let batch = builder.build().unwrap();
        let res = msg_to_sign(&batch);
        assert!(res.is_ok());

        let msg = res.unwrap();
        assert_eq!(msg.len(), 32);

        let mut builder = CommandBatchBuilder::new(1u128.into(), crate::encoding::Encoder::Bcs);
        let _ = builder.add_message(Message {
            id: "ethereum:foobar2".into(),
            destination_address: "0F".repeat(30),
            destination_chain: "sui".into(),
            source_chain: "ethereum".into(),
            source_address: "0x00".into(),
            payload_hash: HexBinary::from(vec![0, 1, 0, 1]),
        });

        let batch = builder.build().unwrap();
        let res2 = msg_to_sign(&batch);
        assert!(res2.is_ok());
        assert_ne!(msg, res2.unwrap());
    }
}
