use bcs::to_bytes;
use cosmwasm_std::{HexBinary, Uint256};
use itertools::Itertools;

use crate::error::ContractError;

use super::Data;

// TODO: all of the public functions in this file should be moved to a trait,
// that has an abi and bcs implementation (and possibly others)

pub fn command_params(
    source_chain: String,
    source_address: String,
    destination_address: String,
    payload_hash: HexBinary,
) -> Result<HexBinary, ContractError> {
    if payload_hash.len() != 32 {
        return Err(ContractError::InvalidMessage {
            reason: format!("payload hash is not 32 bytes {}", payload_hash.to_hex()),
        });
    }

    let destination_address = <[u8; 32]>::try_from(
        HexBinary::from_hex(&destination_address)?.to_vec(),
    )
    .map_err(|_| ContractError::InvalidMessage {
        reason: format!(
            "destination_address is not a valid Sui address: {}",
            destination_address
        ),
    })?;

    Ok(to_bytes(&(
        source_chain,
        source_address,
        destination_address,
        payload_hash.to_vec(),
    ))
    .expect("couldn't serialize command as bcs")
    .into())
}

fn u256_to_u64(chain_id: Uint256) -> u64 {
    chain_id.to_string().parse().expect("chain_id is invalid")
}

fn make_command_id(command_id: &HexBinary) -> [u8; 32] {
    // command-ids are fixed length sequences
    command_id
        .to_vec()
        .try_into()
        .expect("couldn't convert command id to 32 byte array")
}

pub fn encode(data: &Data) -> HexBinary {
    // destination chain id must be u64 for sui
    let destination_chain_id = u256_to_u64(data.destination_chain_id);

    let (commands_ids, command_types, command_params): (Vec<[u8; 32]>, Vec<String>, Vec<Vec<u8>>) =
        data.commands
            .iter()
            .map(|command| {
                (
                    make_command_id(&command.id),
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

#[cfg(test)]
mod test {

    use std::vec;

    use bcs::from_bytes;
    use cosmwasm_std::{HexBinary, Uint256};

    use crate::{
        encoding::{
            bcs::{command_params, encode, make_command_id, u256_to_u64},
            Data,
        },
        types::Command,
    };

    #[test]
    fn test_chain_id_as_u64() {
        let chain_id = 1u64;
        assert_eq!(chain_id, u256_to_u64(Uint256::from(chain_id as u128)));
    }

    #[test]
    #[should_panic]
    fn test_chain_id_as_u64_fails() {
        let chain_id = u128::MAX;
        u256_to_u64(Uint256::from(chain_id));
    }

    #[test]
    fn test_make_command_id() {
        assert_eq!([0; 32], make_command_id(&HexBinary::from(vec![0; 32])));
    }

    #[test]
    #[should_panic]
    fn test_make_command_id_fails_too_large() {
        make_command_id(&HexBinary::from(vec![0; 30]));
    }

    #[test]
    fn test_command_params() {
        let res = command_params(
            "Ethereum".into(),
            "00".into(),
            "01".repeat(32).into(),
            HexBinary::from_hex(&"02".repeat(32)).unwrap(),
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

        assert_eq!(payload_hash, vec![2; 32]);
    }

    #[test]
    fn test_invalid_destination_address() {
        let res = command_params(
            "Ethereum".into(),
            "00".into(),
            "01".into(),
            HexBinary::from_hex("02").unwrap(),
        );
        assert!(!res.is_ok());
    }

    #[test]
    fn test_encode() {
        let source_chain = "Ethereum";
        let source_address = "AA";
        let destination_address = "BB".repeat(32);
        let payload_hash = HexBinary::from_hex(&"CC".repeat(32)).unwrap();
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
}
