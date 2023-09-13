use std::str::FromStr;

use cosmwasm_std::{HexBinary, Uint256};
use ethabi::{short_signature, ParamType, Token};
use k256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey};
use multisig::{key::Signature, msg::Signer};
use sha3::{Digest, Keccak256};

use crate::{
    error::ContractError,
    state::WorkerSet,
    types::{CommandBatch, Operator},
};

use super::Data;
use ethabi::ethereum_types;

pub const GATEWAY_EXECUTE_FUNCTION_NAME: &str = "execute";

pub fn encode(data: &Data) -> HexBinary {
    let destination_chain_id = Token::Uint(ethabi::ethereum_types::U256::from_big_endian(
        &data.destination_chain_id.to_be_bytes(),
    ));

    let (commands_ids, commands_types, commands_params) = data.commands.iter().fold(
        (vec![], vec![], vec![]),
        |(mut commands_ids, mut commands_types, mut commands_params), command| {
            commands_ids.push(Token::FixedBytes(command.id.to_vec()));
            commands_types.push(Token::String(command.ty.to_string()));
            commands_params.push(Token::Bytes(command.params.to_vec()));
            (commands_ids, commands_types, commands_params)
        },
    );

    ethabi::encode(&[
        destination_chain_id,
        Token::Array(commands_ids),
        Token::Array(commands_types),
        Token::Array(commands_params),
    ])
    .into()
}

pub fn msg_to_sign(command_batch: &CommandBatch) -> HexBinary {
    let msg = Keccak256::digest(encode(&command_batch.data).as_slice());

    // Prefix for standard EVM signed data https://eips.ethereum.org/EIPS/eip-191
    let unsigned = [
        "\x19Ethereum Signed Message:\n32".as_bytes(), // Keccek256 hash length = 32
        msg.as_slice(),
    ]
    .concat();

    Keccak256::digest(unsigned).as_slice().into()
}

pub fn encode_execute_data(
    command_batch: &CommandBatch,
    quorum: Uint256,
    signers: Vec<(Signer, Option<Signature>)>,
) -> Result<HexBinary, ContractError> {
    let param = ethabi::encode(&[
        Token::Bytes(encode(&command_batch.data).into()),
        Token::Bytes(encode_proof(quorum, signers)?.into()),
    ]);

    let input = ethabi::encode(&[Token::Bytes(param)]);

    let mut calldata = short_signature(GATEWAY_EXECUTE_FUNCTION_NAME, &[ParamType::Bytes]).to_vec();

    calldata.extend(input);

    Ok(calldata.into())
}

fn encode_proof(
    quorum: Uint256,
    signers: Vec<(Signer, Option<Signature>)>,
) -> Result<HexBinary, ContractError> {
    let mut operators = make_operators(signers)?;
    operators.sort();

    let (addresses, weights, signatures) = operators.iter().fold(
        (vec![], vec![], vec![]),
        |(mut addresses, mut weights, mut signatures), operator| {
            addresses.push(Token::Address(ethereum_types::Address::from_slice(
                operator.address.as_slice(),
            )));
            weights.push(Token::Uint(ethereum_types::U256::from_big_endian(
                &operator.weight.to_be_bytes(),
            )));

            if let Some(signature) = &operator.signature {
                signatures.push(Token::Bytes(<Vec<u8>>::from(signature.clone())));
            }

            (addresses, weights, signatures)
        },
    );

    let quorum = Token::Uint(ethereum_types::U256::from_big_endian(&quorum.to_be_bytes()));

    Ok(ethabi::encode(&[
        Token::Array(addresses),
        Token::Array(weights),
        quorum,
        Token::Array(signatures),
    ])
    .into())
}

pub fn make_operators(
    signers_with_sigs: Vec<(Signer, Option<Signature>)>,
) -> Result<Vec<Operator>, ContractError> {
    axelar_wasm_std::utils::try_map(signers_with_sigs, |(signer, sig)| {
        make_evm_operator(signer).map(|mut op: Operator| {
            if let Some(sig) = sig {
                op.set_signature(sig);
            }
            op
        })
    })
}

fn make_evm_operator(signer: Signer) -> Result<Operator, ContractError> {
    Ok(Operator {
        address: evm_address(signer.pub_key.as_ref())?,
        weight: signer.weight,
        signature: None,
    })
}

pub fn transfer_operatorship_params(worker_set: &WorkerSet) -> Result<HexBinary, ContractError> {
    let mut operators: Vec<(HexBinary, Uint256)> = worker_set
        .signers
        .iter()
        .map(|s| {
            (
                evm_address(s.pub_key.as_ref()).expect("couldn't convert pubkey to evm address"),
                s.weight,
            )
        })
        .collect();
    operators.sort_by_key(|op| op.0.clone());
    let (addresses, weights): (Vec<Token>, Vec<Token>) = operators
        .iter()
        .map(|operator| {
            (
                Token::Address(ethereum_types::Address::from_slice(operator.0.as_slice())),
                Token::Uint(ethereum_types::U256::from_big_endian(
                    &operator.1.to_be_bytes(),
                )),
            )
        })
        .unzip();

    let quorum = Token::Uint(ethereum_types::U256::from_big_endian(
        &worker_set.threshold.to_be_bytes(),
    ));

    Ok(ethabi::encode(&[Token::Array(addresses), Token::Array(weights), quorum]).into())
}

pub fn evm_address(pub_key: &[u8]) -> Result<HexBinary, ContractError> {
    let pub_key =
        PublicKey::from_sec1_bytes(pub_key).map_err(|e| ContractError::InvalidPublicKey {
            reason: e.to_string(),
        })?;
    let pub_key = pub_key.to_encoded_point(false);

    Ok(Keccak256::digest(&pub_key.as_bytes()[1..]).as_slice()[12..].into())
}

pub fn command_params(
    source_chain: String,
    source_address: String,
    destination_address: String,
    payload_hash: HexBinary,
) -> Result<HexBinary, ContractError> {
    let destination_address =
        ethereum_types::Address::from_str(&destination_address).map_err(|e| {
            ContractError::InvalidMessage {
                reason: format!("destination_address is not a valid EVM address: {}", e),
            }
        })?;
    let payload_hash : [u8; 32] =
        payload_hash
            .as_slice()
            .try_into()
            .map_err(|e| ContractError::InvalidMessage {
                reason: format!(
                    "payload_hash length is not a valid keccak256 hash length: {}",
                    e
                ),
            })?;
    Ok(ethabi::encode(&[
        Token::String(source_chain),
        Token::String(source_address),
        Token::Address(destination_address),
        Token::FixedBytes(payload_hash.into()),
        Token::FixedBytes(vec![]), // TODO: Dummy data for now while Gateway is updated to not require these fields
        Token::Uint(ethereum_types::U256::zero()),
    ])
    .into())
}
