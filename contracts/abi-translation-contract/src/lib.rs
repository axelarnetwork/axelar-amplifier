use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{entry_point, Binary, Deps, DepsMut, Env, MessageInfo, Response};
use interchain_token_service::{HubMessage, Message, TokenId, msg::TranslationQueryMsg, InterchainTransfer, DeployInterchainToken, LinkToken, RegisterTokenMetadata};
use alloy_primitives::{FixedBytes, U256};
use alloy_sol_types::{sol, SolValue};
use axelar_wasm_std::{nonempty, FnExt};
use cosmwasm_std::{HexBinary, Uint256};
use router_api::ChainNameRaw;
use std::str::FromStr;

use crate::error::ContractError;

pub mod contract;
pub mod error;

// ITS Message payload types for ABI encoding/decoding
sol! {
    enum MessageType {
        InterchainTransfer,
        DeployInterchainToken,
        DeployTokenManager, // note, this case is not supported by the ITS hub
        SendToHub,
        ReceiveFromHub,
        LinkToken,
        RegisterTokenMetadata,
    }

    struct InterchainTransferAbi {
        uint256 messageType;
        bytes32 tokenId;
        bytes sourceAddress;
        bytes destinationAddress;
        uint256 amount;
        bytes data;
    }

    struct DeployInterchainTokenAbi {
        uint256 messageType;
        bytes32 tokenId;
        string name;
        string symbol;
        uint8 decimals;
        bytes minter;
    }

    struct SendToHubAbi {
        uint256 messageType;
        /// True destination chain name when sending a message from ITS edge source contract -> ITS Hub
        string destination_chain;
        bytes message;
    }

    struct ReceiveFromHubAbi {
        uint256 messageType;
        /// True source chain name when receiving a message from ITS Hub -> ITS edge destination contract
        string source_chain;
        bytes message;
    }

    struct RegisterTokenMetadataAbi {
        uint256 messageType;
        bytes tokenAddress;
        uint8 decimals;
    }

    struct LinkTokenAbi {
        uint256 messageType;
        bytes32 tokenId;
        uint256 tokenManagerType;
        bytes sourceToken;
        bytes destinationToken;
        bytes params;
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("insufficient message length")]
    InsufficientMessageLength,
    #[error("invalid message type")]
    InvalidMessageType,
    #[error("invalid chain name")]
    InvalidChainName,
    #[error(transparent)]
    NonEmpty(#[from] nonempty::Error),
    #[error(transparent)]
    AbiDecodeFailed(#[from] alloy_sol_types::Error),
}

// Standalone functions for ABI encoding/decoding
pub fn message_abi_encode(message: Message) -> HexBinary {
    match message {
        Message::InterchainTransfer(InterchainTransfer {
            token_id,
            source_address,
            destination_address,
            amount,
            data,
        }) => InterchainTransferAbi {
            messageType: MessageType::InterchainTransfer.into(),
            tokenId: FixedBytes::<32>::new(token_id.into()),
            sourceAddress: Vec::<u8>::from(source_address).into(),
            destinationAddress: Vec::<u8>::from(destination_address).into(),
            amount: U256::from_le_bytes(amount.to_le_bytes()),
            data: into_vec(data).into(),
        }
        .abi_encode_params(),
        Message::DeployInterchainToken(DeployInterchainToken {
            token_id,
            name,
            symbol,
            decimals,
            minter,
        }) => DeployInterchainTokenAbi {
            messageType: MessageType::DeployInterchainToken.into(),
            tokenId: FixedBytes::<32>::new(token_id.into()),
            name: name.into(),
            symbol: symbol.into(),
            decimals,
            minter: into_vec(minter).into(),
        }
        .abi_encode_params(),
        Message::LinkToken(LinkToken {
            token_id,
            token_manager_type,
            source_token_address,
            destination_token_address,
            params,
        }) => LinkTokenAbi {
            messageType: MessageType::LinkToken.into(),
            tokenId: FixedBytes::<32>::new(token_id.into()),
            destinationToken: destination_token_address.to_vec().into(),
            sourceToken: source_token_address.to_vec().into(),
            tokenManagerType: U256::from_le_bytes(token_manager_type.to_le_bytes()),
            params: into_vec(params).into(),
        }
        .abi_encode_params(),
    }
    .into()
}

pub fn message_abi_decode(payload: &[u8]) -> Result<Message, Error> {
    if payload.len() < 32 {
        return Err(Error::InsufficientMessageLength);
    }

    let message_type = MessageType::abi_decode(&payload[0..32])
        .map_err(Error::AbiDecodeFailed)?;

    let message = match message_type {
        MessageType::InterchainTransfer => {
            let decoded = InterchainTransferAbi::abi_decode_params(payload)
                .map_err(Error::AbiDecodeFailed)?;

            InterchainTransfer {
                token_id: TokenId::new(decoded.tokenId.into()),
                source_address: Vec::<u8>::from(decoded.sourceAddress)
                    .try_into()
                    .map_err(Error::NonEmpty)?,
                destination_address: Vec::<u8>::from(decoded.destinationAddress)
                    .try_into()
                    .map_err(Error::NonEmpty)?,
                amount: Uint256::from_le_bytes(decoded.amount.to_le_bytes())
                    .try_into()
                    .map_err(Error::NonEmpty)?,
                data: from_vec(decoded.data.into())?,
            }
            .into()
        }
        MessageType::DeployInterchainToken => {
            let decoded = DeployInterchainTokenAbi::abi_decode_params(payload)
                .map_err(Error::AbiDecodeFailed)?;

            DeployInterchainToken {
                token_id: TokenId::new(decoded.tokenId.into()),
                name: decoded.name.try_into().map_err(Error::NonEmpty)?,
                symbol: decoded.symbol.try_into().map_err(Error::NonEmpty)?,
                decimals: decoded.decimals,
                minter: from_vec(decoded.minter.into())?,
            }
            .into()
        }
        MessageType::LinkToken => {
            let LinkTokenAbi {
                tokenId,
                tokenManagerType,
                sourceToken,
                destinationToken,
                params,
                messageType: _,
            } = LinkTokenAbi::abi_decode_params(payload)
                .map_err(Error::AbiDecodeFailed)?;

            LinkToken {
                token_id: TokenId::new(tokenId.into()),
                source_token_address: Vec::<u8>::from(sourceToken)
                    .try_into()
                    .map_err(Error::NonEmpty)?,
                token_manager_type: Uint256::from_le_bytes(tokenManagerType.to_le_bytes()),
                destination_token_address: Vec::<u8>::from(destinationToken)
                    .try_into()
                    .map_err(Error::NonEmpty)?,
                params: from_vec(params.into())?,
            }
            .into()
        }
        _ => return Err(Error::InvalidMessageType),
    };

    Ok(message)
}

pub fn hub_message_abi_encode(hub_message: HubMessage) -> HexBinary {
    match hub_message {
        HubMessage::SendToHub {
            destination_chain,
            message,
        } => SendToHubAbi {
            messageType: MessageType::SendToHub.into(),
            destination_chain: destination_chain.into(),
            message: Vec::<u8>::from(message_abi_encode(message)).into(),
        }
        .abi_encode_params()
        .into(),
        HubMessage::ReceiveFromHub {
            source_chain,
            message,
        } => ReceiveFromHubAbi {
            messageType: MessageType::ReceiveFromHub.into(),
            source_chain: source_chain.into(),
            message: Vec::<u8>::from(message_abi_encode(message)).into(),
        }
        .abi_encode_params()
        .into(),
        HubMessage::RegisterTokenMetadata(RegisterTokenMetadata {
            decimals,
            token_address,
        }) => RegisterTokenMetadataAbi {
            messageType: MessageType::RegisterTokenMetadata.into(),
            decimals,
            tokenAddress: token_address.to_vec().into(),
        }
        .abi_encode_params()
        .into(),
    }
}

pub fn hub_message_abi_decode(payload: &[u8]) -> Result<HubMessage, Error> {
    if payload.len() < 32 {
        return Err(Error::InsufficientMessageLength);
    }

    let message_type = MessageType::abi_decode(&payload[0..32])
        .map_err(Error::AbiDecodeFailed)?;

    let hub_message = match message_type {
        MessageType::SendToHub => {
            let decoded =
                SendToHubAbi::abi_decode_params(payload)
                    .map_err(Error::AbiDecodeFailed)?;

            HubMessage::SendToHub {
                destination_chain: ChainNameRaw::from_str(&decoded.destination_chain)
                    .map_err(|_| Error::InvalidChainName)?,
                message: message_abi_decode(&decoded.message)?,
            }
        }
        MessageType::ReceiveFromHub => {
            let decoded = ReceiveFromHubAbi::abi_decode_params(payload)
                .map_err(Error::AbiDecodeFailed)?;

            HubMessage::ReceiveFromHub {
                source_chain: ChainNameRaw::from_str(&decoded.source_chain)
                    .map_err(|_| Error::InvalidChainName)?,
                message: message_abi_decode(&decoded.message)?,
            }
        }
        MessageType::RegisterTokenMetadata => {
            let RegisterTokenMetadataAbi {
                tokenAddress,
                decimals,
                ..
            } = RegisterTokenMetadataAbi::abi_decode_params(payload)
                .map_err(Error::AbiDecodeFailed)?;
            HubMessage::RegisterTokenMetadata(RegisterTokenMetadata {
                decimals,
                token_address: Vec::<u8>::from(tokenAddress)
                    .try_into()
                    .map_err(Error::NonEmpty)?,
            })
        }
        _ => return Err(Error::InvalidMessageType),
    };

    Ok(hub_message)
}

impl From<MessageType> for U256 {
    fn from(value: MessageType) -> Self {
        U256::from(value as u8)
    }
}

fn into_vec(value: Option<nonempty::HexBinary>) -> std::vec::Vec<u8> {
    value.map(|v| v.into()).unwrap_or_default()
}

fn from_vec(value: std::vec::Vec<u8>) -> Result<Option<nonempty::HexBinary>, Error> {
    if value.is_empty() {
        None
    } else {
        Some(nonempty::HexBinary::try_from(value).map_err(Error::NonEmpty)?)
    }
    .then(Ok)
}

#[entry_point]
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    Ok(Response::new())
}

#[entry_point]
pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    Err(ContractError::UnsupportedOperation)
}

#[entry_point]
pub fn query(_deps: Deps, _env: Env, msg: TranslationQueryMsg) -> Result<Binary, ContractError> {
    match msg {
        TranslationQueryMsg::FromBytes { payload } => {
            // Use the real abi_decode logic to convert payload to HubMessage
            let hub_message = hub_message_abi_decode(payload.as_slice())
                .map_err(|_| ContractError::SerializationFailed)?;
            cosmwasm_std::to_json_binary(&hub_message).map_err(|_| ContractError::SerializationFailed)
        }
        TranslationQueryMsg::ToBytes { message } => {
            // Use the real abi_encode logic to convert HubMessage to payload
            let payload = hub_message_abi_encode(message);
            cosmwasm_std::to_json_binary(&payload).map_err(|_| ContractError::SerializationFailed)
        }
    }
}

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(HubMessage)]
    FromBytes { payload: cosmwasm_std::HexBinary },
    
    #[returns(cosmwasm_std::HexBinary)]
    ToBytes { message: HubMessage },
} 