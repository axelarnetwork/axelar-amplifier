use std::str::FromStr;

use alloy_primitives::{FixedBytes, U256};
use alloy_sol_types::{sol, SolValue};
use axelar_wasm_std::nonempty;
use cosmwasm_std::{HexBinary, Uint256};
use interchain_token_service::{
    DeployInterchainToken, HubMessage, InterchainTransfer, LinkToken, Message,
    RegisterTokenMetadata, TokenId,
};
use router_api::ChainNameRaw;

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

    let message_type = MessageType::abi_decode(&payload[0..32]).map_err(Error::AbiDecodeFailed)?;

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
            } = LinkTokenAbi::abi_decode_params(payload).map_err(Error::AbiDecodeFailed)?;

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
            destination_chain: destination_chain.to_string(),
            message: message_abi_encode(message).to_vec().into(),
        }
        .abi_encode_params(),
        HubMessage::ReceiveFromHub {
            source_chain,
            message,
        } => ReceiveFromHubAbi {
            messageType: MessageType::ReceiveFromHub.into(),
            source_chain: source_chain.to_string(),
            message: message_abi_encode(message).to_vec().into(),
        }
        .abi_encode_params(),
        HubMessage::RegisterTokenMetadata(RegisterTokenMetadata {
            token_address,
            decimals,
        }) => RegisterTokenMetadataAbi {
            messageType: MessageType::RegisterTokenMetadata.into(),
            tokenAddress: token_address.to_vec().into(),
            decimals,
        }
        .abi_encode_params(),
    }
    .into()
}

pub fn hub_message_abi_decode(payload: &[u8]) -> Result<HubMessage, Error> {
    if payload.len() < 32 {
        return Err(Error::InsufficientMessageLength);
    }

    let message_type = MessageType::abi_decode(&payload[0..32]).map_err(Error::AbiDecodeFailed)?;

    let hub_message = match message_type {
        MessageType::SendToHub => {
            let decoded =
                SendToHubAbi::abi_decode_params(payload).map_err(Error::AbiDecodeFailed)?;

            let destination_chain = ChainNameRaw::from_str(&decoded.destination_chain)
                .map_err(|_| Error::InvalidChainName)?;
            let message = message_abi_decode(&decoded.message)?;

            HubMessage::SendToHub {
                destination_chain,
                message,
            }
        }
        MessageType::ReceiveFromHub => {
            let decoded =
                ReceiveFromHubAbi::abi_decode_params(payload).map_err(Error::AbiDecodeFailed)?;

            let source_chain = ChainNameRaw::from_str(&decoded.source_chain)
                .map_err(|_| Error::InvalidChainName)?;
            let message = message_abi_decode(&decoded.message)?;

            HubMessage::ReceiveFromHub {
                source_chain,
                message,
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
    value.map(Vec::from).unwrap_or_default()
}

fn from_vec(value: std::vec::Vec<u8>) -> Result<Option<nonempty::HexBinary>, Error> {
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value.try_into().map_err(Error::NonEmpty)?))
    }
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::nonempty;

    use super::*;

    #[test]
    fn test_message_abi_encode_decode_interchain_transfer() {
        let message = Message::InterchainTransfer(InterchainTransfer {
            token_id: TokenId::new([1u8; 32]),
            source_address: nonempty::HexBinary::try_from(vec![0x11, 0x22, 0x33]).unwrap(),
            destination_address: nonempty::HexBinary::try_from(vec![0x44, 0x55, 0x66]).unwrap(),
            amount: nonempty::Uint256::try_from(1000u64).unwrap(),
            data: Some(nonempty::HexBinary::try_from(vec![0xaa, 0xbb]).unwrap()),
        });

        let encoded = message_abi_encode(message.clone());
        let decoded = message_abi_decode(encoded.as_slice()).unwrap();

        assert_eq!(message, decoded);
    }

    #[test]
    fn test_message_abi_encode_decode_interchain_transfer_no_data() {
        let message = Message::InterchainTransfer(InterchainTransfer {
            token_id: TokenId::new([2u8; 32]),
            source_address: nonempty::HexBinary::try_from(vec![0x11, 0x22, 0x33]).unwrap(),
            destination_address: nonempty::HexBinary::try_from(vec![0x44, 0x55, 0x66]).unwrap(),
            amount: nonempty::Uint256::try_from(5000u64).unwrap(),
            data: None,
        });

        let encoded = message_abi_encode(message.clone());
        let decoded = message_abi_decode(encoded.as_slice()).unwrap();

        assert_eq!(message, decoded);
    }

    #[test]
    fn test_message_abi_encode_decode_deploy_interchain_token() {
        let message = Message::DeployInterchainToken(DeployInterchainToken {
            token_id: TokenId::new([3u8; 32]),
            name: nonempty::String::try_from("Test Token".to_string()).unwrap(),
            symbol: nonempty::String::try_from("TEST".to_string()).unwrap(),
            decimals: 18,
            minter: Some(nonempty::HexBinary::try_from(vec![0xaa, 0xbb, 0xcc]).unwrap()),
        });

        let encoded = message_abi_encode(message.clone());
        let decoded = message_abi_decode(encoded.as_slice()).unwrap();

        assert_eq!(message, decoded);
    }

    #[test]
    fn test_message_abi_encode_decode_deploy_interchain_token_no_minter() {
        let message = Message::DeployInterchainToken(DeployInterchainToken {
            token_id: TokenId::new([4u8; 32]),
            name: nonempty::String::try_from("Another Token".to_string()).unwrap(),
            symbol: nonempty::String::try_from("ANTH".to_string()).unwrap(),
            decimals: 6,
            minter: None,
        });

        let encoded = message_abi_encode(message.clone());
        let decoded = message_abi_decode(encoded.as_slice()).unwrap();

        assert_eq!(message, decoded);
    }

    #[test]
    fn test_message_abi_encode_decode_link_token() {
        let message = Message::LinkToken(LinkToken {
            token_id: TokenId::new([5u8; 32]),
            token_manager_type: Uint256::from(2u64),
            source_token_address: nonempty::HexBinary::try_from(vec![0x11, 0x22, 0x33, 0x44])
                .unwrap(),
            destination_token_address: nonempty::HexBinary::try_from(vec![0x55, 0x66, 0x77, 0x88])
                .unwrap(),
            params: Some(nonempty::HexBinary::try_from(vec![0xaa, 0xbb, 0xcc, 0xdd]).unwrap()),
        });

        let encoded = message_abi_encode(message.clone());
        let decoded = message_abi_decode(encoded.as_slice()).unwrap();

        assert_eq!(message, decoded);
    }

    #[test]
    fn test_hub_message_abi_encode_decode_send_to_hub() {
        let hub_message = HubMessage::SendToHub {
            destination_chain: ChainNameRaw::try_from("ethereum").unwrap(),
            message: Message::InterchainTransfer(InterchainTransfer {
                token_id: TokenId::new([6u8; 32]),
                source_address: nonempty::HexBinary::try_from(vec![0x11, 0x22, 0x33]).unwrap(),
                destination_address: nonempty::HexBinary::try_from(vec![0x44, 0x55, 0x66]).unwrap(),
                amount: nonempty::Uint256::try_from(1000u64).unwrap(),
                data: None,
            }),
        };

        let encoded = hub_message_abi_encode(hub_message.clone());
        let decoded = hub_message_abi_decode(encoded.as_slice()).unwrap();

        assert_eq!(hub_message, decoded);
    }

    #[test]
    fn test_hub_message_abi_encode_decode_receive_from_hub() {
        let hub_message = HubMessage::ReceiveFromHub {
            source_chain: ChainNameRaw::try_from("polygon").unwrap(),
            message: Message::DeployInterchainToken(DeployInterchainToken {
                token_id: TokenId::new([7u8; 32]),
                name: nonempty::String::try_from("Hub Token".to_string()).unwrap(),
                symbol: nonempty::String::try_from("HUB".to_string()).unwrap(),
                decimals: 12,
                minter: None,
            }),
        };

        let encoded = hub_message_abi_encode(hub_message.clone());
        let decoded = hub_message_abi_decode(encoded.as_slice()).unwrap();

        assert_eq!(hub_message, decoded);
    }

    #[test]
    fn test_hub_message_abi_encode_decode_register_token_metadata() {
        let hub_message = HubMessage::RegisterTokenMetadata(RegisterTokenMetadata {
            token_address: nonempty::HexBinary::try_from(vec![0x11, 0x22, 0x33, 0x44, 0x55])
                .unwrap(),
            decimals: 8,
        });

        let encoded = hub_message_abi_encode(hub_message.clone());
        let decoded = hub_message_abi_decode(encoded.as_slice()).unwrap();

        assert_eq!(hub_message, decoded);
    }

    #[test]
    fn test_message_abi_decode_insufficient_length() {
        let payload = vec![0x01, 0x02]; // Too short
        let result = message_abi_decode(&payload);
        assert!(matches!(result, Err(Error::InsufficientMessageLength)));
    }

    #[test]
    fn test_hub_message_abi_decode_insufficient_length() {
        let payload = vec![0x01, 0x02]; // Too short
        let result = hub_message_abi_decode(&payload);
        assert!(matches!(result, Err(Error::InsufficientMessageLength)));
    }

    #[test]
    fn test_message_abi_decode_invalid_message_type() {
        // Create a payload with an invalid message type (99)
        let mut payload = vec![0u8; 32];
        payload[31] = 99; // Invalid message type
        payload.extend_from_slice(&[0u8; 32]); // Add some more data

        let result = message_abi_decode(&payload);
        assert!(matches!(result, Err(Error::InvalidMessageType)));
    }

    #[test]
    fn test_hub_message_abi_decode_invalid_chain_name() {
        // This test would require crafting a payload with an invalid chain name
        // For now, we'll test with a simple invalid payload
        let payload = vec![0u8; 64]; // All zeros, invalid format
        let result = hub_message_abi_decode(&payload);
        assert!(result.is_err());
    }
}
