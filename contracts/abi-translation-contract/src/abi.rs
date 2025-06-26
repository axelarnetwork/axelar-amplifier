use alloy_primitives::{FixedBytes, U256};
use alloy_sol_types::{sol, SolValue};
use axelar_wasm_std::{nonempty, IntoContractError};
use cosmwasm_std::{HexBinary, Uint256};
use error_stack::{bail, ensure, report, Report, ResultExt};
use router_api::ChainNameRaw;

use interchain_token_service::{HubMessage, Message, TokenId};
// ITS Message payload types
// Reference: https://github.com/axelarnetwork/interchain-token-service/blob/v1.2.4/DESIGN.md#interchain-communication-spec
// `abi_encode_params` is used to encode the struct fields as ABI params as required by the spec.
// E.g. `DeployTokenManager::abi_encode_params` encodes as `abi.encode([uint256, bytes32, uint256, bytes], [...])`.
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

    struct InterchainTransfer {
        uint256 messageType;
        bytes32 tokenId;
        bytes sourceAddress;
        bytes destinationAddress;
        uint256 amount;
        bytes data;
    }

    struct DeployInterchainToken {
        uint256 messageType;
        bytes32 tokenId;
        string name;
        string symbol;
        uint8 decimals;
        bytes minter;
    }

    struct SendToHub {
        uint256 messageType;
        /// True destination chain name when sending a message from ITS edge source contract -> ITS Hub
        string destination_chain;
        bytes message;
    }

    struct ReceiveFromHub {
        uint256 messageType;
        /// True source chain name when receiving a message from ITS Hub -> ITS edge destination contract
        string source_chain;
        bytes message;
    }

    struct RegisterTokenMetadata {
        uint256 messageType;
        bytes tokenAddress;
        uint8 decimals;
    }

    struct LinkToken {
        uint256 messageType;
        bytes32 tokenId;
        uint256 tokenManagerType;
        bytes sourceToken;
        bytes destinationToken;
        bytes params;
    }
}

#[derive(thiserror::Error, Debug, IntoContractError)]
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

pub fn message_abi_encode(message: Message) -> HexBinary {
    match message {
        Message::InterchainTransfer(interchain_token_service::InterchainTransfer {
            token_id,
            source_address,
            destination_address,
            amount,
            data,
        }) => InterchainTransfer {
            messageType: MessageType::InterchainTransfer.into(),
            tokenId: FixedBytes::<32>::new(token_id.into()),
            sourceAddress: Vec::<u8>::from(source_address).into(),
            destinationAddress: Vec::<u8>::from(destination_address).into(),
            amount: U256::from_le_bytes(amount.to_le_bytes()),
            data: into_vec(data).into(),
        }
        .abi_encode_params(),
        Message::DeployInterchainToken(interchain_token_service::DeployInterchainToken {
            token_id,
            name,
            symbol,
            decimals,
            minter,
        }) => DeployInterchainToken {
            messageType: MessageType::DeployInterchainToken.into(),
            tokenId: FixedBytes::<32>::new(token_id.into()),
            name: name.into(),
            symbol: symbol.into(),
            decimals,
            minter: into_vec(minter).into(),
        }
        .abi_encode_params(),
        Message::LinkToken(interchain_token_service::LinkToken {
            token_id,
            token_manager_type,
            source_token_address,
            destination_token_address,
            params,
        }) => LinkToken {
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

pub fn message_abi_decode(payload: &[u8]) -> Result<Message, Report<Error>> {
    ensure!(payload.len() >= 32, Error::InsufficientMessageLength);

    let message_type = MessageType::abi_decode(&payload[0..32], true)
        .change_context(Error::InvalidMessageType)?;

    let message = match message_type {
        MessageType::InterchainTransfer => {
            let decoded = InterchainTransfer::abi_decode_params(payload, true)
                .map_err(Error::AbiDecodeFailed)?;

            interchain_token_service::InterchainTransfer {
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
            let decoded = DeployInterchainToken::abi_decode_params(payload, true)
                .map_err(Error::AbiDecodeFailed)?;

            interchain_token_service::DeployInterchainToken {
                token_id: TokenId::new(decoded.tokenId.into()),
                name: decoded.name.try_into().map_err(Error::NonEmpty)?,
                symbol: decoded.symbol.try_into().map_err(Error::NonEmpty)?,
                decimals: decoded.decimals,
                minter: from_vec(decoded.minter.into())?,
            }
            .into()
        }
        MessageType::LinkToken => {
            let LinkToken {
                tokenId,
                tokenManagerType,
                sourceToken,
                destinationToken,
                params,
                ..
            } = LinkToken::abi_decode_params(payload, true).map_err(Error::AbiDecodeFailed)?;

            interchain_token_service::LinkToken {
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
        _ => bail!(Error::InvalidMessageType),
    };

    Ok(message)
}

pub fn hub_message_abi_encode(hub_message: HubMessage) -> HexBinary {
    match hub_message {
        HubMessage::SendToHub {
            destination_chain,
            message,
        } => SendToHub {
            messageType: MessageType::SendToHub.into(),
            destination_chain: destination_chain.into(),
            message: Vec::<u8>::from(message_abi_encode(message)).into(),
        }
        .abi_encode_params()
        .into(),
        HubMessage::ReceiveFromHub {
            source_chain,
            message,
        } => ReceiveFromHub {
            messageType: MessageType::ReceiveFromHub.into(),
            source_chain: source_chain.into(),
            message: Vec::<u8>::from(message_abi_encode(message)).into(),
        }
        .abi_encode_params()
        .into(),
        HubMessage::RegisterTokenMetadata(interchain_token_service::RegisterTokenMetadata {
            decimals,
            token_address,
        }) => RegisterTokenMetadata {
            messageType: MessageType::RegisterTokenMetadata.into(),
            decimals,
            tokenAddress: token_address.to_vec().into(),
        }
        .abi_encode_params()
        .into(),
    }
}

pub fn hub_message_abi_decode(payload: &[u8]) -> Result<HubMessage, Report<Error>> {
    ensure!(payload.len() >= 32, Error::InsufficientMessageLength);

    let message_type = MessageType::abi_decode(&payload[0..32], true)
        .change_context(Error::InvalidMessageType)?;

    let hub_message = match message_type {
        MessageType::SendToHub => {
            let decoded =
                SendToHub::abi_decode_params(payload, true).map_err(Error::AbiDecodeFailed)?;

            HubMessage::SendToHub {
                destination_chain: ChainNameRaw::try_from(decoded.destination_chain)
                    .change_context(Error::InvalidChainName)?,
                message: message_abi_decode(&decoded.message)?,
            }
        }
        MessageType::ReceiveFromHub => {
            let decoded = ReceiveFromHub::abi_decode_params(payload, true)
                .map_err(Error::AbiDecodeFailed)?;

            HubMessage::ReceiveFromHub {
                source_chain: ChainNameRaw::try_from(decoded.source_chain)
                    .change_context(Error::InvalidChainName)?,
                message: message_abi_decode(&decoded.message)?,
            }
        }
        MessageType::RegisterTokenMetadata => {
            let RegisterTokenMetadata {
                tokenAddress,
                decimals,
                ..
            } = RegisterTokenMetadata::abi_decode_params(payload, true)
                .map_err(Error::AbiDecodeFailed)?;
            HubMessage::RegisterTokenMetadata(interchain_token_service::RegisterTokenMetadata {
                decimals,
                token_address: Vec::<u8>::from(tokenAddress)
                    .try_into()
                    .map_err(Error::NonEmpty)?,
            })
        }
        _ => bail!(Error::InvalidMessageType),
    };

    Ok(hub_message)
}

impl From<MessageType> for U256 {
    fn from(value: MessageType) -> Self {
        U256::from(value as u8)
    }
}

fn into_vec(value: Option<nonempty::HexBinary>) -> std::vec::Vec<u8> {
    value.map(|v| v.to_vec()).unwrap_or_default()
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
    use super::*;
    use assert_ok::assert_ok;
    use axelar_wasm_std::assert_err_contains;
    use cosmwasm_std::testing::MockApi;
    use std::str::FromStr;

    fn from_hex(hex: &str) -> nonempty::HexBinary {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    #[test]
    fn interchain_transfer_encode_decode() {
        let remote_chain = ChainNameRaw::from_str("chain").unwrap();

        let cases = vec![
            HubMessage::SendToHub {
                destination_chain: remote_chain.clone(),
                message: interchain_token_service::InterchainTransfer {
                    token_id: [0u8; 32].into(),
                    source_address: from_hex("00"),
                    destination_address: from_hex("00"),
                    amount: 1u64.try_into().unwrap(),
                    data: None,
                }
                .into(),
            },
            HubMessage::SendToHub {
                destination_chain: remote_chain.clone(),
                message: interchain_token_service::InterchainTransfer {
                    token_id: [255u8; 32].into(),
                    source_address: from_hex("4F4495243837681061C4743b74B3eEdf548D56A5"),
                    destination_address: from_hex("4F4495243837681061C4743b74B3eEdf548D56A5"),
                    amount: Uint256::MAX.try_into().unwrap(),
                    data: Some(from_hex("abcd")),
                }
                .into(),
            },
            HubMessage::ReceiveFromHub {
                source_chain: remote_chain.clone(),
                message: interchain_token_service::InterchainTransfer {
                    token_id: [0u8; 32].into(),
                    source_address: from_hex("00"),
                    destination_address: from_hex("00"),
                    amount: 1u64.try_into().unwrap(),
                    data: None,
                }
                .into(),
            },
            HubMessage::ReceiveFromHub {
                source_chain: remote_chain.clone(),
                message: interchain_token_service::InterchainTransfer {
                    token_id: [255u8; 32].into(),
                    source_address: from_hex("4F4495243837681061C4743b74B3eEdf548D56A5"),
                    destination_address: from_hex("4F4495243837681061C4743b74B3eEdf548D56A5"),
                    amount: Uint256::MAX.try_into().unwrap(),
                    data: Some(from_hex("abcd")),
                }
                .into(),
            },
        ];

        let encoded: Vec<_> = cases
            .iter()
            .map(|original| hub_message_abi_encode(original.clone()).to_hex())
            .collect();

        goldie::assert_json!(encoded);

        for original in cases {
            let encoded = hub_message_abi_encode(original.clone());
            let decoded = assert_ok!(hub_message_abi_decode(&encoded));
            assert_eq!(original, decoded);
        }
    }

    #[test]
    fn fail_decode_on_empty_fields() {
        let test_cases = vec![
            InterchainTransfer {
                messageType: MessageType::InterchainTransfer.into(),
                tokenId: FixedBytes::<32>::new([1u8; 32]),
                sourceAddress: vec![1, 2].into(),
                destinationAddress: vec![].into(),
                amount: U256::from(1),
                data: vec![].into(),
            }
            .abi_encode_params(),
            InterchainTransfer {
                messageType: MessageType::InterchainTransfer.into(),
                tokenId: FixedBytes::<32>::new([1u8; 32]),
                sourceAddress: vec![].into(),
                destinationAddress: vec![1, 2].into(),
                amount: U256::from(1),
                data: vec![].into(),
            }
            .abi_encode_params(),
            InterchainTransfer {
                messageType: MessageType::InterchainTransfer.into(),
                tokenId: FixedBytes::<32>::new([1u8; 32]),
                sourceAddress: vec![1, 2].into(),
                destinationAddress: vec![1, 2].into(),
                amount: U256::from(0),
                data: vec![].into(),
            }
            .abi_encode_params(),
            DeployInterchainToken {
                messageType: MessageType::DeployInterchainToken.into(),
                tokenId: FixedBytes::<32>::new([1u8; 32]),
                name: "".into(),
                symbol: "TEST".into(),
                decimals: 0,
                minter: vec![].into(),
            }
            .abi_encode_params(),
            DeployInterchainToken {
                messageType: MessageType::DeployInterchainToken.into(),
                tokenId: FixedBytes::<32>::new([1u8; 32]),
                name: "Test".into(),
                symbol: "".into(),
                decimals: 0,
                minter: vec![].into(),
            }
            .abi_encode_params(),
        ];

        for message in test_cases {
            let payload = SendToHub {
                messageType: MessageType::SendToHub.into(),
                destination_chain: "destination".into(),
                message: message.into(),
            }
            .abi_encode_params();

            let result = hub_message_abi_decode(&payload);
            assert_err_contains!(result, Error, Error::NonEmpty(..));
        }
    }

    #[test]
    fn deploy_interchain_token_encode_decode() {
        let remote_chain = ChainNameRaw::from_str("chain").unwrap();

        let cases = vec![
            HubMessage::SendToHub {
                destination_chain: remote_chain.clone(),
                message: interchain_token_service::DeployInterchainToken {
                    token_id: [0u8; 32].into(),
                    name: "t".try_into().unwrap(),
                    symbol: "T".try_into().unwrap(),
                    decimals: 0,
                    minter: None,
                }
                .into(),
            },
            HubMessage::SendToHub {
                destination_chain: remote_chain.clone(),
                message: interchain_token_service::DeployInterchainToken {
                    token_id: [1u8; 32].into(),
                    name: "Test Token".try_into().unwrap(),
                    symbol: "TST".try_into().unwrap(),
                    decimals: 18,
                    minter: Some(from_hex("1234")),
                }
                .into(),
            },
            HubMessage::SendToHub {
                destination_chain: remote_chain.clone(),
                message: interchain_token_service::DeployInterchainToken {
                    token_id: [0u8; 32].into(),
                    name: "Unicode Token 🪙".try_into().unwrap(),
                    symbol: "UNI🔣".try_into().unwrap(),
                    decimals: 255,
                    minter: Some(from_hex("abcd")),
                }
                .into(),
            },
            HubMessage::ReceiveFromHub {
                source_chain: remote_chain.clone(),
                message: interchain_token_service::DeployInterchainToken {
                    token_id: [0u8; 32].into(),
                    name: "t".try_into().unwrap(),
                    symbol: "T".try_into().unwrap(),
                    decimals: 0,
                    minter: None,
                }
                .into(),
            },
            HubMessage::ReceiveFromHub {
                source_chain: remote_chain.clone(),
                message: interchain_token_service::DeployInterchainToken {
                    token_id: [1u8; 32].into(),
                    name: "Test Token".try_into().unwrap(),
                    symbol: "TST".try_into().unwrap(),
                    decimals: 18,
                    minter: Some(from_hex("1234")),
                }
                .into(),
            },
            HubMessage::ReceiveFromHub {
                source_chain: remote_chain.clone(),
                message: interchain_token_service::DeployInterchainToken {
                    token_id: [0u8; 32].into(),
                    name: "Unicode Token 🪙".try_into().unwrap(),
                    symbol: "UNI🔣".try_into().unwrap(),
                    decimals: 255,
                    minter: Some(from_hex("abcd")),
                }
                .into(),
            },
        ];

        let encoded: Vec<_> = cases
            .iter()
            .map(|original| hub_message_abi_encode(original.clone()).to_hex())
            .collect();

        goldie::assert_json!(encoded);

        for original in cases {
            let encoded = hub_message_abi_encode(original.clone());
            let decoded = assert_ok!(hub_message_abi_decode(&encoded));
            assert_eq!(original, decoded);
        }
    }

    #[test]
    fn invalid_hub_message_type() {
        let payload = vec![0u8; 32];
        let result = hub_message_abi_decode(&payload);
        assert_err_contains!(result, Error, Error::InvalidMessageType);
    }

    #[test]
    fn invalid_message_type() {
        let payload = vec![0u8; 32];
        let result = message_abi_decode(&payload);
        assert_err_contains!(result, Error, Error::InvalidMessageType);
    }

    #[test]
    fn invalid_destination_chain() {
        let message = DeployInterchainToken {
            messageType: MessageType::DeployInterchainToken.into(),
            tokenId: FixedBytes::<32>::new([0u8; 32]),
            name: "Test Token".into(),
            symbol: "TST".into(),
            decimals: 18,
            minter: vec![].into(),
        };

        let payload = SendToHub {
            messageType: MessageType::SendToHub.into(),
            destination_chain: "".into(),
            message: message.abi_encode_params().into(),
        }
        .abi_encode_params();

        let result = hub_message_abi_decode(&payload);
        assert_err_contains!(result, Error, Error::InvalidChainName);
    }

    #[test]
    fn encode_decode_large_data() {
        let large_data = vec![0u8; 1024 * 1024]; // 1MB of data
        let original = HubMessage::SendToHub {
            destination_chain: ChainNameRaw::from_str("large-data-chain").unwrap(),
            message: interchain_token_service::InterchainTransfer {
                token_id: [0u8; 32].into(),
                source_address: from_hex("1234"),
                destination_address: from_hex("5678"),
                amount: Uint256::from(1u128).try_into().unwrap(),
                data: Some(large_data.try_into().unwrap()),
            }
            .into(),
        };

        let encoded = hub_message_abi_encode(original.clone());
        let decoded = assert_ok!(hub_message_abi_decode(&encoded));
        assert_eq!(original, decoded);
    }

    #[test]
    fn encode_decode_unicode_strings() {
        let original = HubMessage::SendToHub {
            destination_chain: ChainNameRaw::from_str("chain").unwrap(),
            message: interchain_token_service::DeployInterchainToken {
                token_id: [0u8; 32].into(),
                name: "Unicode Token 🪙".try_into().unwrap(),
                symbol: "UNI🔣".try_into().unwrap(),
                decimals: 18,
                minter: Some(from_hex("abcd")),
            }
            .into(),
        };

        let encoded = hub_message_abi_encode(original.clone());
        let decoded = assert_ok!(hub_message_abi_decode(&encoded));
        assert_eq!(original, decoded);
    }
}



