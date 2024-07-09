use alloy_primitives::{Bytes, FixedBytes, U256};
use alloy_sol_types::{sol, SolValue};
use cosmwasm_std::{HexBinary, Uint256};
use error_stack::{Report, ResultExt};
use router_api::Address;

use crate::{
    error::Error,
    primitives::{ITSMessage, ITSRoutedMessage},
    TokenId, TokenManagerType,
};

// ITS Message payload types
// Reference: https://github.com/axelarnetwork/interchain-token-service/blob/v1.2.4/DESIGN.md#interchain-communication-spec
// `abi_encode_params` is used to encode the struct fields as ABI params as required by the spec.
// E.g. `DeployTokenManager::abi_encode_params` encodes as `abi.encode([uint256, bytes32, uint256, bytes], [...])`.
sol! {
    enum MessageType {
        InterchainTransfer,
        DeployInterchainToken,
        DeployTokenManager,
        RoutedCall,
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

    struct DeployTokenManager {
        uint256 messageType;
        bytes32 tokenId;
        uint256 tokenManagerType;
        bytes params;
    }

    struct RoutedCall {
        uint256 messageType;
        /// Remote chain name.
        /// ITS edge source contract -> ITS Hub GMP call: Set to the true destination chain name.
        /// ITS Hub -> ITS edge destination contract: Set to the true source chain name.
        string remote_chain;
        bytes message;
    }
}

impl ITSRoutedMessage {
    pub fn abi_encode(&self) -> HexBinary {
        let message: Vec<u8> = match self.message.clone() {
            ITSMessage::InterchainTransfer {
                token_id,
                source_address,
                destination_address,
                amount,
                data,
            } => InterchainTransfer {
                messageType: MessageType::InterchainTransfer.into(),
                tokenId: FixedBytes::<32>::new(token_id.to_bytes()),
                sourceAddress: Bytes::copy_from_slice(source_address.as_slice()),
                destinationAddress: Bytes::copy_from_slice(destination_address.as_slice()),
                amount: U256::from_le_bytes(amount.to_le_bytes()),
                data: Bytes::copy_from_slice(data.as_slice()),
            }
            .abi_encode_params(),
            ITSMessage::DeployInterchainToken {
                token_id,
                name,
                symbol,
                decimals,
                minter,
            } => DeployInterchainToken {
                messageType: MessageType::DeployInterchainToken.into(),
                tokenId: FixedBytes::<32>::new(token_id.to_bytes()),
                name: name.clone(),
                symbol: symbol.clone(),
                decimals,
                minter: Bytes::copy_from_slice(minter.as_slice()),
            }
            .abi_encode_params(),
            ITSMessage::DeployTokenManager {
                token_id,
                token_manager_type,
                params,
            } => DeployTokenManager {
                messageType: MessageType::DeployTokenManager.into(),
                tokenId: FixedBytes::<32>::new(token_id.to_bytes()),
                tokenManagerType: token_manager_type.into(),
                params: Bytes::copy_from_slice(params.as_slice()),
            }
            .abi_encode_params(),
        };

        RoutedCall {
            messageType: MessageType::RoutedCall.into(),
            remote_chain: self.remote_chain.to_string(),
            message: Bytes::copy_from_slice(&message),
        }
        .abi_encode_params()
        .into()
    }

    pub fn abi_decode(payload: &[u8]) -> Result<Self, Report<Error>> {
        let routed_message: RoutedCall = RoutedCall::abi_decode_params(payload, true)
            .map_err(|e| Error::InvalidMessage(e.to_string()))?;

        let routed_message_type = u8::try_from(routed_message.messageType)
            .map_err(|e| Report::new(Error::InvalidMessage(e.to_string())))?;

        if routed_message_type != MessageType::RoutedCall as u8 {
            return Err(Report::new(Error::InvalidMessage(
                "invalid routed call".into(),
            )));
        }

        if routed_message.message.len() < 32 {
            return Err(Report::new(Error::InvalidMessage(
                "invalid message length".into(),
            )));
        }

        let message_type = MessageType::abi_decode(&routed_message.message[0..32], true)
            .map_err(|e| Error::InvalidMessage(e.to_string()))?;

        let message = match message_type {
            MessageType::InterchainTransfer => {
                let decoded = InterchainTransfer::abi_decode_params(&routed_message.message, true)
                    .map_err(|e| Report::new(Error::InvalidMessage(e.to_string())))?;

                Ok(ITSMessage::InterchainTransfer {
                    token_id: TokenId::new(decoded.tokenId.into()),
                    source_address: HexBinary::from(decoded.sourceAddress.to_vec()),
                    destination_address: HexBinary::from(decoded.destinationAddress.as_ref()),
                    amount: Uint256::from_le_bytes(decoded.amount.to_le_bytes()),
                    data: HexBinary::from(decoded.data.as_ref()),
                })
            }
            MessageType::DeployInterchainToken => {
                let decoded =
                    DeployInterchainToken::abi_decode_params(&routed_message.message, true)
                        .map_err(|e| Report::new(Error::InvalidMessage(e.to_string())))?;

                Ok(ITSMessage::DeployInterchainToken {
                    token_id: TokenId::new(decoded.tokenId.into()),
                    name: decoded.name,
                    symbol: decoded.symbol,
                    decimals: decoded.decimals,
                    minter: HexBinary::from(decoded.minter.as_ref()),
                })
            }
            MessageType::DeployTokenManager => {
                let decoded = DeployTokenManager::abi_decode_params(&routed_message.message, true)
                    .map_err(|e| Report::new(Error::InvalidMessage(e.to_string())))?;

                let token_manager_type = u8::try_from(decoded.tokenManagerType)
                    .map_err(|e| Report::new(Error::InvalidMessage(e.to_string())))?;

                Ok(ITSMessage::DeployTokenManager {
                    token_id: TokenId::new(decoded.tokenId.into()),
                    token_manager_type: TokenManagerType::try_from(token_manager_type)?,
                    params: HexBinary::from(decoded.params.as_ref()),
                })
            }
            _ => Err(Report::new(Error::InvalidMessage(
                "invalid inner message".into(),
            ))),
        }?;

        Ok(ITSRoutedMessage {
            remote_chain: Address::try_from(routed_message.remote_chain)
                .change_context(Error::InvalidMessage("invalid remote chain".into()))?,
            message,
        })
    }
}

impl From<MessageType> for U256 {
    fn from(value: MessageType) -> Self {
        U256::from(value as u8)
    }
}

impl From<TokenManagerType> for U256 {
    fn from(value: TokenManagerType) -> Self {
        U256::from(value as u8)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::str::FromStr;

    use super::*;
    use cosmwasm_std::{HexBinary, Uint256};
    use golden_test_macro::golden_test;

    #[golden_test]
    #[test]
    fn interchain_transfer_encode_decode() {
        let remote_chain = Address::from_str("chain").unwrap();

        let cases = vec![
            ITSRoutedMessage {
                remote_chain: remote_chain.clone(),
                message: ITSMessage::InterchainTransfer {
                    token_id: TokenId::new([0u8; 32]),
                    source_address: HexBinary::from_hex("").unwrap(),
                    destination_address: HexBinary::from_hex("").unwrap(),
                    amount: Uint256::zero(),
                    data: HexBinary::from_hex("").unwrap(),
                },
            },
            ITSRoutedMessage {
                remote_chain: remote_chain.clone(),
                message: ITSMessage::InterchainTransfer {
                    token_id: TokenId::new([255u8; 32]),
                    source_address: HexBinary::from_hex("4F4495243837681061C4743b74B3eEdf548D56A5")
                        .unwrap(),
                    destination_address: HexBinary::from_hex(
                        "4F4495243837681061C4743b74B3eEdf548D56A5",
                    )
                    .unwrap(),
                    amount: Uint256::MAX,
                    data: HexBinary::from_hex("abcd").unwrap(),
                },
            },
        ];

        for original in cases {
            let encoded = original.abi_encode();

            writeln!(golden_file, "{}", encoded.to_hex()).unwrap();

            let decoded = ITSRoutedMessage::abi_decode(&encoded).unwrap();
            assert_eq!(original, decoded);
        }
    }

    #[golden_test]
    #[test]
    fn deploy_interchain_token_encode_decode() {
        let remote_chain = Address::from_str("chain").unwrap();

        let cases = vec![
            ITSRoutedMessage {
                remote_chain: remote_chain.clone(),
                message: ITSMessage::DeployInterchainToken {
                    token_id: TokenId::new([0u8; 32]),
                    name: "".into(),
                    symbol: "".into(),
                    decimals: 0,
                    minter: HexBinary::from_hex("").unwrap(),
                },
            },
            ITSRoutedMessage {
                remote_chain: remote_chain.clone(),
                message: ITSMessage::DeployInterchainToken {
                    token_id: TokenId::new([1u8; 32]),
                    name: "Test Token".into(),
                    symbol: "TST".into(),
                    decimals: 18,
                    minter: HexBinary::from_hex("1234").unwrap(),
                },
            },
            ITSRoutedMessage {
                remote_chain: Address::from_str("unicode_chain_🌍").unwrap(),
                message: ITSMessage::DeployInterchainToken {
                    token_id: TokenId::new([0u8; 32]),
                    name: "Unicode Token 🪙".into(),
                    symbol: "UNI🔣".into(),
                    decimals: 255,
                    minter: HexBinary::from_hex("abcd").unwrap(),
                },
            },
        ];

        for original in cases {
            let encoded = original.abi_encode();

            writeln!(golden_file, "{}", encoded.to_hex()).unwrap();

            let decoded = ITSRoutedMessage::abi_decode(&encoded).unwrap();
            assert_eq!(original, decoded);
        }
    }

    #[golden_test]
    #[test]
    fn deploy_token_manager_encode_decode() {
        let remote_chain = Address::from_str("chain").unwrap();

        let cases = vec![
            ITSRoutedMessage {
                remote_chain: remote_chain.clone(),
                message: ITSMessage::DeployTokenManager {
                    token_id: TokenId::new([0u8; 32]),
                    token_manager_type: TokenManagerType::NativeInterchainToken,
                    params: HexBinary::default(),
                },
            },
            ITSRoutedMessage {
                remote_chain: remote_chain.clone(),
                message: ITSMessage::DeployTokenManager {
                    token_id: TokenId::new([1u8; 32]),
                    token_manager_type: TokenManagerType::Gateway,
                    params: HexBinary::from_hex("1234").unwrap(),
                },
            },
        ];

        for original in cases {
            let encoded = original.abi_encode();

            writeln!(golden_file, "{}", encoded.to_hex()).unwrap();

            let decoded = ITSRoutedMessage::abi_decode(&encoded).unwrap();
            assert_eq!(original, decoded);
        }
    }

    #[test]
    fn invalid_routed_message_type() {
        let invalid_payload = RoutedCall {
            messageType: U256::from(MessageType::RoutedCall as u8 + 1),
            remote_chain: "remote_chain".into(),
            message: Bytes::new(),
        }
        .abi_encode_params();

        let result = ITSRoutedMessage::abi_decode(&invalid_payload);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid routed call"));
    }

    #[test]
    fn invalid_inner_message_type() {
        let mut message = MessageType::DeployTokenManager.abi_encode();
        message[31] = 3;

        let invalid_payload = RoutedCall {
            messageType: MessageType::RoutedCall.into(),
            remote_chain: "remote_chain".into(),
            message: message.into(),
        }
        .abi_encode_params();

        let result = ITSRoutedMessage::abi_decode(&invalid_payload);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid inner message"));
    }

    #[test]
    fn invalid_remote_chain() {
        let message = DeployTokenManager {
            messageType: MessageType::DeployTokenManager.into(),
            tokenId: FixedBytes::<32>::new([0u8; 32]),
            tokenManagerType: TokenManagerType::NativeInterchainToken.into(),
            params: Bytes::new(),
        };

        let payload = RoutedCall {
            messageType: MessageType::RoutedCall.into(),
            remote_chain: "".into(),
            message: Bytes::copy_from_slice(&message.abi_encode_params()),
        }
        .abi_encode_params();

        let result = ITSRoutedMessage::abi_decode(&payload);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid remote chain"));
    }

    #[test]
    fn invalid_token_manager_type() {
        let message = DeployTokenManager {
            messageType: MessageType::DeployTokenManager.into(),
            tokenId: FixedBytes::<32>::new([0u8; 32]),
            tokenManagerType: U256::from(TokenManagerType::Gateway as u8 + 1),
            params: Bytes::new(),
        };

        let payload = RoutedCall {
            messageType: MessageType::RoutedCall.into(),
            remote_chain: "chain".into(),
            message: Bytes::copy_from_slice(&message.abi_encode_params()),
        }
        .abi_encode_params();

        let result = ITSRoutedMessage::abi_decode(&payload);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("failed to convert enum"));
    }

    #[test]
    fn encode_decode_large_data() {
        let large_data = vec![0u8; 1024 * 1024]; // 1MB of data
        let original = ITSRoutedMessage {
            remote_chain: Address::from_str("large_data_chain").unwrap(),
            message: ITSMessage::InterchainTransfer {
                token_id: TokenId::new([0u8; 32]),
                source_address: HexBinary::from_hex("1234").unwrap(),
                destination_address: HexBinary::from_hex("5678").unwrap(),
                amount: Uint256::from(1u128),
                data: HexBinary::from(large_data),
            },
        };

        let encoded = original.abi_encode();
        let decoded = ITSRoutedMessage::abi_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn encode_decode_unicode_strings() {
        let original = ITSRoutedMessage {
            remote_chain: Address::from_str("unicode_chain_🌍").unwrap(),
            message: ITSMessage::DeployInterchainToken {
                token_id: TokenId::new([0u8; 32]),
                name: "Unicode Token 🪙".into(),
                symbol: "UNI🔣".into(),
                decimals: 18,
                minter: HexBinary::from_hex("abcd").unwrap(),
            },
        };

        let encoded = original.abi_encode();
        let decoded = ITSRoutedMessage::abi_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }
}
