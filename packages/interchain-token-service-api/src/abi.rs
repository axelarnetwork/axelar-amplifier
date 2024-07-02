use alloy_primitives::{Bytes, FixedBytes, U256};
use alloy_sol_types::{sol, SolValue};
use cosmwasm_std::{HexBinary, Uint256};
use error_stack::Report;

use crate::{
    error::Error,
    primitives::{ITSMessage, ITSRoutedMessage},
    TokenId, TokenManagerType,
};

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
        string chain;
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
                messageType: U256::from(0u64),
                tokenId: FixedBytes::<32>::from_slice(token_id.id.as_slice()),
                sourceAddress: Bytes::copy_from_slice(source_address.as_slice()),
                destinationAddress: Bytes::copy_from_slice(destination_address.as_slice()),
                amount: U256::from_le_bytes(amount.to_le_bytes()),
                data: Bytes::copy_from_slice(data.as_slice()),
            }
            .abi_encode(),
            ITSMessage::DeployInterchainToken {
                token_id,
                name,
                symbol,
                decimals,
                minter,
            } => DeployInterchainToken {
                messageType: U256::from(1u64),
                tokenId: FixedBytes::<32>::from_slice(token_id.id.as_slice()),
                name: name.clone(),
                symbol: symbol.clone(),
                decimals,
                minter: Bytes::copy_from_slice(minter.as_slice()),
            }
            .abi_encode(),
            ITSMessage::DeployTokenManager {
                token_id,
                token_manager_type,
                params,
            } => DeployTokenManager {
                messageType: U256::from(2u64),
                tokenId: FixedBytes::<32>::from_slice(token_id.id.as_slice()),
                tokenManagerType: U256::from(token_manager_type as u64),
                params: Bytes::copy_from_slice(params.as_slice()),
            }
            .abi_encode(),
        };

        RoutedCall {
            messageType: U256::from(MessageType::RoutedCall as u64),
            chain: self.remote_chain.clone(),
            message: Bytes::copy_from_slice(&message),
        }
        .abi_encode()
        .into()
    }

    pub fn abi_decode(payload: &[u8]) -> Result<Self, Report<Error>> {
        let wrapped_message: RoutedCall = RoutedCall::abi_decode(payload, true)
            .map_err(|e| Error::InvalidMessage(e.to_string()))?;

        if u8::try_from(wrapped_message.messageType)
            .map_err(|e| Report::new(Error::InvalidMessage(e.to_string())))?
            != MessageType::RoutedCall as u8
        {
            return Err(Report::new(Error::InvalidMessage(
                "invalid routed call".into(),
            )));
        }

        let message_type = MessageType::abi_decode(&wrapped_message.message[32..64], true)
            .map_err(|e| Error::InvalidMessage(e.to_string()))?;

        let message = match message_type {
            MessageType::InterchainTransfer => {
                let decoded = InterchainTransfer::abi_decode(&wrapped_message.message, true)
                    .map_err(|e| Report::new(Error::InvalidMessage(e.to_string())))?;

                Ok(ITSMessage::InterchainTransfer {
                    token_id: TokenId {
                        id: decoded.tokenId.into(),
                    },
                    source_address: HexBinary::from(decoded.sourceAddress.to_vec()),
                    destination_address: HexBinary::from(decoded.destinationAddress.as_ref()),
                    amount: Uint256::from_le_bytes(decoded.amount.to_le_bytes()),
                    data: HexBinary::from(decoded.data.as_ref()),
                })
            }
            MessageType::DeployInterchainToken => {
                let decoded = DeployInterchainToken::abi_decode(&wrapped_message.message, true)
                    .map_err(|e| Report::new(Error::InvalidMessage(e.to_string())))?;

                Ok(ITSMessage::DeployInterchainToken {
                    token_id: TokenId {
                        id: decoded.tokenId.into(),
                    },
                    name: decoded.name,
                    symbol: decoded.symbol,
                    decimals: decoded.decimals,
                    minter: HexBinary::from(decoded.minter.as_ref()),
                })
            }
            MessageType::DeployTokenManager => {
                let decoded = DeployTokenManager::abi_decode(&wrapped_message.message, true)
                    .map_err(|e| Report::new(Error::InvalidMessage(e.to_string())))?;

                let token_manager_type = u8::try_from(decoded.tokenManagerType)
                    .map_err(|e| Report::new(Error::InvalidMessage(e.to_string())))?;

                Ok(ITSMessage::DeployTokenManager {
                    token_id: TokenId {
                        id: decoded.tokenId.into(),
                    },
                    token_manager_type: TokenManagerType::try_from(token_manager_type)?,
                    params: HexBinary::from(decoded.params.as_ref()),
                })
            }
            _ => Err(Report::new(Error::InvalidMessage(
                "unsupported inner message".into(),
            ))),
        }?;

        Ok(ITSRoutedMessage {
            remote_chain: wrapped_message.chain,
            message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::{HexBinary, Uint256};

    fn create_token_id(value: u8) -> TokenId {
        let mut id = [0u8; 32];
        id[0] = value;
        TokenId::new(id)
    }

    #[test]
    fn interchain_transfer_encode_decode() {
        let cases = vec![
            ITSRoutedMessage {
                remote_chain: "ethereum".to_string(),
                message: ITSMessage::InterchainTransfer {
                    token_id: create_token_id(1),
                    source_address: HexBinary::from_hex("1234").unwrap(),
                    destination_address: HexBinary::from_hex("5678").unwrap(),
                    amount: Uint256::from(1000u128),
                    data: HexBinary::from_hex("74657374646174").unwrap(), // "testdata" in hex
                },
            },
            ITSRoutedMessage {
                remote_chain: "".to_string(),
                message: ITSMessage::InterchainTransfer {
                    token_id: create_token_id(2),
                    source_address: HexBinary::from_hex("").unwrap(),
                    destination_address: HexBinary::from_hex("").unwrap(),
                    amount: Uint256::zero(),
                    data: HexBinary::from_hex("").unwrap(),
                },
            },
            ITSRoutedMessage {
                remote_chain: "max_chain".to_string(),
                message: ITSMessage::InterchainTransfer {
                    token_id: create_token_id(3),
                    source_address: HexBinary::from_hex("ffff").unwrap(),
                    destination_address: HexBinary::from_hex("ffff").unwrap(),
                    amount: Uint256::MAX,
                    data: HexBinary::from_hex("6d61785f64617461").unwrap(), // "max_data" in hex
                },
            },
        ];

        for original in cases {
            let encoded = original.abi_encode();
            let decoded = ITSRoutedMessage::abi_decode(&encoded).unwrap();
            assert_eq!(original, decoded);
        }
    }

    #[test]
    fn deploy_interchain_token_encode_decode() {
        let cases = vec![
            ITSRoutedMessage {
                remote_chain: "polygon".to_string(),
                message: ITSMessage::DeployInterchainToken {
                    token_id: create_token_id(4),
                    name: "Test Token".to_string(),
                    symbol: "TST".to_string(),
                    decimals: 18,
                    minter: HexBinary::from_hex("abcd").unwrap(),
                },
            },
            ITSRoutedMessage {
                remote_chain: "".to_string(),
                message: ITSMessage::DeployInterchainToken {
                    token_id: create_token_id(5),
                    name: "".to_string(),
                    symbol: "".to_string(),
                    decimals: 0,
                    minter: HexBinary::from_hex("").unwrap(),
                },
            },
            ITSRoutedMessage {
                remote_chain: "max_chain".to_string(),
                message: ITSMessage::DeployInterchainToken {
                    token_id: create_token_id(6),
                    name: "Max Token".to_string(),
                    symbol: "MAX".to_string(),
                    decimals: 255,
                    minter: HexBinary::from_hex("ffffffff").unwrap(),
                },
            },
        ];

        for original in cases {
            let encoded = original.abi_encode();
            let decoded = ITSRoutedMessage::abi_decode(&encoded).unwrap();
            assert_eq!(original, decoded);
        }
    }

    #[test]
    fn deploy_token_manager_encode_decode() {
        let cases = vec![
            ITSRoutedMessage {
                remote_chain: "avalanche".to_string(),
                message: ITSMessage::DeployTokenManager {
                    token_id: create_token_id(7),
                    token_manager_type: TokenManagerType::NativeInterchainToken,
                    params: HexBinary::from_hex("706172616d7331").unwrap(), // "params1" in hex
                },
            },
            ITSRoutedMessage {
                remote_chain: "fantom".to_string(),
                message: ITSMessage::DeployTokenManager {
                    token_id: create_token_id(8),
                    token_manager_type: TokenManagerType::MintBurnFrom,
                    params: HexBinary::from_hex("706172616d7332").unwrap(), // "params2" in hex
                },
            },
            ITSRoutedMessage {
                remote_chain: "binance".to_string(),
                message: ITSMessage::DeployTokenManager {
                    token_id: create_token_id(9),
                    token_manager_type: TokenManagerType::LockUnlock,
                    params: HexBinary::from_hex("706172616d7333").unwrap(), // "params3" in hex
                },
            },
            ITSRoutedMessage {
                remote_chain: "optimism".to_string(),
                message: ITSMessage::DeployTokenManager {
                    token_id: create_token_id(10),
                    token_manager_type: TokenManagerType::LockUnlockFee,
                    params: HexBinary::from_hex("706172616d7334").unwrap(), // "params4" in hex
                },
            },
            ITSRoutedMessage {
                remote_chain: "arbitrum".to_string(),
                message: ITSMessage::DeployTokenManager {
                    token_id: create_token_id(11),
                    token_manager_type: TokenManagerType::MintBurn,
                    params: HexBinary::from_hex("706172616d7335").unwrap(), // "params5" in hex
                },
            },
            ITSRoutedMessage {
                remote_chain: "zksync".to_string(),
                message: ITSMessage::DeployTokenManager {
                    token_id: create_token_id(12),
                    token_manager_type: TokenManagerType::Gateway,
                    params: HexBinary::from_hex("706172616d7336").unwrap(), // "params6" in hex
                },
            },
        ];

        for original in cases {
            let encoded = original.abi_encode();
            let decoded = ITSRoutedMessage::abi_decode(&encoded).unwrap();
            assert_eq!(original, decoded);
        }
    }

    #[test]
    fn invalid_message_type() {
        let invalid_payload = RoutedCall {
            messageType: U256::from((MessageType::RoutedCall as u8) + 1),
            chain: "chain".to_string(),
            message: Bytes::copy_from_slice(&[0u8; 0]),
        }
        .abi_encode();

        let result = ITSRoutedMessage::abi_decode(&invalid_payload);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid routed call"));
    }

    #[test]
    fn invalid_token_manager_type() {
        let original = ITSRoutedMessage {
            remote_chain: "invalid".to_string(),
            message: ITSMessage::DeployTokenManager {
                token_id: create_token_id(13),
                token_manager_type: TokenManagerType::Gateway,
                params: HexBinary::from_hex("696e76616c69645f706172616d73").unwrap(), // "invalid_params" in hex
            },
        };

        let mut encoded = original.abi_encode().to_vec();

        // Modify the encoded data to have an invalid TokenManagerType
        let len = encoded.len();
        encoded[len - 33] = 10; // Set to an invalid value

        let result = ITSRoutedMessage::abi_decode(&encoded);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("hello"));
    }

    #[test]
    fn encode_decode_large_data() {
        let large_data = vec![0u8; 1024 * 1024]; // 1MB of data
        let original = ITSRoutedMessage {
            remote_chain: "large_data_chain".to_string(),
            message: ITSMessage::InterchainTransfer {
                token_id: create_token_id(14),
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
            remote_chain: "unicode_chain_🌍".to_string(),
            message: ITSMessage::DeployInterchainToken {
                token_id: create_token_id(15),
                name: "Unicode Token 🪙".to_string(),
                symbol: "UNI🔣".to_string(),
                decimals: 18,
                minter: HexBinary::from_hex("abcd").unwrap(),
            },
        };

        let encoded = original.abi_encode();
        let decoded = ITSRoutedMessage::abi_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn encode_decode_boundary_values() {
        let original = ITSRoutedMessage {
            remote_chain: "boundary".to_string(),
            message: ITSMessage::InterchainTransfer {
                token_id: TokenId::new([255u8; 32]), // Max value for all bytes
                source_address: HexBinary::from([255u8; 32]),
                destination_address: HexBinary::from([255u8; 32]),
                amount: Uint256::MAX,
                data: HexBinary::from([255u8; 1024]),
            },
        };

        let encoded = original.abi_encode();
        let decoded = ITSRoutedMessage::abi_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }
}
