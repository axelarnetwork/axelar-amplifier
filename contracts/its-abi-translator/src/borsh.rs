use axelar_wasm_std::{nonempty, IntoContractError};
use borsh::{BorshDeserialize, BorshSerialize};
use cosmwasm_std::{HexBinary, Uint256};
use error_stack::{Report, ResultExt};
use interchain_token_service_std::TokenId;
use router_api::ChainNameRaw;

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("borsh serialization failed")]
    SerializationFailed,
    #[error("borsh deserialization failed")]
    DeserializationFailed,
    #[error("invalid chain name")]
    InvalidChainName,
    #[error(transparent)]
    NonEmpty(#[from] nonempty::Error),
}

/// Borsh-serializable mirror of interchain_token_service_std::InterchainTransfer
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq)]
pub struct InterchainTransfer {
    pub token_id: [u8; 32],
    pub source_address: Vec<u8>,
    pub destination_address: Vec<u8>,
    pub amount: [u8; 32], // Uint256 as 32-byte little-endian
    pub data: Option<Vec<u8>>,
}

/// Borsh-serializable mirror of interchain_token_service_std::DeployInterchainToken
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq)]
pub struct DeployInterchainToken {
    pub token_id: [u8; 32],
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub minter: Option<Vec<u8>>,
}

/// Borsh-serializable mirror of interchain_token_service_std::LinkToken
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq)]
pub struct LinkToken {
    pub token_id: [u8; 32],
    pub token_manager_type: [u8; 32], // Uint256 as 32-byte little-endian
    pub source_token_address: Vec<u8>,
    pub destination_token_address: Vec<u8>,
    pub params: Option<Vec<u8>>,
}

/// Borsh-serializable mirror of interchain_token_service_std::RegisterTokenMetadata
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq)]
pub struct RegisterTokenMetadata {
    pub decimals: u8,
    pub token_address: Vec<u8>,
}

/// Borsh-serializable mirror of interchain_token_service_std::Message
/// Note: Borsh enums automatically serialize with a discriminant byte
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq)]
pub enum Message {
    InterchainTransfer(InterchainTransfer),
    DeployInterchainToken(DeployInterchainToken),
    LinkToken(LinkToken),
}

/// Borsh-serializable mirror of interchain_token_service_std::HubMessage
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq)]
pub enum HubMessage {
    SendToHub {
        destination_chain: String,
        message: Message,
    },
    ReceiveFromHub {
        source_chain: String,
        message: Message,
    },
    RegisterTokenMetadata(RegisterTokenMetadata),
}

//
// Conversion: Domain Types -> Borsh Types
//

impl From<interchain_token_service_std::InterchainTransfer> for InterchainTransfer {
    fn from(t: interchain_token_service_std::InterchainTransfer) -> Self {
        Self {
            token_id: t.token_id.into(),
            source_address: t.source_address.into(),
            destination_address: t.destination_address.into(),
            amount: Uint256::from(t.amount).to_le_bytes(),
            data: t.data.map(Into::into),
        }
    }
}

impl From<interchain_token_service_std::DeployInterchainToken> for DeployInterchainToken {
    fn from(d: interchain_token_service_std::DeployInterchainToken) -> Self {
        Self {
            token_id: d.token_id.into(),
            name: d.name.into(),
            symbol: d.symbol.into(),
            decimals: d.decimals,
            minter: d.minter.map(Into::into),
        }
    }
}

impl From<interchain_token_service_std::LinkToken> for LinkToken {
    fn from(l: interchain_token_service_std::LinkToken) -> Self {
        Self {
            token_id: l.token_id.into(),
            token_manager_type: l.token_manager_type.to_le_bytes(),
            source_token_address: l.source_token_address.into(),
            destination_token_address: l.destination_token_address.into(),
            params: l.params.map(Into::into),
        }
    }
}

impl From<interchain_token_service_std::RegisterTokenMetadata> for RegisterTokenMetadata {
    fn from(r: interchain_token_service_std::RegisterTokenMetadata) -> Self {
        Self {
            decimals: r.decimals,
            token_address: r.token_address.into(),
        }
    }
}

impl From<interchain_token_service_std::Message> for Message {
    fn from(msg: interchain_token_service_std::Message) -> Self {
        match msg {
            interchain_token_service_std::Message::InterchainTransfer(t) => {
                Message::InterchainTransfer(t.into())
            }
            interchain_token_service_std::Message::DeployInterchainToken(d) => {
                Message::DeployInterchainToken(d.into())
            }
            interchain_token_service_std::Message::LinkToken(l) => Message::LinkToken(l.into()),
        }
    }
}

impl From<interchain_token_service_std::HubMessage> for HubMessage {
    fn from(msg: interchain_token_service_std::HubMessage) -> Self {
        match msg {
            interchain_token_service_std::HubMessage::SendToHub {
                destination_chain,
                message,
            } => HubMessage::SendToHub {
                destination_chain: destination_chain.into(),
                message: message.into(),
            },
            interchain_token_service_std::HubMessage::ReceiveFromHub {
                source_chain,
                message,
            } => HubMessage::ReceiveFromHub {
                source_chain: source_chain.into(),
                message: message.into(),
            },
            interchain_token_service_std::HubMessage::RegisterTokenMetadata(r) => {
                HubMessage::RegisterTokenMetadata(r.into())
            }
        }
    }
}

//
// Conversion: Borsh Types -> Domain Types
//

impl TryFrom<InterchainTransfer> for interchain_token_service_std::InterchainTransfer {
    type Error = nonempty::Error;

    fn try_from(t: InterchainTransfer) -> Result<Self, Self::Error> {
        Ok(Self {
            token_id: TokenId::new(t.token_id),
            source_address: t.source_address.try_into()?,
            destination_address: t.destination_address.try_into()?,
            amount: Uint256::from_le_bytes(t.amount).try_into()?,
            data: t.data.map(|d| d.try_into()).transpose()?,
        })
    }
}

impl TryFrom<DeployInterchainToken> for interchain_token_service_std::DeployInterchainToken {
    type Error = nonempty::Error;

    fn try_from(d: DeployInterchainToken) -> Result<Self, Self::Error> {
        Ok(Self {
            token_id: TokenId::new(d.token_id),
            name: d.name.try_into()?,
            symbol: d.symbol.try_into()?,
            decimals: d.decimals,
            minter: d.minter.map(|m| m.try_into()).transpose()?,
        })
    }
}

impl TryFrom<LinkToken> for interchain_token_service_std::LinkToken {
    type Error = nonempty::Error;

    fn try_from(l: LinkToken) -> Result<Self, Self::Error> {
        Ok(Self {
            token_id: TokenId::new(l.token_id),
            token_manager_type: Uint256::from_le_bytes(l.token_manager_type),
            source_token_address: l.source_token_address.try_into()?,
            destination_token_address: l.destination_token_address.try_into()?,
            params: l.params.map(|p| p.try_into()).transpose()?,
        })
    }
}

impl TryFrom<RegisterTokenMetadata> for interchain_token_service_std::RegisterTokenMetadata {
    type Error = nonempty::Error;

    fn try_from(r: RegisterTokenMetadata) -> Result<Self, Self::Error> {
        Ok(Self {
            decimals: r.decimals,
            token_address: r.token_address.try_into()?,
        })
    }
}

impl TryFrom<Message> for interchain_token_service_std::Message {
    type Error = nonempty::Error;

    fn try_from(msg: Message) -> Result<Self, Self::Error> {
        Ok(match msg {
            Message::InterchainTransfer(t) => {
                interchain_token_service_std::Message::InterchainTransfer(t.try_into()?)
            }
            Message::DeployInterchainToken(d) => {
                interchain_token_service_std::Message::DeployInterchainToken(d.try_into()?)
            }
            Message::LinkToken(l) => {
                interchain_token_service_std::Message::LinkToken(l.try_into()?)
            }
        })
    }
}

impl TryFrom<HubMessage> for interchain_token_service_std::HubMessage {
    type Error = Report<Error>;

    fn try_from(msg: HubMessage) -> Result<Self, Self::Error> {
        Ok(match msg {
            HubMessage::SendToHub {
                destination_chain,
                message,
            } => interchain_token_service_std::HubMessage::SendToHub {
                destination_chain: ChainNameRaw::try_from(destination_chain)
                    .change_context(Error::InvalidChainName)?,
                message: interchain_token_service_std::Message::try_from(message)
                    .map_err(Error::NonEmpty)?,
            },
            HubMessage::ReceiveFromHub {
                source_chain,
                message,
            } => interchain_token_service_std::HubMessage::ReceiveFromHub {
                source_chain: ChainNameRaw::try_from(source_chain)
                    .change_context(Error::InvalidChainName)?,
                message: interchain_token_service_std::Message::try_from(message)
                    .map_err(Error::NonEmpty)?,
            },
            HubMessage::RegisterTokenMetadata(r) => {
                interchain_token_service_std::HubMessage::RegisterTokenMetadata(
                    interchain_token_service_std::RegisterTokenMetadata::try_from(r)
                        .map_err(Error::NonEmpty)?,
                )
            }
        })
    }
}

//
// Public Encode/Decode API
//

pub fn hub_message_encode(
    hub_message: interchain_token_service_std::HubMessage,
) -> Result<HexBinary, Report<Error>> {
    let borsh_msg: HubMessage = hub_message.into();
    borsh::to_vec(&borsh_msg)
        .map(Into::into)
        .map_err(|_| Report::new(Error::SerializationFailed))
}

pub fn hub_message_decode(
    payload: HexBinary,
) -> Result<interchain_token_service_std::HubMessage, Report<Error>> {
    let borsh_msg: HubMessage =
        borsh::from_slice(payload.as_slice()).map_err(|_| Error::DeserializationFailed)?;
    borsh_msg.try_into()
}

pub fn message_encode(
    message: interchain_token_service_std::Message,
) -> Result<HexBinary, Report<Error>> {
    let borsh_msg: Message = message.into();
    borsh::to_vec(&borsh_msg)
        .map(Into::into)
        .map_err(|_| Report::new(Error::SerializationFailed))
}

pub fn message_decode(
    payload: &[u8],
) -> Result<interchain_token_service_std::Message, Report<Error>> {
    let borsh_msg: Message =
        borsh::from_slice(payload).map_err(|_| Error::DeserializationFailed)?;
    interchain_token_service_std::Message::try_from(borsh_msg)
        .map_err(Error::NonEmpty)
        .map_err(Report::new)
}

#[cfg(test)]
mod tests {
    use assert_ok::assert_ok;
    use axelar_wasm_std::nonempty;
    use cosmwasm_std::{HexBinary, Uint256};
    use router_api::chain_name_raw;

    use super::*;

    fn from_hex(hex: &str) -> nonempty::HexBinary {
        HexBinary::from_hex(hex).unwrap().try_into().unwrap()
    }

    //
    // Roundtrip encode/decode tests
    //

    #[test]
    fn interchain_transfer_roundtrip_encode_decode() {
        let remote_chain = chain_name_raw!("chain");

        let cases = vec![
            interchain_token_service_std::HubMessage::SendToHub {
                destination_chain: remote_chain.clone(),
                message: interchain_token_service_std::InterchainTransfer {
                    token_id: [0u8; 32].into(),
                    source_address: from_hex("00"),
                    destination_address: from_hex("00"),
                    amount: 1u64.try_into().unwrap(),
                    data: None,
                }
                .into(),
            },
            interchain_token_service_std::HubMessage::SendToHub {
                destination_chain: remote_chain.clone(),
                message: interchain_token_service_std::InterchainTransfer {
                    token_id: [255u8; 32].into(),
                    source_address: from_hex("4F4495243837681061C4743b74B3eEdf548D56A5"),
                    destination_address: from_hex("4F4495243837681061C4743b74B3eEdf548D56A5"),
                    amount: Uint256::MAX.try_into().unwrap(),
                    data: Some(from_hex("abcd")),
                }
                .into(),
            },
            interchain_token_service_std::HubMessage::ReceiveFromHub {
                source_chain: remote_chain.clone(),
                message: interchain_token_service_std::InterchainTransfer {
                    token_id: [0u8; 32].into(),
                    source_address: from_hex("00"),
                    destination_address: from_hex("00"),
                    amount: 1u64.try_into().unwrap(),
                    data: None,
                }
                .into(),
            },
            interchain_token_service_std::HubMessage::ReceiveFromHub {
                source_chain: remote_chain.clone(),
                message: interchain_token_service_std::InterchainTransfer {
                    token_id: [255u8; 32].into(),
                    source_address: from_hex("4F4495243837681061C4743b74B3eEdf548D56A5"),
                    destination_address: from_hex("4F4495243837681061C4743b74B3eEdf548D56A5"),
                    amount: Uint256::MAX.try_into().unwrap(),
                    data: Some(from_hex("abcd")),
                }
                .into(),
            },
        ];

        for original in cases {
            let encoded = hub_message_encode(original.clone())
                .expect("borsh serialization should not fail for valid data");
            let decoded = assert_ok!(hub_message_decode(encoded));
            assert_eq!(original, decoded);
        }
    }

    #[test]
    fn deploy_interchain_token_roundtrip_encode_decode() {
        let remote_chain = chain_name_raw!("chain");

        let cases = vec![
            interchain_token_service_std::HubMessage::SendToHub {
                destination_chain: remote_chain.clone(),
                message: interchain_token_service_std::DeployInterchainToken {
                    token_id: [0u8; 32].into(),
                    name: "t".try_into().unwrap(),
                    symbol: "T".try_into().unwrap(),
                    decimals: 0,
                    minter: None,
                }
                .into(),
            },
            interchain_token_service_std::HubMessage::SendToHub {
                destination_chain: remote_chain.clone(),
                message: interchain_token_service_std::DeployInterchainToken {
                    token_id: [1u8; 32].into(),
                    name: "Test Token".try_into().unwrap(),
                    symbol: "TST".try_into().unwrap(),
                    decimals: 18,
                    minter: Some(from_hex("1234")),
                }
                .into(),
            },
            interchain_token_service_std::HubMessage::SendToHub {
                destination_chain: remote_chain.clone(),
                message: interchain_token_service_std::DeployInterchainToken {
                    token_id: [0u8; 32].into(),
                    name: "Unicode Token 🪙".try_into().unwrap(),
                    symbol: "UNI🔣".try_into().unwrap(),
                    decimals: 255,
                    minter: Some(from_hex("abcd")),
                }
                .into(),
            },
            interchain_token_service_std::HubMessage::ReceiveFromHub {
                source_chain: remote_chain.clone(),
                message: interchain_token_service_std::DeployInterchainToken {
                    token_id: [0u8; 32].into(),
                    name: "t".try_into().unwrap(),
                    symbol: "T".try_into().unwrap(),
                    decimals: 0,
                    minter: None,
                }
                .into(),
            },
        ];

        for original in cases {
            let encoded = hub_message_encode(original.clone())
                .expect("borsh serialization should not fail for valid data");
            let decoded = assert_ok!(hub_message_decode(encoded));
            assert_eq!(original, decoded);
        }
    }

    #[test]
    fn link_token_roundtrip_encode_decode() {
        let remote_chain = chain_name_raw!("chain");

        let cases = vec![
            interchain_token_service_std::HubMessage::SendToHub {
                destination_chain: remote_chain.clone(),
                message: interchain_token_service_std::LinkToken {
                    token_id: [0u8; 32].into(),
                    token_manager_type: Uint256::from(0u64),
                    source_token_address: from_hex("1111111111111111111111111111111111111111"),
                    destination_token_address: from_hex("2222222222222222222222222222222222222222"),
                    params: None,
                }
                .into(),
            },
            interchain_token_service_std::HubMessage::SendToHub {
                destination_chain: remote_chain.clone(),
                message: interchain_token_service_std::LinkToken {
                    token_id: [255u8; 32].into(),
                    token_manager_type: Uint256::MAX,
                    source_token_address: from_hex("4F4495243837681061C4743b74B3eEdf548D56A5"),
                    destination_token_address: from_hex("742d35Cc6639C25B1CdBd1b8b3731b0b2E8f4321"),
                    params: Some(from_hex("deadbeef")),
                }
                .into(),
            },
            interchain_token_service_std::HubMessage::ReceiveFromHub {
                source_chain: remote_chain.clone(),
                message: interchain_token_service_std::LinkToken {
                    token_id: [0u8; 32].into(),
                    token_manager_type: Uint256::from(0u64),
                    source_token_address: from_hex("1111111111111111111111111111111111111111"),
                    destination_token_address: from_hex("2222222222222222222222222222222222222222"),
                    params: None,
                }
                .into(),
            },
        ];

        for original in cases {
            let encoded = hub_message_encode(original.clone())
                .expect("borsh serialization should not fail for valid data");
            let decoded = assert_ok!(hub_message_decode(encoded));
            assert_eq!(original, decoded);
        }
    }

    #[test]
    fn register_token_metadata_roundtrip_encode_decode() {
        let cases = vec![
            interchain_token_service_std::HubMessage::RegisterTokenMetadata(
                interchain_token_service_std::RegisterTokenMetadata {
                    decimals: 18,
                    token_address: from_hex("4F4495243837681061C4743b74B3eEdf548D56A5"),
                },
            ),
            interchain_token_service_std::HubMessage::RegisterTokenMetadata(
                interchain_token_service_std::RegisterTokenMetadata {
                    decimals: 6,
                    token_address: from_hex("A0b86a33E6441d36C3ad4d96eD9b3E5D6e6bC7a0"),
                },
            ),
        ];

        for original in cases {
            let encoded = hub_message_encode(original.clone())
                .expect("borsh serialization should not fail for valid data");
            let decoded = assert_ok!(hub_message_decode(encoded));
            assert_eq!(original, decoded);
        }
    }

    //
    // Edge cases and boundary value
    //

    #[test]
    fn uint256_boundary_values_preserved() {
        let test_amounts = vec![
            Uint256::from(1u128),
            Uint256::from(u128::MAX),
            Uint256::MAX,
            // Test a value that would be different in big-endian vs little-endian
            Uint256::from(0x0102030405060708u128),
        ];

        for amount in test_amounts {
            let original = interchain_token_service_std::InterchainTransfer {
                token_id: [0u8; 32].into(),
                source_address: from_hex("01"),
                destination_address: from_hex("02"),
                amount: amount.try_into().unwrap(),
                data: None,
            };

            let borsh_type: InterchainTransfer = original.clone().into();
            let recovered: interchain_token_service_std::InterchainTransfer =
                assert_ok!(borsh_type.try_into());

            assert_eq!(
                Uint256::from(recovered.amount),
                Uint256::from(original.amount),
                "Amount mismatch for value: {amount}"
            );
        }
    }

    #[test]
    fn large_data_payload_preserved() {
        let large_data = vec![0u8; 1024 * 1024]; // 1MB of data
        let original = interchain_token_service_std::HubMessage::SendToHub {
            destination_chain: chain_name_raw!("large-data-chain"),
            message: interchain_token_service_std::InterchainTransfer {
                token_id: [0u8; 32].into(),
                source_address: from_hex("1234"),
                destination_address: from_hex("5678"),
                amount: Uint256::from(1u128).try_into().unwrap(),
                data: Some(large_data.try_into().unwrap()),
            }
            .into(),
        };

        let encoded = hub_message_encode(original.clone())
            .expect("borsh serialization should not fail for valid data");
        let decoded = assert_ok!(hub_message_decode(encoded));
        assert_eq!(original, decoded);
    }

    //
    // Error handling
    //

    #[test]
    fn decode_fails_on_empty_required_fields() {
        // Empty source_address should fail
        let borsh_transfer = InterchainTransfer {
            token_id: [1u8; 32],
            source_address: vec![], // Empty - should fail
            destination_address: vec![1, 2],
            amount: Uint256::from(1u128).to_le_bytes(),
            data: None,
        };

        let result: Result<interchain_token_service_std::InterchainTransfer, _> =
            borsh_transfer.try_into();
        assert!(result.is_err());

        // Empty destination_address should fail
        let borsh_transfer = InterchainTransfer {
            token_id: [1u8; 32],
            source_address: vec![1, 2],
            destination_address: vec![], // Empty - should fail
            amount: Uint256::from(1u128).to_le_bytes(),
            data: None,
        };

        let result: Result<interchain_token_service_std::InterchainTransfer, _> =
            borsh_transfer.try_into();
        assert!(result.is_err());

        // Zero amount should fail
        let borsh_transfer = InterchainTransfer {
            token_id: [1u8; 32],
            source_address: vec![1, 2],
            destination_address: vec![3, 4],
            amount: Uint256::from(0u128).to_le_bytes(), // Zero - should fail
            data: None,
        };

        let result: Result<interchain_token_service_std::InterchainTransfer, _> =
            borsh_transfer.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn decode_fails_on_empty_name_or_symbol() {
        // Empty name should fail
        let borsh_deploy = DeployInterchainToken {
            token_id: [1u8; 32],
            name: String::new(), // Empty - should fail
            symbol: "TST".to_string(),
            decimals: 18,
            minter: None,
        };

        let result: Result<interchain_token_service_std::DeployInterchainToken, _> =
            borsh_deploy.try_into();
        assert!(result.is_err());

        // Empty symbol should fail
        let borsh_deploy = DeployInterchainToken {
            token_id: [1u8; 32],
            name: "Test".to_string(),
            symbol: String::new(), // Empty - should fail
            decimals: 18,
            minter: None,
        };

        let result: Result<interchain_token_service_std::DeployInterchainToken, _> =
            borsh_deploy.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn decode_fails_on_invalid_chain_name() {
        let borsh_msg = HubMessage::SendToHub {
            destination_chain: String::new(), // Empty - should fail
            message: Message::InterchainTransfer(InterchainTransfer {
                token_id: [0u8; 32],
                source_address: vec![1],
                destination_address: vec![2],
                amount: Uint256::from(1u128).to_le_bytes(),
                data: None,
            }),
        };

        let encoded = borsh::to_vec(&borsh_msg).unwrap();
        let result = hub_message_decode(encoded.into());
        assert!(result.is_err());
    }

    #[test]
    fn decode_fails_on_corrupted_data() {
        let result = hub_message_decode(vec![0xff, 0xff, 0xff].into());
        assert!(result.is_err());
    }

    #[test]
    fn decode_fails_on_empty_payload() {
        let result = hub_message_decode(vec![].into());
        assert!(result.is_err());
    }

    //
    // Snapshot tests for encoded format stability
    //

    #[test]
    fn borsh_encoded_format_stability() {
        let remote_chain = chain_name_raw!("ethereum");

        let cases = vec![
            (
                "send_to_hub__interchain_transfer",
                interchain_token_service_std::HubMessage::SendToHub {
                    destination_chain: remote_chain.clone(),
                    message: interchain_token_service_std::InterchainTransfer {
                        token_id: [0u8; 32].into(),
                        source_address: from_hex("01"),
                        destination_address: from_hex("02"),
                        amount: 1u64.try_into().unwrap(),
                        data: None,
                    }
                    .into(),
                },
            ),
            (
                "send_to_hub__interchain_transfer_data",
                interchain_token_service_std::HubMessage::SendToHub {
                    destination_chain: remote_chain.clone(),
                    message: interchain_token_service_std::InterchainTransfer {
                        token_id: [0u8; 32].into(),
                        source_address: from_hex("01"),
                        destination_address: from_hex("02"),
                        amount: 1u64.try_into().unwrap(),
                        data: Some(from_hex("03040506")),
                    }
                    .into(),
                },
            ),
            (
                "send_to_hub__deploy_token",
                interchain_token_service_std::HubMessage::SendToHub {
                    destination_chain: remote_chain.clone(),
                    message: interchain_token_service_std::DeployInterchainToken {
                        token_id: [1u8; 32].into(),
                        name: "Test".try_into().unwrap(),
                        symbol: "TST".try_into().unwrap(),
                        decimals: 18,
                        minter: None,
                    }
                    .into(),
                },
            ),
            (
                "send_to_hub__deploy_token_minter",
                interchain_token_service_std::HubMessage::SendToHub {
                    destination_chain: remote_chain.clone(),
                    message: interchain_token_service_std::DeployInterchainToken {
                        token_id: [1u8; 32].into(),
                        name: "Test".try_into().unwrap(),
                        symbol: "TST".try_into().unwrap(),
                        decimals: 18,
                        minter: Some(from_hex("abcd")),
                    }
                    .into(),
                },
            ),
            (
                "receive_from_hub__interchain_transfer",
                interchain_token_service_std::HubMessage::ReceiveFromHub {
                    source_chain: remote_chain.clone(),
                    message: interchain_token_service_std::InterchainTransfer {
                        token_id: [0u8; 32].into(),
                        source_address: from_hex("01"),
                        destination_address: from_hex("02"),
                        amount: 1u64.try_into().unwrap(),
                        data: None,
                    }
                    .into(),
                },
            ),
            (
                "receive_from_hub__deploy_token",
                interchain_token_service_std::HubMessage::ReceiveFromHub {
                    source_chain: remote_chain.clone(),
                    message: interchain_token_service_std::DeployInterchainToken {
                        token_id: [1u8; 32].into(),
                        name: "Test".try_into().unwrap(),
                        symbol: "TST".try_into().unwrap(),
                        decimals: 18,
                        minter: None,
                    }
                    .into(),
                },
            ),
            (
                "receive_from_hub__link_token",
                interchain_token_service_std::HubMessage::ReceiveFromHub {
                    source_chain: remote_chain.clone(),
                    message: interchain_token_service_std::LinkToken {
                        token_id: [2u8; 32].into(),
                        token_manager_type: Uint256::from(1u64),
                        source_token_address: from_hex("1111"),
                        destination_token_address: from_hex("2222"),
                        params: None,
                    }
                    .into(),
                },
            ),
            (
                "register_metadata",
                interchain_token_service_std::HubMessage::RegisterTokenMetadata(
                    interchain_token_service_std::RegisterTokenMetadata {
                        decimals: 6,
                        token_address: from_hex("abcd"),
                    },
                ),
            ),
        ];

        let encoded: Vec<_> = cases
            .iter()
            .map(|(name, msg)| {
                let encoded = hub_message_encode(msg.clone())
                    .expect("borsh serialization should not fail for valid data");
                (name.to_string(), encoded.to_hex())
            })
            .collect();

        goldie::assert_json!(encoded);
    }
}
