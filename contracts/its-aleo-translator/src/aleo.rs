use aleo_gateway_types::{ItsIncomingInterchainTransfer, ItsMessageDeployInterchainToken};
use aleo_gmp_types::aleo_struct::AxelarToLeo as _;
use aleo_gmp_types::SafeGmpChainName;
use axelar_wasm_std::{nonempty, IntoContractError};
use cosmwasm_std::{ConversionOverflowError, HexBinary};
use error_stack::{bail, report, Report};
use interchain_token_service_std::{HubMessage, Message};
use snarkvm_cosmwasm::prelude::{FromBytes as _, Network, Value};
use thiserror::Error;

use crate::aleo::to_its_hub_message::ToItsHubMessage;

mod to_its_hub_message;

#[derive(Error, Debug, IntoContractError)]
pub enum Error {
    #[error("SnarkVmError: {0}")]
    SnarkVm(#[from] snarkvm_cosmwasm::prelude::Error),
    #[error("StringEncoder: {0}")]
    StringEncoder(#[from] aleo_string_encoder::AleoStringEncoderError),
    #[error("Utf8Error: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("AleoGmpTypes: {0}")]
    AleoGmpTypes(#[from] aleo_gmp_types::error::Error),
    #[error(transparent)]
    NonEmpty(#[from] nonempty::Error),
    #[error("TranslationFailed: {0}")]
    TranslationFailed(String),
    #[error("ConversionOverflowError: {0}")]
    ConversionOverflow(#[from] ConversionOverflowError),
    #[error("Hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("Invalid chain name: {0}")]
    InvalidChainName(String),
}

/// Converts a HubMessage to snarkvm Value.
pub fn aleo_inbound_hub_message<N: Network>(
    hub_message: HubMessage,
) -> Result<Value<N>, Report<Error>> {
    match hub_message {
        HubMessage::ReceiveFromHub {
            source_chain,
            message: Message::InterchainTransfer(interchain_transfer),
        } => {
            let source_chain = SafeGmpChainName::try_from(source_chain)
                .map_err(|e| report!(Error::InvalidChainName(e.to_string())))?;
            let interchain_transfer = interchain_transfer
                .to_leo()
                .map_err(|e| report!(Error::AleoGmpTypes(e)))?;
            let interchain_transfer = ItsIncomingInterchainTransfer {
                inner_message: interchain_transfer,
                source_chain: source_chain.aleo_chain_name(),
            };
            Ok(Value::<N>::try_from(&interchain_transfer)
                .map_err(|e| report!(Error::SnarkVm(e)))?)
        }
        HubMessage::ReceiveFromHub {
            source_chain,
            message: Message::DeployInterchainToken(deploy_interchain_token),
        } => {
            let source_chain = SafeGmpChainName::try_from(source_chain)
                .map_err(|e| report!(Error::InvalidChainName(e.to_string())))?;
            let deploy_interchain_token = deploy_interchain_token
                .to_leo()
                .map_err(|e| report!(Error::AleoGmpTypes(e)))?;
            let deploy_interchain_token = ItsMessageDeployInterchainToken {
                inner_message: deploy_interchain_token,
                source_chain: source_chain.aleo_chain_name(),
            };
            Ok(Value::<N>::try_from(&deploy_interchain_token)
                .map_err(|e| report!(Error::SnarkVm(e)))?)
        }
        HubMessage::ReceiveFromHub {
            source_chain,
            message: Message::LinkToken(link_token),
        } => {
            let source_chain = SafeGmpChainName::try_from(source_chain)
                .map_err(|e| report!(Error::InvalidChainName(e.to_string())))?;
            let link_token = link_token
                .to_leo()
                .map_err(|e| report!(Error::AleoGmpTypes(e)))?;
            let link_token = aleo_gateway_types::WrappedReceivedLinkToken {
                link_token,
                source_chain: source_chain.aleo_chain_name(),
            };
            Ok(Value::<N>::try_from(&link_token).map_err(|e| report!(Error::SnarkVm(e)))?)
        }
        _ => bail!(Error::TranslationFailed(format!(
            "Unsupported HubMessage type for inbound translation: {hub_message:?}"
        ))),
    }
}

/// Converts a SnarkVM Value to HubMessage.
pub fn aleo_outbound_hub_message<N: Network>(
    payload: HexBinary,
) -> Result<HubMessage, Report<Error>> {
    let v = Value::<N>::from_bytes_le(&payload).map_err(|e| report!(Error::SnarkVm(e)))?;
    let plaintext = match v {
        Value::Plaintext(p) => p,
        _ => bail!(Error::TranslationFailed(
            "Expected Value to be of Plaintext variant".to_string()
        )),
    };

    if let Ok(its_outbound_transfer) =
        aleo_gateway_types::ItsOutgoingInterchainTransfer::<N>::try_from(&plaintext)
    {
        Ok(its_outbound_transfer.to_hub_message()?)
    } else if let Ok(remote_deploy_interchain_token) =
        aleo_gateway_types::RemoteDeployInterchainToken::try_from(&plaintext)
    {
        Ok(remote_deploy_interchain_token.to_hub_message()?)
    } else if let Ok(register_token_metadata) =
        aleo_gateway_types::RegisterTokenMetadata::try_from(&plaintext)
    {
        Ok(register_token_metadata.to_hub_message()?)
    } else if let Ok(wrapped_send_linked_token) =
        aleo_gateway_types::WrappedSendLinkToken::try_from(&plaintext)
    {
        Ok(wrapped_send_linked_token.to_hub_message()?)
    } else {
        bail!(Error::TranslationFailed(format!(
            "Failed to convert Plaintext to one of the expected types.
            Expected types are:
                1. ItsOutboundInterchainTransfer
                2. RemoteDeployInterchainToken
                3. RegisterTokenMetadata
                4. WrappedSendLinkToken
            Received plaintext: {plaintext:?}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use aleo_gateway_types::constants::{CHAIN_NAME_LEN, TOKEN_ID_LEN};
    use aleo_gmp_types::token_id_conversion::ItsTokenIdNewType;
    use aleo_gmp_types::{SafeGmpChainName, GMP_ADDRESS_LENGTH};
    use aleo_string_encoder::StringEncoder;
    use interchain_token_service_std::{InterchainTransfer, LinkToken, Message, TokenId};
    use router_api::ChainNameRaw;
    use snarkvm_cosmwasm::prelude::Address;

    use super::*;

    type CurrentNetwork = snarkvm_cosmwasm::prelude::TestnetV0;

    const EVM_DESTINATION_ADDRESS: &str = "aA411dE17e8E5C12bfac98c53670D520BB827d94";

    fn random_address<N: Network>() -> String {
        rand::random::<Address<N>>().to_string()
    }

    fn random_token_id() -> TokenId {
        rand::random::<[u8; 32]>().into()
    }

    fn eth_sepolia_chain() -> ChainNameRaw {
        ChainNameRaw::from_str("eth-sepolia").unwrap()
    }

    // Convert cosmwasm_std::HexBinary to nonempty::HexBinary
    fn from_hex_to_hex(hex: &str) -> nonempty::HexBinary {
        HexBinary::from_hex(hex)
            .expect("Valid hex string")
            .try_into()
            .expect("Valid non-empty hex binary")
    }

    fn to_hex(data: &str) -> nonempty::HexBinary {
        from_hex_to_hex(&hex::encode(data.as_bytes()))
    }

    fn format_aleo_array(data: &[u128], len: usize) -> String {
        format!(
            "[ {} ]",
            data.iter()
                .map(|n| format!("{n}u128"))
                .chain(std::iter::repeat_n(
                    "0u128".to_string(),
                    len.saturating_sub(data.len()),
                ))
                .collect::<Vec<String>>()
                .join(", ")
        )
    }

    fn format_its_token_id(token_id: TokenId) -> String {
        let its_token_id = ItsTokenIdNewType::from(token_id);
        format_aleo_array(&its_token_id.0, TOKEN_ID_LEN)
    }

    fn format_chain_name(chain_name: &ChainNameRaw) -> String {
        let safe_chain_name = SafeGmpChainName::try_from(chain_name)
            .expect("Failed to convert ChainNameRaw to SafeGmpChainName");
        format_aleo_array(&safe_chain_name.aleo_chain_name(), CHAIN_NAME_LEN)
    }

    fn format_address(address: &str) -> String {
        let encoded_address = StringEncoder::encode_string(address)
            .expect("Failed to encode string to Aleo GMP address")
            .consume();
        format_aleo_array(&encoded_address, GMP_ADDRESS_LENGTH)
    }

    struct TestTransferBuilder {
        token_id: TokenId,
        source_address: String,
        destination_address: String,
        amount: u64,
        external_chain: ChainNameRaw,
    }

    impl TestTransferBuilder {
        fn new(source_address: String, destination_address: String) -> Self {
            Self {
                token_id: random_token_id(),
                source_address,
                destination_address,
                amount: rand::random(),
                external_chain: eth_sepolia_chain(),
            }
        }

        fn inbound_hub_message(&self) -> HubMessage {
            HubMessage::ReceiveFromHub {
                source_chain: self.external_chain.clone(),
                message: Message::InterchainTransfer(InterchainTransfer {
                    token_id: self.token_id,
                    source_address: to_hex(&self.source_address),
                    destination_address: to_hex(&self.destination_address),
                    amount: self.amount.try_into().expect("Valid amount"),
                    data: None,
                }),
            }
        }

        fn outbound_hub_message(&self) -> HubMessage {
            HubMessage::SendToHub {
                destination_chain: self.external_chain.clone(),
                message: Message::InterchainTransfer(InterchainTransfer {
                    token_id: self.token_id,
                    source_address: to_hex(&self.source_address),
                    destination_address: from_hex_to_hex(&self.destination_address),
                    amount: self.amount.try_into().expect("Valid amount"),
                    data: None,
                }),
            }
        }

        fn inbound_aleo_message(&self) -> String {
            let its_token_id = format_its_token_id(self.token_id);
            let amount = self.amount;
            let destination_address = &self.destination_address;
            let source_address = format_address(&self.source_address);
            let source_chain = format_chain_name(&self.external_chain);

            let aleo_message = format!(
                "{{
                    inner_message: {{
                        its_token_id: {its_token_id},
                        source_address: {source_address},
                        destination_address: {destination_address},
                        amount: {amount}u128
                    }},
                    source_chain: {source_chain}
                }}"
            );
            aleo_message
        }

        fn outbound_aleo_message(&self) -> String {
            let its_token_id = format_its_token_id(self.token_id);
            let amount = self.amount;
            let source_address = &self.source_address;
            let destination_chain = format_chain_name(&self.external_chain);
            let destination_address = format_address(&self.destination_address);

            format!(
                "{{
                    inner_message: {{
                        its_token_id: {its_token_id},
                        source_address: {source_address},
                        destination_address: {destination_address},
                        amount: {amount}u128
                    }},
                    destination_chain: {destination_chain}
                }}",
            )
        }
    }

    struct TestDeployBuilder {
        token_id: TokenId,
        token_name: String,
        token_symbol: String,
        decimals: u8,
        minter: Option<String>,
        external_chain: ChainNameRaw,
    }

    impl TestDeployBuilder {
        fn new(minter: Option<String>) -> Self {
            let token_id = random_token_id();
            let suffix: u8 = rand::random();
            let token_name = format!("TokenName_{suffix}");
            let token_symbol = format!("TN{suffix}");
            let decimals: u8 = rand::random();
            let destination_chain = eth_sepolia_chain();

            Self {
                token_id,
                token_name,
                token_symbol,
                decimals,
                minter,
                external_chain: destination_chain,
            }
        }

        fn inbound_hub_message(&self) -> HubMessage {
            HubMessage::ReceiveFromHub {
                source_chain: self.external_chain.clone(),
                message: Message::DeployInterchainToken(
                    interchain_token_service_std::DeployInterchainToken {
                        token_id: self.token_id,
                        name: self
                            .token_name
                            .clone()
                            .try_into()
                            .expect("Valid token name"),
                        symbol: self
                            .token_symbol
                            .clone()
                            .try_into()
                            .expect("Valid token symbol"),
                        decimals: self.decimals,
                        minter: self.minter.as_ref().map(|m| to_hex(m)),
                    },
                ),
            }
        }

        fn outbound_hub_message(&self) -> HubMessage {
            HubMessage::SendToHub {
                destination_chain: self.external_chain.clone(),
                message: Message::DeployInterchainToken(
                    interchain_token_service_std::DeployInterchainToken {
                        token_id: self.token_id,
                        name: self
                            .token_name
                            .clone()
                            .try_into()
                            .expect("Valid token name"),
                        symbol: self
                            .token_symbol
                            .clone()
                            .try_into()
                            .expect("Valid token symbol"),
                        decimals: self.decimals,
                        minter: self.minter.as_ref().map(|m| from_hex_to_hex(m)),
                    },
                ),
            }
        }

        fn outbound_aleo_deploy_interchain_token(&self) -> String {
            let its_token_id = format_its_token_id(self.token_id);

            let token_name = StringEncoder::encode_string(&self.token_name)
                .expect("Failed to encode token name")
                .consume()[0];

            let token_symbol = StringEncoder::encode_string(&self.token_symbol)
                .expect("Failed to encode token symbol")
                .consume()[0];

            let decimals = self.decimals;

            let minter = self.minter.as_ref().map_or_else(Vec::new, |m| {
                StringEncoder::encode_string(m)
                    .expect("Failed to encode string to Aleo GMP address")
                    .consume()
            });
            let minter = format_aleo_array(&minter, GMP_ADDRESS_LENGTH);

            let destination_chain = format_chain_name(&self.external_chain);

            format!(
                "{{
                    payload: {{
                        its_token_id: {its_token_id},
                        name: {token_name}u128,
                        symbol: {token_symbol}u128,
                        decimals: {decimals}u8,
                        minter: {minter}
                    }},
                    destination_chain: {destination_chain}
                }}",
            )
        }

        fn inbound_aleo_deploy_interchain_token(&self) -> String {
            let its_token_id = format_its_token_id(self.token_id);

            let decimals = self.decimals;

            let minter = self.minter.as_ref().map_or_else(
                || Address::<CurrentNetwork>::zero().to_string(),
                ToString::to_string,
            );

            let source_chain = format_chain_name(&self.external_chain);

            let aleo_token_name = StringEncoder::encode_string(&self.token_name)
                .expect("Failed to encode token name")
                .consume()[0];
            let aleo_token_symbol = StringEncoder::encode_string(&self.token_symbol)
                .expect("Failed to encode token symbol")
                .consume()[0];

            format!(
                "{{
                inner_message: {{
                    its_token_id: {its_token_id},
                    name: {aleo_token_name}u128,
                    symbol: {aleo_token_symbol}u128,
                    decimals: {decimals}u8,
                    minter: {minter}
                }},
                source_chain: {source_chain}
            }}"
            )
        }
    }

    const ALEO_TOKEN_ID: &str = "3field";

    struct TestLinkToken {
        token_id: TokenId,
        source_token_address: String,
        destination_token_address: String,
        token_manager_type: u8,
        external_chain: ChainNameRaw,
    }

    impl TestLinkToken {
        fn new(source_token_address: String, destination_token_address: String) -> Self {
            Self {
                token_id: random_token_id(),
                source_token_address,
                destination_token_address,
                token_manager_type: rand::random::<u8>() % 4u8,
                external_chain: eth_sepolia_chain(),
            }
        }

        fn inbound_hub_message(&self) -> HubMessage {
            HubMessage::ReceiveFromHub {
                source_chain: self.external_chain.clone(),
                message: Message::LinkToken(LinkToken {
                    token_id: self.token_id,
                    token_manager_type: self.token_manager_type.into(),
                    source_token_address: to_hex(self.source_token_address.as_str()),
                    destination_token_address: to_hex(&self.destination_token_address),
                    params: None,
                }),
            }
        }

        fn outbound_hub_message(&self) -> HubMessage {
            HubMessage::SendToHub {
                destination_chain: self.external_chain.clone(),
                message: Message::LinkToken(LinkToken {
                    token_id: self.token_id,
                    token_manager_type: self.token_manager_type.into(),
                    source_token_address: to_hex(&self.source_token_address),
                    destination_token_address: from_hex_to_hex(&self.destination_token_address),
                    params: None,
                }),
            }
        }

        fn inbound_aleo_message(&self) -> String {
            let its_token_id = format_its_token_id(self.token_id);
            let source_chain = format_chain_name(&self.external_chain);
            let source_token_address = format_address(EVM_DESTINATION_ADDRESS);
            let destination_token_address = ALEO_TOKEN_ID;
            let token_manager_type = self.token_manager_type;
            let operator = Address::<CurrentNetwork>::zero().to_string();

            let aleo_message = format!(
                "{{
                    link_token: {{
                        its_token_id: {its_token_id},
                        token_manager_type: {token_manager_type}u8,
                        source_token_address: {source_token_address},
                        destination_token_address: {destination_token_address},
                        operator: {operator}
                    }},
                    source_chain: {source_chain}
                }}"
            );
            aleo_message
        }

        fn outbound_aleo_message(&self) -> String {
            let its_token_id = format_its_token_id(self.token_id);
            let token_manager_type = self.token_manager_type;
            let destination_chain = format_chain_name(&self.external_chain);
            let source_token_address = &self.source_token_address;
            let destination_token_address = format_address(&self.destination_token_address);
            let operator = format_aleo_array(&[0], GMP_ADDRESS_LENGTH);

            format!(
                "{{
                    link_token: {{
                        token_id: {its_token_id},
                        token_manager_type: {token_manager_type}u8,
                        aleo_token_id: {source_token_address},
                        destination_token_address: {destination_token_address},
                        operator: {operator}
                    }},
                    destination_chain: {destination_chain}
                }}",
            )
        }
    }

    mod inbound {
        use super::*;

        #[test]
        fn translate_transfer() {
            let source_address = EVM_DESTINATION_ADDRESS.to_string();
            let destination_address = random_address::<CurrentNetwork>();
            let test_transfer = TestTransferBuilder::new(source_address, destination_address);
            let its_message = test_transfer.inbound_hub_message();
            let expected_aleo_message = test_transfer.inbound_aleo_message();

            let aleo_message = aleo_inbound_hub_message::<CurrentNetwork>(its_message)
                .expect("Failed to convert HubMessage to Aleo value");

            let exected_aleo_value = Value::<CurrentNetwork>::from_str(&expected_aleo_message)
                .expect("Failed to parse Aleo value");

            assert_eq!(
                aleo_message, exected_aleo_value,
                "Expected Aleo value does not match the actual Aleo value."
            );
        }

        #[test]
        fn translate_token_deploy() {
            let test_token_deploy_without_minter = TestDeployBuilder::new(None);
            let test_token_deploy_with_minter =
                TestDeployBuilder::new(Some(random_address::<CurrentNetwork>()));

            for token_deploy_builder in [
                test_token_deploy_without_minter,
                test_token_deploy_with_minter,
            ] {
                let expected = token_deploy_builder.inbound_aleo_deploy_interchain_token();
                let expected_aleo_value = Value::<CurrentNetwork>::from_str(&expected)
                    .expect("Failed to parse expected Aleo value");
                let its_hub_message = token_deploy_builder.inbound_hub_message();

                let aleo_value = aleo_inbound_hub_message::<CurrentNetwork>(its_hub_message)
                    .expect("Failed to convert HubMessage to Aleo value");

                assert_eq!(
                    aleo_value, expected_aleo_value,
                    "Expected Aleo value does not match the actual Aleo value."
                );
            }
        }

        #[test]
        fn translate_link_token() {
            let test_data = TestLinkToken::new(
                EVM_DESTINATION_ADDRESS.to_string(),
                ALEO_TOKEN_ID.to_string(),
            );
            let its_hub_message = test_data.inbound_hub_message();

            let result = aleo_inbound_hub_message::<CurrentNetwork>(its_hub_message)
                .expect("Successful conversion");

            let aleo_value_str = test_data.inbound_aleo_message();
            let expected_aleo_value =
                Value::<CurrentNetwork>::from_str(&aleo_value_str).expect("Valid Aleo value");

            assert_eq!(
                result, expected_aleo_value,
                "Expected Aleo value does not match the actual Aleo value.",
            );
        }
    }

    mod outbound {
        use snarkvm_cosmwasm::prelude::{Field, Plaintext, ToBytes as _};

        use super::*;

        #[test]
        fn translate_transfer() {
            let test_data = TestTransferBuilder::new(
                random_address::<CurrentNetwork>(),
                EVM_DESTINATION_ADDRESS.to_string(),
            );

            let aleo_value_str = test_data.outbound_aleo_message();

            let aleo_value = Value::<CurrentNetwork>::from_str(&aleo_value_str)
                .expect("Valid Aleo value")
                .to_bytes_le()
                .expect("Valid bytes");

            let result = aleo_outbound_hub_message::<CurrentNetwork>(aleo_value.into())
                .expect("Successful conversion");

            let expected_message = test_data.outbound_hub_message();
            assert_eq!(
                result, expected_message,
                "Expected HubMessage does not match the actual HubMessage.",
            );
        }

        #[test]
        fn translate_token_deploy() {
            let test_builder_without_minter = TestDeployBuilder::new(None);
            let test_builder_with_minter =
                TestDeployBuilder::new(Some(EVM_DESTINATION_ADDRESS.to_string()));

            for test_builder in [test_builder_without_minter, test_builder_with_minter].into_iter()
            {
                let outbound_deploy_interchain_token =
                    test_builder.outbound_aleo_deploy_interchain_token();

                let aleo_value =
                    Value::<CurrentNetwork>::from_str(&outbound_deploy_interchain_token)
                        .expect("Failed to parse Aleo value")
                        .to_bytes_le()
                        .expect("Valid bytes");

                let its_hub_message =
                    aleo_outbound_hub_message::<CurrentNetwork>(aleo_value.into())
                        .expect("Failed to convert Aleo value to HubMessage");

                let expected_message = test_builder.outbound_hub_message();
                assert_eq!(
                    its_hub_message, expected_message,
                    "Expected HubMessage does not match the actual HubMessage.",
                );
            }
        }

        #[test]
        fn translate_register_token_metadata() {
            let decimals = 8u8;
            let token_address = Field::from_str("3field").expect("Valid field");

            let aleo_register_token_metadata = aleo_gateway_types::RegisterTokenMetadata {
                decimals,
                token_address,
            };
            let aleo_plaintest =
                Plaintext::try_from(&aleo_register_token_metadata).expect("Valid plaintext");
            let aleo_value = Value::<CurrentNetwork>::from(aleo_plaintest)
                .to_bytes_le()
                .expect("Valid bytes");

            let expected = HubMessage::RegisterTokenMetadata(
                interchain_token_service_std::RegisterTokenMetadata {
                    decimals,
                    token_address: to_hex(&token_address.to_string()),
                },
            );

            let its_hub_message = aleo_outbound_hub_message::<CurrentNetwork>(aleo_value.into())
                .expect("Successful conversion");
            assert_eq!(
                its_hub_message, expected,
                "Expected HubMessage does not match the actual HubMessage."
            );
        }

        #[test]
        fn translate_link_token() {
            let test_data = TestLinkToken::new(
                ALEO_TOKEN_ID.to_string(),
                EVM_DESTINATION_ADDRESS.to_string(),
            );
            let expected_message = test_data.outbound_hub_message();

            let aleo_value_str = test_data.outbound_aleo_message();
            let aleo_value = Value::<CurrentNetwork>::from_str(&aleo_value_str)
                .expect("Valid Aleo value")
                .to_bytes_le()
                .expect("Valid bytes");

            let result = aleo_outbound_hub_message::<CurrentNetwork>(aleo_value.into())
                .expect("Successful conversion");

            assert_eq!(
                result, expected_message,
                "Expected HubMessage does not match the actual HubMessage.",
            );
        }
    }
}
