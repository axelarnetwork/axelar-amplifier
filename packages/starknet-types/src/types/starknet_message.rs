use std::str::FromStr;

use error_stack::{Report, ResultExt};
use ethers_core::abi::{
    AbiDecode, AbiError, AbiType, Detokenize, FixedBytes, InvalidOutputType, ParamType, Token,
    Tokenizable,
};
use ethers_core::types::{Address, Selector, U256};
use router_api::Message as RouterMessage;
use starknet_core::types::Felt;

use crate::error::Error;

/// A message that is encoded in the prover and later sent to the Starknet gateway.
#[derive(Clone, Debug, PartialEq)]
pub struct StarknetMessage {
    pub source_chain: String,
    pub message_id: String,
    pub source_address: String,
    pub contract_address: Felt,
    pub payload_hash: U256,
}

impl TryFrom<&RouterMessage> for StarknetMessage {
    type Error = Report<Error>;

    fn try_from(msg: &RouterMessage) -> Result<Self, Self::Error> {
        let contract_address = Felt::from_str(msg.destination_address.as_str())
            .change_context(Error::InvalidAddress)?;

        Ok(StarknetMessage {
            source_chain: msg.cc_id.source_chain.to_string(),
            message_id: msg.cc_id.message_id.to_string(),
            source_address: msg.source_address.to_string(),
            contract_address,
            payload_hash: U256::from(msg.payload_hash),
        })
    }
}

impl AbiType for StarknetMessage {
    fn param_type() -> ParamType {
        ParamType::Tuple(vec![
            ethers_core::abi::ParamType::String,
            ethers_core::abi::ParamType::String,
            ethers_core::abi::ParamType::String,
            ethers_core::abi::ParamType::FixedBytes(32usize),
            <U256 as AbiType>::param_type(),
        ])
    }
}

impl AbiDecode for StarknetMessage {
    fn decode(bytes: impl AsRef<[u8]>) -> Result<Self, AbiError> {
        let tokens = ethers_core::abi::decode(&[Self::param_type()], bytes.as_ref())?;
        Ok(<Self as Detokenize>::from_tokens(tokens)?)
    }
}

impl Tokenizable for StarknetMessage {
    fn from_token(token: Token) -> Result<Self, InvalidOutputType>
    where
        Self: Sized,
    {
        if let Token::Tuple(tokens) = token {
            if tokens.len() != 5 {
                return Err(InvalidOutputType(
                    "failed to read tokens: starknet message should have 5 tokens".to_string(),
                ));
            }

            if let (
                Token::String(source_chain),
                Token::String(message_id),
                Token::String(source_address),
                Token::FixedBytes(contract_address),
                Token::Uint(payload_hash),
            ) = (
                tokens[0].clone(),
                tokens[1].clone(),
                tokens[2].clone(),
                tokens[3].clone(),
                tokens[4].clone(),
            ) {
                let contract_address_bytes: [u8; 32] =
                    contract_address.try_into().map_err(|_| {
                        InvalidOutputType(
                            "failed to convert contract_address to bytes32".to_string(),
                        )
                    })?;

                let contract_address_felt: Felt = Felt::from_bytes_be(&contract_address_bytes);

                return Ok(StarknetMessage {
                    source_chain,
                    message_id,
                    source_address,
                    contract_address: contract_address_felt,
                    payload_hash: U256::from(payload_hash),
                });
            }
        }

        return Err(InvalidOutputType(
            "failed to convert tokens to StarknetMessage".to_string(),
        ));
    }

    fn into_token(self) -> Token {
        let contract_address_bytes = self.contract_address.to_bytes_be().to_vec();

        Token::Tuple(vec![
            Token::String(self.source_chain),
            Token::String(self.message_id),
            Token::String(self.source_address),
            Token::FixedBytes(contract_address_bytes),
            Token::Uint(self.payload_hash),
        ])
    }
}

#[cfg(test)]
mod tests {
    use ethers_core::abi::{InvalidOutputType, Token, Tokenizable};
    use ethers_core::types::U256;
    use starknet_core::types::Felt;

    use super::StarknetMessage;

    #[test]
    fn starknet_message_from_token_should_error_on_non_tuple() {
        // pas something else than a Token::Tuple
        let starknet_msg_token = Token::String("not a starknet message".to_string());

        let result = StarknetMessage::from_token(starknet_msg_token);

        // Tested like this, because InvalidOutputType doesn't implement PartialEq
        assert!(
            matches!(result, Err(InvalidOutputType(msg)) if msg == "failed to convert tokens to StarknetMessage")
        );
    }

    #[test]
    fn starknet_message_from_token_should_error_on_failing_felt_conversion() {
        // overflow the 31 byte size of a Felt
        let starknet_msg_token = Token::Tuple(vec![
            Token::String("starknet".to_string()),
            Token::String("some_msg_id".to_string()),
            Token::String("some_source_address".to_string()),
            Token::FixedBytes(vec![
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            ]),
            Token::Uint(U256::from(123)),
        ]);

        let result = StarknetMessage::from_token(starknet_msg_token);

        // Tested like this, because InvalidOutputType doesn't implement PartialEq
        assert!(
            matches!(result, Err(InvalidOutputType(msg)) if msg == "failed to convert contract_address bytes to field element (felt)")
        );
    }

    #[test]
    fn starknet_message_from_token_should_error_on_failing_contract_address_conversion() {
        // more than 32 bytes for contract address
        let starknet_msg_token = Token::Tuple(vec![
            Token::String("starknet".to_string()),
            Token::String("some_msg_id".to_string()),
            Token::String("some_source_address".to_string()),
            Token::FixedBytes(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 3, 2, 1,
            ]),
            Token::Uint(U256::from(123)),
        ]);

        let result = StarknetMessage::from_token(starknet_msg_token);

        // Tested like this, because InvalidOutputType doesn't implement PartialEq
        assert!(
            matches!(result, Err(InvalidOutputType(msg)) if msg == "failed to convert contract_address to bytes32")
        );
    }

    #[test]
    fn starknet_message_from_token_should_error_on_less_tokens() {
        // removed last token
        let starknet_msg_token = Token::Tuple(vec![
            Token::String("starknet".to_string()),
            Token::String("some_msg_id".to_string()),
            Token::String("some_source_address".to_string()),
            Token::FixedBytes(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 3,
            ]),
        ]);

        let result = StarknetMessage::from_token(starknet_msg_token);

        // Tested like this, because InvalidOutputType doesn't implement PartialEq
        assert!(
            matches!(result, Err(InvalidOutputType(msg)) if msg == "failed to read tokens: starknet message should have 5 tokens")
        );
    }

    #[test]
    fn starknet_message_from_token_should_be_converted_from_tokens_successfully() {
        let starknet_msg_token = Token::Tuple(vec![
            Token::String("starknet".to_string()),
            Token::String("some_msg_id".to_string()),
            Token::String("some_source_address".to_string()),
            Token::FixedBytes(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 3,
            ]),
            Token::Uint(U256::from(123)),
        ]);

        let expected = StarknetMessage {
            source_chain: "starknet".to_string(),
            message_id: "some_msg_id".to_string(),
            source_address: "some_source_address".to_string(),
            contract_address: Felt::THREE,
            payload_hash: U256::from(123),
        };

        assert_eq!(
            StarknetMessage::from_token(starknet_msg_token).unwrap(),
            expected
        );
    }

    #[test]
    fn starknet_message_should_convert_to_token() {
        let starknet_message = StarknetMessage {
            source_chain: "starknet".to_string(),
            message_id: "some_msg_id".to_string(),
            source_address: "some_source_address".to_string(),
            contract_address: Felt::THREE,
            payload_hash: U256::from(123),
        };

        let expected = Token::Tuple(vec![
            Token::String("starknet".to_string()),
            Token::String("some_msg_id".to_string()),
            Token::String("some_source_address".to_string()),
            Token::FixedBytes(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 3,
            ]),
            Token::Uint(U256::from(123)),
        ]);

        assert_eq!(starknet_message.into_token(), expected);
    }
}
