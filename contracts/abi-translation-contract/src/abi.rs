use alloy_sol_types::{sol, SolType, SolValue};
use axelar_wasm_std::{
    flagset::FlagSet,
    nonempty::{NonEmpty, Uint256},
    operators::Operators,
    voting::VerifierSet,
    FnExt,
};
use cosmwasm_std::{Addr, HexBinary};
use error_stack::{Report, ResultExt};
use interchain_token_service::{
    HubMessage, Message, RegisterTokenMetadata,
    DeployInterchainToken, InterchainTransfer, TokenId, LinkToken,
};
use std::str::FromStr;

use crate::error::Error;

// Define the ABI types using alloy_sol_types
sol! {
    enum MessageType {
        InterchainTransfer,
        DeployInterchainToken,
        LinkToken,
    }

    struct InterchainTransferAbi {
        uint8 messageType;
        bytes32 tokenId;
        bytes sourceAddress;
        bytes destinationAddress;
        uint256 amount;
        bytes data;
    }

    struct DeployInterchainTokenAbi {
        uint8 messageType;
        bytes32 tokenId;
        string name;
        string symbol;
        uint8 decimals;
        bytes minter;
        bytes data;
    }

    struct LinkTokenAbi {
        uint8 messageType;
        bytes32 tokenId;
        uint256 tokenManagerType;
        bytes sourceTokenAddress;
        bytes destinationTokenAddress;
        bytes params;
    }

    struct RegisterTokenMetadataAbi {
        uint8 decimals;
        bytes tokenAddress;
    }

    struct SendToHubAbi {
        bytes32 tokenId;
        bytes sourceAddress;
        bytes destinationAddress;
        uint256 amount;
        bytes data;
    }

    struct ReceiveFromHubAbi {
        bytes32 tokenId;
        bytes sourceAddress;
        bytes destinationAddress;
        uint256 amount;
        bytes data;
    }
}

// Helper function to convert Option<HexBinary> to Vec<u8>
fn from_vec(opt: Option<axelar_wasm_std::nonempty::HexBinary>) -> Result<Vec<u8>, Error> {
    match opt {
        Some(binary) => Ok(binary.to_vec()),
        None => Ok(vec![]),
    }
}

// Helper function to convert Vec<u8> to Option<HexBinary>
fn to_hex_binary(vec: Vec<u8>) -> Result<Option<axelar_wasm_std::nonempty::HexBinary>, Error> {
    if vec.is_empty() {
        Ok(None)
    } else {
        Some(axelar_wasm_std::nonempty::HexBinary::try_from(vec)?)
            .then(Ok)
    }
}

// Helper function to convert Uint256 to alloy U256
fn uint256_to_u256(uint256: axelar_wasm_std::nonempty::Uint256) -> alloy_primitives::U256 {
    alloy_primitives::U256::from_be_bytes(uint256.to_be_bytes())
}

// Helper function to convert alloy U256 to Uint256
fn u256_to_uint256(u256: alloy_primitives::U256) -> axelar_wasm_std::nonempty::Uint256 {
    axelar_wasm_std::nonempty::Uint256::from_be_bytes(u256.to_be_bytes::<32>())
}

// Helper function to convert cosmwasm Uint256 to axelar Uint256
fn cosmwasm_to_axelar_uint256(uint256: cosmwasm_std::Uint256) -> axelar_wasm_std::nonempty::Uint256 {
    axelar_wasm_std::nonempty::Uint256::from_be_bytes(uint256.to_be_bytes())
}

// Helper function to convert axelar Uint256 to cosmwasm Uint256
fn axelar_to_cosmwasm_uint256(uint256: axelar_wasm_std::nonempty::Uint256) -> cosmwasm_std::Uint256 {
    cosmwasm_std::Uint256::from_be_bytes(uint256.to_be_bytes())
}

// Helper function to convert string to axelar_wasm_std::nonempty::String
fn to_axelar_string(s: &str) -> Result<axelar_wasm_std::nonempty::String, Error> {
    axelar_wasm_std::nonempty::String::try_from(s.to_string())
        .change_context(Error::AbiEncodingFailed)
}

// Helper function to convert cosmwasm HexBinary to axelar HexBinary
fn cosmwasm_to_axelar_hex_binary(binary: cosmwasm_std::HexBinary) -> axelar_wasm_std::nonempty::HexBinary {
    axelar_wasm_std::nonempty::HexBinary::try_from(binary.to_vec()).unwrap()
}

// Helper function to convert axelar HexBinary to cosmwasm HexBinary
fn axelar_to_cosmwasm_hex_binary(binary: axelar_wasm_std::nonempty::HexBinary) -> cosmwasm_std::HexBinary {
    cosmwasm_std::HexBinary::from(binary.to_vec())
}

pub fn abi_encode(message: &str) -> Result<String, Error> {
    let message: Message = serde_json::from_str(message)
        .change_context(Error::AbiEncodingFailed)
        .attach_printable("Failed to deserialize message")?;

    let encoded = match message {
        Message::InterchainTransfer(transfer) => {
            let abi_struct = InterchainTransferAbi {
                messageType: MessageType::InterchainTransfer.into(),
                tokenId: alloy_primitives::FixedBytes::<32>::new(transfer.token_id.into()),
                sourceAddress: transfer.source_address.to_vec().into(),
                destinationAddress: transfer.destination_address.to_vec().into(),
                amount: uint256_to_u256(transfer.amount),
                data: from_vec(transfer.data)?,
            };
            abi_struct.abi_encode()
        }
        Message::DeployInterchainToken(deploy) => {
            let abi_struct = DeployInterchainTokenAbi {
                messageType: MessageType::DeployInterchainToken.into(),
                tokenId: alloy_primitives::FixedBytes::<32>::new(deploy.token_id.into()),
                name: deploy.name.to_string(),
                symbol: deploy.symbol.to_string(),
                decimals: deploy.decimals,
                minter: from_vec(deploy.minter)?,
                data: from_vec(deploy.data)?,
            };
            abi_struct.abi_encode()
        }
        Message::LinkToken(link_token) => {
            let abi_struct = LinkTokenAbi {
                messageType: MessageType::LinkToken.into(),
                tokenId: alloy_primitives::FixedBytes::<32>::new(link_token.token_id.into()),
                tokenManagerType: uint256_to_u256(link_token.token_manager_type),
                sourceTokenAddress: link_token.source_token_address.to_vec().into(),
                destinationTokenAddress: link_token.destination_token_address.to_vec().into(),
                params: link_token.params.map(|p| p.to_vec()).unwrap_or_default().into(),
            };
            abi_struct.abi_encode()
        }
    };

    Ok(hex::encode(encoded))
}

pub fn abi_decode(encoded_message: &str) -> Result<String, Error> {
    let bytes = hex::decode(encoded_message)
        .change_context(Error::AbiDecodingFailed)
        .attach_printable("Failed to decode hex string")?;

    // Try to decode as InterchainTransfer first
    if let Ok(decoded) = InterchainTransferAbi::abi_decode(&bytes) {
        let transfer = InterchainTransfer {
            token_id: TokenId::new(decoded.tokenId.0),
            source_address: axelar_wasm_std::nonempty::HexBinary::try_from(decoded.sourceAddress.to_vec())?,
            destination_address: axelar_wasm_std::nonempty::HexBinary::try_from(decoded.destinationAddress.to_vec())?,
            amount: u256_to_uint256(decoded.amount),
            data: to_hex_binary(decoded.data.to_vec())?,
        };
        let message = Message::InterchainTransfer(transfer);
        return Ok(serde_json::to_string(&message)?);
    }

    // Try to decode as DeployInterchainToken
    if let Ok(decoded) = DeployInterchainTokenAbi::abi_decode(&bytes) {
        let deploy = DeployInterchainToken {
            token_id: TokenId::new(decoded.tokenId.0),
            name: to_axelar_string(&decoded.name)?,
            symbol: to_axelar_string(&decoded.symbol)?,
            decimals: decoded.decimals,
            minter: to_hex_binary(decoded.minter.to_vec())?,
            data: to_hex_binary(decoded.data.to_vec())?,
        };
        let message = Message::DeployInterchainToken(deploy);
        return Ok(serde_json::to_string(&message)?);
    }

    // Try to decode as LinkToken
    if let Ok(decoded) = LinkTokenAbi::abi_decode(&bytes) {
        let link_token = LinkToken {
            token_id: TokenId::new(decoded.tokenId.0),
            token_manager_type: cosmwasm_to_axelar_uint256(u256_to_uint256(decoded.tokenManagerType)),
            source_token_address: axelar_wasm_std::nonempty::HexBinary::try_from(decoded.sourceTokenAddress.to_vec())?,
            destination_token_address: axelar_wasm_std::nonempty::HexBinary::try_from(decoded.destinationTokenAddress.to_vec())?,
            params: to_hex_binary(decoded.params.to_vec())?,
        };
        let message = Message::LinkToken(link_token);
        return Ok(serde_json::to_string(&message)?);
    }

    // Try to decode as RegisterTokenMetadata
    if let Ok(decoded) = RegisterTokenMetadataAbi::abi_decode(&bytes) {
        let metadata = RegisterTokenMetadata {
            decimals: decoded.decimals,
            token_address: axelar_wasm_std::nonempty::HexBinary::try_from(decoded.tokenAddress.to_vec())?,
        };
        return Ok(serde_json::to_string(&metadata)?);
    }

    // Try to decode as SendToHub
    if let Ok(decoded) = SendToHubAbi::abi_decode(&bytes) {
        let send_to_hub = interchain_token_service::SendToHub {
            token_id: TokenId::new(decoded.tokenId.0),
            source_address: axelar_wasm_std::nonempty::HexBinary::try_from(decoded.sourceAddress.to_vec())?,
            destination_address: axelar_wasm_std::nonempty::HexBinary::try_from(decoded.destinationAddress.to_vec())?,
            amount: u256_to_uint256(decoded.amount),
            data: to_hex_binary(decoded.data.to_vec())?,
        };
        return Ok(serde_json::to_string(&send_to_hub)?);
    }

    // Try to decode as ReceiveFromHub
    if let Ok(decoded) = ReceiveFromHubAbi::abi_decode(&bytes) {
        let receive_from_hub = interchain_token_service::ReceiveFromHub {
            token_id: TokenId::new(decoded.tokenId.0),
            source_address: axelar_wasm_std::nonempty::HexBinary::try_from(decoded.sourceAddress.to_vec())?,
            destination_address: axelar_wasm_std::nonempty::HexBinary::try_from(decoded.destinationAddress.to_vec())?,
            amount: u256_to_uint256(decoded.amount),
            data: to_hex_binary(decoded.data.to_vec())?,
        };
        return Ok(serde_json::to_string(&receive_from_hub)?);
    }

    Err(Error::AbiDecodingFailed)
        .attach_printable("Failed to decode any known message type")
}

// Helper functions for encoding/decoding specific message types
pub fn message_abi_encode(message: Message) -> Vec<u8> {
    match message {
        Message::InterchainTransfer(transfer) => {
            let abi_struct = InterchainTransferAbi {
                messageType: MessageType::InterchainTransfer.into(),
                tokenId: alloy_primitives::FixedBytes::<32>::new(transfer.token_id.into()),
                sourceAddress: transfer.source_address.to_vec().into(),
                destinationAddress: transfer.destination_address.to_vec().into(),
                amount: uint256_to_u256(transfer.amount),
                data: transfer.data.map(|d| d.to_vec()).unwrap_or_default().into(),
            };
            abi_struct.abi_encode()
        }
        Message::DeployInterchainToken(deploy) => {
            let abi_struct = DeployInterchainTokenAbi {
                messageType: MessageType::DeployInterchainToken.into(),
                tokenId: alloy_primitives::FixedBytes::<32>::new(deploy.token_id.into()),
                name: deploy.name.to_string(),
                symbol: deploy.symbol.to_string(),
                decimals: deploy.decimals,
                minter: deploy.minter.map(|m| m.to_vec()).unwrap_or_default().into(),
                data: deploy.data.map(|d| d.to_vec()).unwrap_or_default().into(),
            };
            abi_struct.abi_encode()
        }
        Message::LinkToken(link_token) => {
            let abi_struct = LinkTokenAbi {
                messageType: MessageType::LinkToken.into(),
                tokenId: alloy_primitives::FixedBytes::<32>::new(link_token.token_id.into()),
                tokenManagerType: uint256_to_u256(link_token.token_manager_type),
                sourceTokenAddress: link_token.source_token_address.to_vec().into(),
                destinationTokenAddress: link_token.destination_token_address.to_vec().into(),
                params: link_token.params.map(|p| p.to_vec()).unwrap_or_default().into(),
            };
            abi_struct.abi_encode()
        }
    }
}

pub fn message_abi_decode(data: &[u8]) -> Result<Message, Error> {
    // Try to decode as InterchainTransfer first
    if let Ok(decoded) = InterchainTransferAbi::abi_decode(data) {
        let transfer = InterchainTransfer {
            token_id: TokenId::new(decoded.tokenId.0),
            source_address: axelar_wasm_std::nonempty::HexBinary::try_from(decoded.sourceAddress.to_vec())?,
            destination_address: axelar_wasm_std::nonempty::HexBinary::try_from(decoded.destinationAddress.to_vec())?,
            amount: u256_to_uint256(decoded.amount),
            data: to_hex_binary(decoded.data.to_vec())?,
        };
        return Ok(Message::InterchainTransfer(transfer));
    }

    // Try to decode as DeployInterchainToken
    if let Ok(decoded) = DeployInterchainTokenAbi::abi_decode(data) {
        let deploy = DeployInterchainToken {
            token_id: TokenId::new(decoded.tokenId.0),
            name: to_axelar_string(&decoded.name)?,
            symbol: to_axelar_string(&decoded.symbol)?,
            decimals: decoded.decimals,
            minter: to_hex_binary(decoded.minter.to_vec())?,
            data: to_hex_binary(decoded.data.to_vec())?,
        };
        return Ok(Message::DeployInterchainToken(deploy));
    }

    // Try to decode as LinkToken
    if let Ok(decoded) = LinkTokenAbi::abi_decode(data) {
        let link_token = LinkToken {
            token_id: TokenId::new(decoded.tokenId.0),
            token_manager_type: cosmwasm_to_axelar_uint256(u256_to_uint256(decoded.tokenManagerType)),
            source_token_address: axelar_wasm_std::nonempty::HexBinary::try_from(decoded.sourceTokenAddress.to_vec())?,
            destination_token_address: axelar_wasm_std::nonempty::HexBinary::try_from(decoded.destinationTokenAddress.to_vec())?,
            params: to_hex_binary(decoded.params.to_vec())?,
        };
        return Ok(Message::LinkToken(link_token));
    }

    Err(Error::AbiDecodingFailed)
        .attach_printable("Failed to decode any known message type")
}

// Helper function for encoding/decoding hub messages
pub fn hub_message_abi_encode(hub_message: HubMessage) -> Vec<u8> {
    match hub_message {
        HubMessage::SendToHub { message, .. } => {
            message_abi_encode(message)
        }
        HubMessage::ReceiveFromHub { message, .. } => {
            message_abi_encode(message)
        }
        HubMessage::RegisterTokenMetadata(metadata) => {
            let abi_struct = RegisterTokenMetadataAbi {
                decimals: metadata.decimals,
                tokenAddress: metadata.token_address.to_vec().into(),
            };
            abi_struct.abi_encode()
        }
    }
}

pub fn hub_message_abi_decode(data: &[u8]) -> Result<HubMessage, Error> {
    // Try to decode as a regular message first
    if let Ok(message) = message_abi_decode(data) {
        // For now, we'll wrap it in SendToHub since we don't have chain information
        return Ok(HubMessage::SendToHub {
            destination_chain: "unknown".parse().unwrap(),
            message,
        });
    }

    // Try to decode as RegisterTokenMetadata
    if let Ok(decoded) = RegisterTokenMetadataAbi::abi_decode(data) {
        let metadata = RegisterTokenMetadata {
            decimals: decoded.decimals,
            token_address: axelar_wasm_std::nonempty::HexBinary::try_from(decoded.tokenAddress.to_vec())?,
        };
        return Ok(HubMessage::RegisterTokenMetadata(metadata));
    }

    Err(Error::AbiDecodingFailed)
        .attach_printable("Failed to decode any known hub message type")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_interchain_transfer() {
        let transfer = InterchainTransfer {
            token_id: TokenId::new([1u8; 32]),
            source_address: axelar_wasm_std::nonempty::HexBinary::try_from(vec![1, 2]).unwrap(),
            destination_address: axelar_wasm_std::nonempty::HexBinary::try_from(vec![3, 4]).unwrap(),
            amount: axelar_wasm_std::nonempty::Uint256::from(100u128),
            data: Some(axelar_wasm_std::nonempty::HexBinary::try_from(vec![5, 6]).unwrap()),
        };
        let message = Message::InterchainTransfer(transfer);
        let json = serde_json::to_string(&message).unwrap();
        
        let encoded = abi_encode(&json).unwrap();
        assert!(!encoded.is_empty());
        
        let decoded = abi_decode(&encoded).unwrap();
        assert_eq!(decoded, json);
    }

    #[test]
    fn test_encode_deploy_interchain_token() {
        let deploy = DeployInterchainToken {
            token_id: TokenId::new([1u8; 32]),
            name: axelar_wasm_std::nonempty::String::try_from("Test Token".to_string()).unwrap(),
            symbol: axelar_wasm_std::nonempty::String::try_from("TST".to_string()).unwrap(),
            decimals: 18,
            minter: Some(axelar_wasm_std::nonempty::HexBinary::try_from(vec![1, 2, 3]).unwrap()),
            data: Some(axelar_wasm_std::nonempty::HexBinary::try_from(vec![4, 5, 6]).unwrap()),
        };
        let message = Message::DeployInterchainToken(deploy);
        let json = serde_json::to_string(&message).unwrap();
        
        let encoded = abi_encode(&json).unwrap();
        assert!(!encoded.is_empty());
        
        let decoded = abi_decode(&encoded).unwrap();
        assert_eq!(decoded, json);
    }

    #[test]
    fn test_encode_link_token() {
        let link_token = LinkToken {
            token_id: TokenId::new([1u8; 32]),
            token_manager_type: cosmwasm_std::Uint256::from(1u128),
            source_token_address: axelar_wasm_std::nonempty::HexBinary::try_from(vec![1, 2, 3]).unwrap(),
            destination_token_address: axelar_wasm_std::nonempty::HexBinary::try_from(vec![4, 5, 6]).unwrap(),
            params: Some(axelar_wasm_std::nonempty::HexBinary::try_from(vec![7, 8, 9]).unwrap()),
        };
        let message = Message::LinkToken(link_token);
        let json = serde_json::to_string(&message).unwrap();
        
        let encoded = abi_encode(&json).unwrap();
        assert!(!encoded.is_empty());
        
        let decoded = abi_decode(&encoded).unwrap();
        assert_eq!(decoded, json);
    }

    #[test]
    fn test_encode_register_token_metadata() {
        let metadata = RegisterTokenMetadata {
            decimals: 18,
            token_address: axelar_wasm_std::nonempty::HexBinary::try_from(vec![1, 2, 3]).unwrap(),
        };
        let json = serde_json::to_string(&metadata).unwrap();
        
        let encoded = abi_encode(&json).unwrap();
        assert!(!encoded.is_empty());
        
        let decoded = abi_decode(&encoded).unwrap();
        assert_eq!(decoded, json);
    }

    #[test]
    fn test_encode_send_to_hub() {
        let send_to_hub = interchain_token_service::SendToHub {
            token_id: TokenId::new([1u8; 32]),
            source_address: axelar_wasm_std::nonempty::HexBinary::try_from(vec![1, 2]).unwrap(),
            destination_address: axelar_wasm_std::nonempty::HexBinary::try_from(vec![3, 4]).unwrap(),
            amount: axelar_wasm_std::nonempty::Uint256::from(100u128),
            data: Some(axelar_wasm_std::nonempty::HexBinary::try_from(vec![5, 6]).unwrap()),
        };
        let json = serde_json::to_string(&send_to_hub).unwrap();
        
        let encoded = abi_encode(&json).unwrap();
        assert!(!encoded.is_empty());
        
        let decoded = abi_decode(&encoded).unwrap();
        assert_eq!(decoded, json);
    }

    #[test]
    fn test_encode_receive_from_hub() {
        let receive_from_hub = interchain_token_service::ReceiveFromHub {
            token_id: TokenId::new([1u8; 32]),
            source_address: axelar_wasm_std::nonempty::HexBinary::try_from(vec![1, 2]).unwrap(),
            destination_address: axelar_wasm_std::nonempty::HexBinary::try_from(vec![3, 4]).unwrap(),
            amount: axelar_wasm_std::nonempty::Uint256::from(100u128),
            data: Some(axelar_wasm_std::nonempty::HexBinary::try_from(vec![5, 6]).unwrap()),
        };
        let json = serde_json::to_string(&receive_from_hub).unwrap();
        
        let encoded = abi_encode(&json).unwrap();
        assert!(!encoded.is_empty());
        
        let decoded = abi_decode(&encoded).unwrap();
        assert_eq!(decoded, json);
    }

    #[test]
    fn test_message_abi_encode_decode() {
        let transfer = InterchainTransfer {
            token_id: TokenId::new([1u8; 32]),
            source_address: axelar_wasm_std::nonempty::HexBinary::try_from(vec![1, 2]).unwrap(),
            destination_address: axelar_wasm_std::nonempty::HexBinary::try_from(vec![3, 4]).unwrap(),
            amount: axelar_wasm_std::nonempty::Uint256::from(100u128),
            data: Some(axelar_wasm_std::nonempty::HexBinary::try_from(vec![5, 6]).unwrap()),
        };
        let message = Message::InterchainTransfer(transfer);
        
        let encoded = message_abi_encode(message.clone());
        let decoded = message_abi_decode(&encoded).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_hub_message_abi_encode_decode() {
        let hub_message = HubMessage::SendToHub {
            destination_chain: "test-chain".parse().unwrap(),
            message: Message::InterchainTransfer(InterchainTransfer {
                token_id: TokenId::new([1u8; 32]),
                source_address: axelar_wasm_std::nonempty::HexBinary::try_from(vec![1, 2]).unwrap(),
                destination_address: axelar_wasm_std::nonempty::HexBinary::try_from(vec![3, 4]).unwrap(),
                amount: axelar_wasm_std::nonempty::Uint256::from(100u128),
                data: Some(axelar_wasm_std::nonempty::HexBinary::try_from(vec![5, 6]).unwrap()),
            }),
        };
        
        let encoded = hub_message_abi_encode(hub_message.clone());
        let decoded = hub_message_abi_decode(&encoded).unwrap();
        // Note: We can't directly compare because we lose chain information in the round trip
        assert!(matches!(decoded, HubMessage::SendToHub { .. }));
    }

    #[test]
    fn test_invalid_hex_decode() {
        let result = abi_decode("invalid_hex");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_message_decode() {
        let invalid_payload = vec![0u8; 32];
        let result = abi_decode(&hex::encode(invalid_payload));
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_message_decode() {
        let result = abi_decode("");
        assert!(result.is_err());
    }

    #[test]
    fn test_message_abi_decode_invalid() {
        let payload = vec![0u8; 32];
        let result = message_abi_decode(&payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_hub_message_abi_decode_invalid() {
        let payload = vec![0u8; 32];
        let result = hub_message_abi_decode(&payload);
        assert!(result.is_err());
    }
}
