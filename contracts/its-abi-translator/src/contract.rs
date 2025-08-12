#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response};
use its_msg_translator_api::QueryMsg;

use crate::error::ContractError;

mod query;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: Empty,
) -> Result<Response, ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    match msg {
        QueryMsg::FromBytes { payload } => query::from_bytes(deps, env, payload),
        QueryMsg::ToBytes { message } => query::to_bytes(deps, env, message),
    }
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::nonempty;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cosmwasm_std::{from_json, Addr, HexBinary};
    use interchain_token_service_std::{
        DeployInterchainToken, HubMessage, InterchainTransfer, Message, TokenId,
    };
    use router_api::chain_name_raw;

    use super::*;

    #[test]
    fn instantiate_should_succeed() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = message_info(&Addr::unchecked("creator"), &[]);
        let msg = Empty {};

        let res = instantiate(deps.as_mut(), env, info, msg).unwrap();
        assert_eq!(res.messages.len(), 0);

        let version = cw2::get_contract_version(&deps.storage).unwrap();
        assert_eq!(version.contract, CONTRACT_NAME);
        assert_eq!(version.version, CONTRACT_VERSION);
    }

    #[test]
    fn query_hub_message_round_trip() {
        let deps = mock_dependencies();
        let env = mock_env();

        let hub_message = HubMessage::SendToHub {
            destination_chain: chain_name_raw!("ethereum"),
            message: Message::InterchainTransfer(InterchainTransfer {
                token_id: TokenId::new([1u8; 32]),
                source_address: nonempty::HexBinary::try_from(vec![0x11, 0x22, 0x33]).unwrap(),
                destination_address: nonempty::HexBinary::try_from(vec![0x44, 0x55, 0x66]).unwrap(),
                amount: nonempty::Uint256::try_from(1000u64).unwrap(),
                data: None,
            }),
        };

        let to_bytes_msg = QueryMsg::ToBytes {
            message: hub_message.clone(),
        };
        let bytes_result = query(deps.as_ref(), env.clone(), to_bytes_msg).unwrap();
        let payload: HexBinary = from_json(bytes_result).unwrap();

        let from_bytes_msg = QueryMsg::FromBytes {
            payload: payload.clone(),
        };
        let message_result = query(deps.as_ref(), env, from_bytes_msg).unwrap();
        let decoded_message: HubMessage = from_json(message_result).unwrap();

        assert_eq!(hub_message, decoded_message);
    }

    #[test]
    fn query_receive_from_hub_message() {
        let deps = mock_dependencies();
        let env = mock_env();

        let hub_message = HubMessage::ReceiveFromHub {
            source_chain: chain_name_raw!("ethereum"),
            message: Message::DeployInterchainToken(DeployInterchainToken {
                token_id: TokenId::new([2u8; 32]),
                name: nonempty::String::try_from("Test Token".to_string()).unwrap(),
                symbol: nonempty::String::try_from("TEST".to_string()).unwrap(),
                decimals: 18,
                minter: Some(nonempty::HexBinary::try_from(vec![0xaa, 0xbb, 0xcc]).unwrap()),
            }),
        };

        let to_bytes_msg = QueryMsg::ToBytes {
            message: hub_message.clone(),
        };
        let bytes_result = query(deps.as_ref(), env.clone(), to_bytes_msg).unwrap();
        let payload: HexBinary = from_json(bytes_result).unwrap();

        let from_bytes_msg = QueryMsg::FromBytes { payload };
        let message_result = query(deps.as_ref(), env, from_bytes_msg).unwrap();
        let decoded_message: HubMessage = from_json(message_result).unwrap();

        assert_eq!(hub_message, decoded_message);
    }

    #[test]
    fn query_from_bytes_invalid_payload() {
        let deps = mock_dependencies();
        let env = mock_env();

        let invalid_payload = HexBinary::from_hex("deadbeef").unwrap();
        let from_bytes_msg = QueryMsg::FromBytes {
            payload: invalid_payload,
        };

        let err = query(deps.as_ref(), env, from_bytes_msg).unwrap_err();
        assert_eq!(err, ContractError::SerializationFailed);
    }
}
