use axelar_wasm_std::{nonempty, FnExt, IntoContractError};
use cosmwasm_std::{DepsMut, HexBinary, QuerierWrapper, Response, Storage};
use error_stack::{bail, ensure, report, Result, ResultExt};
use router_api::{Address, ChainName, ChainNameRaw, CrossChainId};
use sha3::{Digest, Keccak256};

use crate::events::Event;
use crate::primitives::HubMessage;
use crate::state::{self, load_config, load_its_contract};
use crate::TokenId;

// this is just keccak256("its-interchain-token-id-gateway")
const GATEWAY_TOKEN_PREFIX: [u8; 32] = [
    106, 80, 188, 250, 12, 170, 167, 223, 94, 185, 52, 185, 146, 147, 21, 23, 145, 36, 97, 146,
    215, 72, 32, 167, 6, 16, 83, 155, 176, 213, 112, 44,
];

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("unknown chain {0}")]
    UnknownChain(ChainNameRaw),
    #[error("unknown its address {0}")]
    UnknownItsContract(Address),
    #[error("failed to decode payload")]
    InvalidPayload,
    #[error("invalid message type")]
    InvalidMessageType,
    #[error("failed to register its contract for chain {0}")]
    FailedItsContractRegistration(ChainNameRaw),
    #[error("failed to deregister its contract for chain {0}")]
    FailedItsContractDeregistration(ChainNameRaw),
    #[error("failed to register gateway token")]
    FailedGatewayTokenRegistration,
    #[error("failed to generate token id")]
    FailedTokenIdGeneration,
}

/// Executes an incoming ITS message.
///
/// This function handles the execution of ITS (Interchain Token Service) messages received from
/// its sources. It verifies the source address, decodes the message, applies balance tracking,
/// and forwards the message to the destination chain.
pub fn execute_message(
    deps: DepsMut,
    cc_id: CrossChainId,
    source_address: Address,
    payload: HexBinary,
) -> Result<Response, Error> {
    ensure_its_source_address(deps.storage, &cc_id.source_chain, &source_address)?;

    match HubMessage::abi_decode(&payload).change_context(Error::InvalidPayload)? {
        HubMessage::SendToHub {
            destination_chain,
            message,
        } => {
            let destination_address = load_its_contract(deps.storage, &destination_chain)
                .change_context_lazy(|| Error::UnknownChain(destination_chain.clone()))?;

            let destination_payload = HubMessage::ReceiveFromHub {
                source_chain: cc_id.source_chain.clone(),
                message: message.clone(),
            }
            .abi_encode();

            Ok(send_to_destination(
                deps.storage,
                deps.querier,
                destination_chain.clone(),
                destination_address,
                destination_payload,
            )?
            .add_event(
                Event::MessageReceived {
                    cc_id,
                    destination_chain,
                    message,
                }
                .into(),
            ))
        }
        _ => bail!(Error::InvalidMessageType),
    }
}

fn normalize(chain: &ChainNameRaw) -> ChainName {
    ChainName::try_from(chain.as_ref()).expect("invalid chain name")
}

/// Ensures that the source address of the cross-chain message is the registered ITS contract for the source chain.
fn ensure_its_source_address(
    storage: &dyn Storage,
    source_chain: &ChainNameRaw,
    source_address: &Address,
) -> Result<(), Error> {
    let source_its_contract = load_its_contract(storage, source_chain)
        .change_context_lazy(|| Error::UnknownChain(source_chain.clone()))?;

    ensure!(
        source_address == &source_its_contract,
        Error::UnknownItsContract(source_address.clone())
    );

    Ok(())
}

fn send_to_destination(
    storage: &dyn Storage,
    querier: QuerierWrapper,
    destination_chain: ChainNameRaw,
    destination_address: Address,
    payload: HexBinary,
) -> Result<Response, Error> {
    let config = load_config(storage);

    let gateway: axelarnet_gateway::Client =
        client::ContractClient::new(querier, &config.axelarnet_gateway).into();

    let call_contract_msg =
        gateway.call_contract(normalize(&destination_chain), destination_address, payload);

    Ok(Response::new().add_message(call_contract_msg))
}

pub fn register_its_contract(
    deps: DepsMut,
    chain: ChainNameRaw,
    address: Address,
) -> Result<Response, Error> {
    state::save_its_contract(deps.storage, &chain, &address)
        .change_context_lazy(|| Error::FailedItsContractRegistration(chain.clone()))?;

    Ok(Response::new().add_event(Event::ItsContractRegistered { chain, address }.into()))
}

pub fn deregister_its_contract(deps: DepsMut, chain: ChainNameRaw) -> Result<Response, Error> {
    state::remove_its_contract(deps.storage, &chain)
        .change_context_lazy(|| Error::FailedItsContractDeregistration(chain.clone()))?;

    Ok(Response::new().add_event(Event::ItsContractDeregistered { chain }.into()))
}

pub fn register_gateway_token(
    deps: DepsMut,
    denom: nonempty::String,
    _chain: ChainNameRaw,
) -> Result<Response, Error> {
    let token_id = gateway_token_id(&deps, &denom)?;
    state::save_gateway_token_denom(deps.storage, token_id, denom)
        .change_context(Error::FailedGatewayTokenRegistration)?;
    Ok(Response::new())
}

pub fn gateway_token_id(deps: &DepsMut, denom: &str) -> Result<TokenId, Error> {
    let config = state::load_config(deps.storage);
    let gateway: axelarnet_gateway::Client =
        client::ContractClient::new(deps.querier, &config.axelarnet_gateway).into();
    let chain_name = gateway
        .chain_name()
        .change_context(Error::FailedTokenIdGeneration)?;
    let chain_name_hash: [u8; 32] = Keccak256::digest(chain_name.to_string().as_bytes()).into();

    Keccak256::digest([&GATEWAY_TOKEN_PREFIX, &chain_name_hash, denom.as_bytes()].concat())
        .then(<[u8; 32]>::from)
        .then(TokenId::new)
        .then(Ok)
}

#[cfg(test)]
mod tests {
    use assert_ok::assert_ok;
    use axelarnet_gateway::msg::QueryMsg;
    use cosmwasm_std::testing::{mock_dependencies, MockApi, MockQuerier};
    use cosmwasm_std::{from_json, to_json_binary, Addr, MemoryStorage, OwnedDeps, WasmQuery};
    use router_api::{ChainName, ChainNameRaw};

    use super::{gateway_token_id, register_gateway_token};
    use crate::state::{self, Config};

    #[test]
    fn gateway_token_id_should_be_idempotent() {
        let mut deps = init();
        let denom = "uaxl";
        let token_id = assert_ok!(gateway_token_id(&deps.as_mut(), denom));
        let token_id_2 = assert_ok!(gateway_token_id(&deps.as_mut(), denom));
        assert_eq!(token_id, token_id_2);
    }

    #[test]
    fn gateway_token_id_should_differ_for_different_denoms() {
        let mut deps = init();
        let axl_denom = "uaxl";
        let eth_denom = "eth";
        let token_id_axl = assert_ok!(gateway_token_id(&deps.as_mut(), axl_denom));
        let token_id_eth = assert_ok!(gateway_token_id(&deps.as_mut(), eth_denom));
        assert_ne!(token_id_axl, token_id_eth);
    }

    #[test]
    fn gateway_token_id_should_not_change() {
        let mut deps = init();
        let denom = "uaxl";
        let token_id = assert_ok!(gateway_token_id(&deps.as_mut(), denom));
        goldie::assert_json!(token_id);
    }

    #[test]
    fn register_token_id_should_not_overwrite() {
        let mut deps = init();
        let denom = "uaxl";
        let chain = ChainNameRaw::try_from("ethereum").unwrap();
        let res = register_gateway_token(deps.as_mut(), denom.try_into().unwrap(), chain.clone());
        assert!(res.is_ok());
        // calling again should fail
        let res = register_gateway_token(deps.as_mut(), denom.try_into().unwrap(), chain);
        assert!(res.is_err());
    }

    fn init() -> OwnedDeps<MemoryStorage, MockApi, MockQuerier> {
        let addr = Addr::unchecked("axelar-gateway");
        let mut deps = mock_dependencies();
        state::save_config(
            deps.as_mut().storage,
            &Config {
                axelarnet_gateway: addr.clone(),
            },
        )
        .unwrap();

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart { contract_addr, msg } if contract_addr == &addr.to_string() => {
                let msg = from_json::<QueryMsg>(msg).unwrap();
                match msg {
                    QueryMsg::ChainName {} => {
                        Ok(to_json_binary(&ChainName::try_from("axelar").unwrap()).into()).into()
                    }
                    _ => panic!("unsupported query"),
                }
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        deps.querier = querier;
        deps
    }
}
