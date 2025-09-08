use axelar_wasm_std::{address, permission_control, FnExt};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Attribute, Binary, Deps, DepsMut, Env, Event, MessageInfo, Response,
};
use error_stack::ResultExt;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{Config, CONFIG};

mod execute;
mod migrations;
mod query;

pub use migrations::{migrate, MigrateMsg};

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let governance = address::validate_cosmwasm_address(deps.api, &msg.governance_address)?;
    permission_control::set_governance(deps.storage, &governance)?;
    let admin = address::validate_cosmwasm_address(deps.api, &msg.admin_address)?;
    permission_control::set_admin(deps.storage, &admin)?;



    let config = Config {
        service_name: msg.service_name,
        service_registry_contract: address::validate_cosmwasm_address(
            deps.api,
            &msg.service_registry_address,
        )?,
        admin: address::validate_cosmwasm_address(deps.api, &msg.admin_address)?,
        voting_threshold: msg.voting_threshold,
        block_expiry: msg.block_expiry,
        fee: msg.fee,
    };
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new()
        .add_event(Event::new("instantiated").add_attributes(<Vec<Attribute>>::from(config))))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    match msg.ensure_permissions(deps.storage, &info.sender)? {
        ExecuteMsg::VerifyEvents(events) => Ok(execute::verify_events(deps, env, info, events)?),
        ExecuteMsg::Vote { poll_id, votes } => Ok(execute::vote(deps, env, info, poll_id, votes)?),
        ExecuteMsg::UpdateVotingThreshold {
            new_voting_threshold,
        } => Ok(execute::update_voting_threshold(
            deps,
            new_voting_threshold,
        )?),
        ExecuteMsg::UpdateFee { new_fee } => Ok(execute::update_fee(deps, info, new_fee)?),
        ExecuteMsg::Withdraw { receiver } => Ok(execute::withdraw(deps, env, info, receiver)?),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps,
    env: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::error::ContractError> {
    match msg {
        QueryMsg::Poll { poll_id } => {
            to_json_binary(&query::poll_response(deps, env.block.height, poll_id)?)
        }
        QueryMsg::EventsStatus(events) => {
            to_json_binary(&query::events_status(deps, &events, env.block.height)?)
        }
        QueryMsg::CurrentThreshold => to_json_binary(&query::voting_threshold(deps)?),
        QueryMsg::CurrentFee => to_json_binary(&query::current_fee(deps)?),
    }?
    .then(Ok)
}

#[cfg(test)]
mod test {
    use assert_ok::assert_ok;
    use axelar_wasm_std::address::AddressFormat;
    use axelar_wasm_std::msg_id::{
        Base58SolanaTxSignatureAndEventIndex, Base58TxDigestAndEventIndex,
        FieldElementAndEventIndex, HexTxHash, HexTxHashAndEventIndex, MessageIdFormat,
    };
    use axelar_wasm_std::voting::Vote;
    use axelar_wasm_std::{
        assert_err_contains, err_contains, nonempty, MajorityThreshold, Threshold,
        VerificationStatus,
    };
    use bech32::{Bech32m, Hrp};
    use cosmwasm_std::testing::{
        message_info, mock_dependencies, mock_env, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{from_json, Empty, Fraction, OwnedDeps, Uint128, Uint64, WasmQuery};
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ecdsa_test_data};
    use router_api::{ChainName, CrossChainId, Message};
    use service_registry::{AuthorizationState, BondingState, Verifier, WeightedVerifier};
    use sha3::{Digest, Keccak256, Keccak512};
    use starknet_checked_felt::CheckedFelt;
    use alloy_primitives::hex;

    use super::*;
    use crate::error::ContractError;
    use crate::events::TxEventConfirmation;
    use crate::msg::{EventId, EventToVerify};

    const SENDER: &str = "sender";
    const SERVICE_REGISTRY_ADDRESS: &str = "service_registry_address";
    // rewards address removed
    const SERVICE_NAME: &str = "service_name";
    const POLL_BLOCK_EXPIRY: u64 = 100;
    const GOVERNANCE: &str = "governance";

    fn source_chain() -> ChainName {
        "source-chain".parse().unwrap()
    }

    fn initial_voting_threshold() -> MajorityThreshold {
        Threshold::try_from((2, 3)).unwrap().try_into().unwrap()
    }

    fn assert_contract_err_strings_equal(
        actual: impl Into<axelar_wasm_std::error::ContractError>,
        expected: impl Into<axelar_wasm_std::error::ContractError>,
    ) {
        assert_eq!(actual.into().to_string(), expected.into().to_string());
    }

    fn verifiers(num_verifiers: usize) -> Vec<Verifier> {
        let mut verifiers = vec![];
        for i in 0..num_verifiers {
            verifiers.push(Verifier {
                address: MockApi::default().addr_make(format!("addr{}", i).as_str()),
                bonding_state: BondingState::Bonded {
                    amount: Uint128::from(100u128).try_into().unwrap(),
                },
                authorization_state: AuthorizationState::Authorized,
                service_name: SERVICE_NAME.parse().unwrap(),
            })
        }
        verifiers
    }

    // TODO: this makes explicit assumptions about the weight distribution strategy of the service registry, it's probably better to change it into an integration test
    fn setup(
        verifiers: Vec<Verifier>,
        msg_id_format: &MessageIdFormat,
    ) -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();
        let api = deps.api;
        let service_registry = api.addr_make(SERVICE_REGISTRY_ADDRESS);

        instantiate(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("admin"), &[]),
            InstantiateMsg {
                governance_address: api.addr_make(GOVERNANCE).as_str().parse().unwrap(),
                service_registry_address: service_registry.as_str().parse().unwrap(),
                service_name: SERVICE_NAME.parse().unwrap(),
                admin_address: api.addr_make(GOVERNANCE).as_str().parse().unwrap(),
                voting_threshold: initial_voting_threshold(),
                block_expiry: POLL_BLOCK_EXPIRY.try_into().unwrap(),
                fee: cosmwasm_std::coin(0, "uaxl"),
            },
        )
        .unwrap();

        deps.querier.update_wasm(move |wq| match wq {
            WasmQuery::Smart { contract_addr, .. }
                if contract_addr == service_registry.as_str() =>
            {
                Ok(to_json_binary(
                    &verifiers
                        .clone()
                        .into_iter()
                        .map(|v| WeightedVerifier {
                            verifier_info: v,
                            weight: nonempty::Uint128::one(),
                        })
                        .collect::<Vec<WeightedVerifier>>(),
                )
                .into())
                .into()
            }
            _ => panic!("no mock for this query"),
        });

        deps
    }

    fn message_id(id: &str, index: u64, msg_id_format: &MessageIdFormat) -> nonempty::String {
        match msg_id_format {
            MessageIdFormat::FieldElementAndEventIndex => {
                let mut id_bytes: [u8; 32] = Keccak256::digest(id.as_bytes()).into();
                id_bytes[0] = 0; // felt is ~31 bytes
                FieldElementAndEventIndex {
                    tx_hash: CheckedFelt::try_from(&id_bytes).unwrap(),
                    event_index: index,
                }
                .to_string()
                .parse()
                .unwrap()
            }
            MessageIdFormat::HexTxHashAndEventIndex => HexTxHashAndEventIndex {
                tx_hash: Keccak256::digest(id.as_bytes()).into(),
                event_index: index,
            }
            .to_string()
            .parse()
            .unwrap(),
            MessageIdFormat::Base58TxDigestAndEventIndex => Base58TxDigestAndEventIndex {
                tx_digest: Keccak256::digest(id.as_bytes()).into(),
                event_index: index,
            }
            .to_string()
            .parse()
            .unwrap(),
            MessageIdFormat::Base58SolanaTxSignatureAndEventIndex => {
                Base58SolanaTxSignatureAndEventIndex {
                    raw_signature: Keccak512::digest(id.as_bytes()).into(),
                    event_index: index,
                }
                .to_string()
                .parse()
                .unwrap()
            }
            MessageIdFormat::HexTxHash => HexTxHash {
                tx_hash: Keccak256::digest(id.as_bytes()).into(),
            }
            .to_string()
            .parse()
            .unwrap(),
            MessageIdFormat::Bech32m {
                prefix,
                length: _length,
            } => {
                let data = format!("{id}-{index}");
                let hrp = Hrp::parse(prefix).expect("valid hrp");
                bech32::encode::<Bech32m>(hrp, data.as_bytes())
                    .unwrap()
                    .to_string()
                    .parse()
                    .unwrap()
            }
        }
    }

    fn transaction_hash(id: &str, index: u64) -> String {
        let data = format!("{id}-{index}");
        let hash = Keccak256::digest(data.as_bytes());
        format!("0x{}", hex::encode(hash))
    }

    fn events(len: u64, _msg_id_format: &MessageIdFormat) -> Vec<EventToVerify> {
        (0..len)
            .map(|i| EventToVerify {
                event_id: EventId {
                    source_chain: source_chain(),
                    transaction_hash: transaction_hash("id", i),
                },
                event_data: serde_json::to_string(&serde_json::json!({
                    "Evm": {
                        "transaction_details": null,
                        "events": [{
                            "contract_address": alloy_primitives::Address::random().to_string(),
                            "event_index": i,
                            "topics": [],
                            "data": "0000000000000000000000000000000000000000000000000000000000000000"
                        }]
                    }
                })).unwrap(),
            })
            .collect()
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn mock_env_expired() -> Env {
        let mut env = mock_env();
        env.block.height += POLL_BLOCK_EXPIRY;
        env
    }



    #[test]
    fn should_be_able_to_update_threshold_and_then_query_new_threshold() {
        let msg_id_format = MessageIdFormat::HexTxHashAndEventIndex;
        let verifiers = verifiers(2);
        let mut deps = setup(verifiers.clone(), &msg_id_format);
        let api = deps.api;

        let new_voting_threshold: MajorityThreshold = Threshold::try_from((
            initial_voting_threshold().numerator().u64() + 1,
            initial_voting_threshold().denominator().u64() + 1,
        ))
        .unwrap()
        .try_into()
        .unwrap();

        execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(GOVERNANCE), &[]),
            ExecuteMsg::UpdateVotingThreshold {
                new_voting_threshold,
            },
        )
        .unwrap();

        let res = query(deps.as_ref(), mock_env(), QueryMsg::CurrentThreshold).unwrap();

        let threshold: MajorityThreshold = from_json(res).unwrap();
        assert_eq!(threshold, new_voting_threshold);
    }

    #[test]
    fn admin_update_fee_and_withdraw_permissions() {
        let msg_id_format = MessageIdFormat::HexTxHashAndEventIndex;
        let verifiers = verifiers(1);
        let mut deps = setup(verifiers, &msg_id_format);
        let api = deps.api;

        // Unauthorized update_fee by non-admin
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("not-admin"), &[]),
            ExecuteMsg::UpdateFee { new_fee: cosmwasm_std::coin(1, "uaxl") },
        );
        assert!(res.is_err());

        // Authorized update_fee by admin (governance address used as admin in setup)
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(GOVERNANCE), &[]),
            ExecuteMsg::UpdateFee { new_fee: cosmwasm_std::coin(2, "uaxl") },
        );
        assert!(res.is_ok());

        // Unauthorized withdraw by non-admin
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("not-admin"), &[]),
            ExecuteMsg::Withdraw { receiver: api.addr_make("rcv").as_str().parse().unwrap() },
        );
        assert!(res.is_err());

        // Authorized withdraw by admin
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(GOVERNANCE), &[]),
            ExecuteMsg::Withdraw { receiver: api.addr_make("rcv").as_str().parse().unwrap() },
        );
        assert!(res.is_ok());
    }

	#[test]
	fn verify_events_should_fail_when_source_chains_differ() {
		let msg_id_format = MessageIdFormat::HexTxHashAndEventIndex;
		let verifiers = verifiers(2);
		let mut deps = setup(verifiers, &msg_id_format);
		let api = deps.api;

		let mut evs = events(2, &msg_id_format);
		// change the second event's source chain to a different one
		evs[1].event_id.source_chain = "another-chain".parse().unwrap();

		let res = execute(
			deps.as_mut(),
			mock_env(),
			message_info(&api.addr_make(SENDER), &[]),
			ExecuteMsg::VerifyEvents(evs),
		);

		let err = res.expect_err("expected SourceChainMismatch error");
		assert_contract_err_strings_equal(
			err,
			ContractError::SourceChainMismatch(source_chain()),
		);
	}
}
