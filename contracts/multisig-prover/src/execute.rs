use std::collections::BTreeMap;

use cosmwasm_std::{
    to_json_binary, wasm_execute, Addr, DepsMut, Env, MessageInfo, QuerierWrapper, QueryRequest,
    Response, Storage, SubMsg, WasmQuery,
};

use itertools::Itertools;
use multisig::{key::PublicKey, msg::Signer, verifier_set::VerifierSet};

use axelar_wasm_std::{snapshot, MajorityThreshold, VerificationStatus};
use router_api::{ChainName, CrossChainId, Message};
use service_registry::state::WeightedVerifier;

use crate::{
    contract::START_MULTISIG_REPLY_ID,
    error::ContractError,
    payload::Payload,
    state::{Config, CONFIG, CURRENT_VERIFIER_SET, NEXT_VERIFIER_SET, PAYLOAD, REPLY_TRACKER},
    types::VerifiersInfo,
};

pub fn require_admin(deps: &DepsMut, info: MessageInfo) -> Result<(), ContractError> {
    match CONFIG.load(deps.storage)?.admin {
        admin if admin == info.sender => Ok(()),
        _ => Err(ContractError::Unauthorized),
    }
}

pub fn require_governance(deps: &DepsMut, info: MessageInfo) -> Result<(), ContractError> {
    match CONFIG.load(deps.storage)?.governance {
        governance if governance == info.sender => Ok(()),
        _ => Err(ContractError::Unauthorized),
    }
}

pub fn construct_proof(
    deps: DepsMut,
    message_ids: Vec<CrossChainId>,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let payload_id = (&message_ids).into();

    let messages = get_messages(
        deps.querier,
        message_ids,
        config.gateway.clone(),
        config.chain_name.clone(),
    )?;

    let payload = match PAYLOAD.may_load(deps.storage, &payload_id)? {
        Some(payload) => payload,
        None => {
            let payload = Payload::Messages(messages);
            PAYLOAD.save(deps.storage, &payload_id, &payload)?;

            payload
        }
    };

    // keep track of the payload id to use during submessage reply
    REPLY_TRACKER.save(deps.storage, &payload_id)?;

    let verifier_set = CURRENT_VERIFIER_SET
        .may_load(deps.storage)?
        .ok_or(ContractError::NoVerifierSet)?;

    let digest = payload.digest(config.encoder, &config.domain_separator, &verifier_set)?;

    let start_sig_msg = multisig::msg::ExecuteMsg::StartSigningSession {
        verifier_set_id: verifier_set.id(),
        msg: digest.into(),
        chain_name: config.chain_name,
        sig_verifier: None,
    };

    let wasm_msg = wasm_execute(config.multisig, &start_sig_msg, vec![])?;

    Ok(Response::new().add_submessage(SubMsg::reply_on_success(wasm_msg, START_MULTISIG_REPLY_ID)))
}

fn get_messages(
    querier: QuerierWrapper,
    message_ids: Vec<CrossChainId>,
    gateway: Addr,
    chain_name: ChainName,
) -> Result<Vec<Message>, ContractError> {
    let length = message_ids.len();

    let query = gateway_api::msg::QueryMsg::GetOutgoingMessages { message_ids };
    let messages: Vec<Message> = querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: gateway.into(),
        msg: to_json_binary(&query)?,
    }))?;

    assert_eq!(
        messages.len(),
        length,
        "violated invariant: returned gateway messages count mismatch"
    );

    if messages
        .iter()
        .any(|msg| msg.destination_chain != chain_name)
    {
        panic!("violated invariant: messages from different chain found");
    }

    Ok(messages)
}

fn get_verifiers_info(deps: &DepsMut, config: &Config) -> Result<VerifiersInfo, ContractError> {
    let active_verifiers_query = service_registry::msg::QueryMsg::GetActiveVerifiers {
        service_name: config.service_name.clone(),
        chain_name: config.chain_name.clone(),
    };

    let verifiers: Vec<WeightedVerifier> =
        deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: config.service_registry.to_string(),
            msg: to_json_binary(&active_verifiers_query)?,
        }))?;

    let participants = verifiers
        .clone()
        .into_iter()
        .map(WeightedVerifier::into)
        .collect::<Vec<snapshot::Participant>>();

    let snapshot =
        snapshot::Snapshot::new(config.signing_threshold, participants.clone().try_into()?);

    let mut pub_keys = vec![];
    for participant in &participants {
        let pub_key_query = multisig::msg::QueryMsg::GetPublicKey {
            verifier_address: participant.address.to_string(),
            key_type: config.key_type,
        };
        let pub_key: PublicKey = deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: config.multisig.to_string(),
            msg: to_json_binary(&pub_key_query)?,
        }))?;
        pub_keys.push(pub_key);
    }

    Ok(VerifiersInfo {
        snapshot,
        pubkeys_by_participant: participants.into_iter().zip(pub_keys).collect(),
    })
}

fn make_verifier_set(
    deps: &DepsMut,
    env: &Env,
    config: &Config,
) -> Result<VerifierSet, ContractError> {
    let verifiers_info = get_verifiers_info(deps, config)?;
    Ok(VerifierSet::new(
        verifiers_info.pubkeys_by_participant,
        verifiers_info.snapshot.quorum.into(),
        env.block.height,
    ))
}

fn get_next_verifier_set(
    deps: &DepsMut,
    env: &Env,
    config: &Config,
) -> Result<Option<VerifierSet>, ContractError> {
    // if there's already a pending verifiers set update, just return it
    if let Some(pending_verifier_set) = NEXT_VERIFIER_SET.may_load(deps.storage)? {
        return Ok(Some(pending_verifier_set));
    }
    let cur_verifier_set = CURRENT_VERIFIER_SET.may_load(deps.storage)?;
    let new_verifier_set = make_verifier_set(deps, env, config)?;

    match cur_verifier_set {
        Some(cur_verifier_set) => {
            if should_update_verifier_set(
                &new_verifier_set,
                &cur_verifier_set,
                config.verifier_set_diff_threshold as usize,
            ) {
                Ok(Some(new_verifier_set))
            } else {
                Ok(None)
            }
        }
        None => Err(ContractError::NoVerifierSet),
    }
}

fn save_next_verifier_set(
    storage: &mut dyn Storage,
    new_verifier_set: &VerifierSet,
) -> Result<(), ContractError> {
    if different_set_in_progress(storage, new_verifier_set) {
        return Err(ContractError::VerifierSetConfirmationInProgress);
    }

    NEXT_VERIFIER_SET.save(storage, new_verifier_set)?;
    Ok(())
}

pub fn update_verifier_set(deps: DepsMut, env: Env) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let cur_verifier_set = CURRENT_VERIFIER_SET.may_load(deps.storage)?;

    match cur_verifier_set {
        None => {
            // if no verifier set, just store it and return
            let new_verifier_set = make_verifier_set(&deps, &env, &config)?;
            CURRENT_VERIFIER_SET.save(deps.storage, &new_verifier_set)?;

            Ok(Response::new().add_message(wasm_execute(
                config.multisig,
                &multisig::msg::ExecuteMsg::RegisterVerifierSet {
                    verifier_set: new_verifier_set,
                },
                vec![],
            )?))
        }
        Some(cur_verifier_set) => {
            let new_verifier_set = get_next_verifier_set(&deps, &env, &config)?
                .ok_or(ContractError::VerifierSetUnchanged)?;

            save_next_verifier_set(deps.storage, &new_verifier_set)?;

            let payload = Payload::VerifierSet(new_verifier_set.clone());
            let payload_id = payload.id();
            PAYLOAD.save(deps.storage, &payload_id, &payload)?;
            REPLY_TRACKER.save(deps.storage, &payload_id)?;

            let digest =
                payload.digest(config.encoder, &config.domain_separator, &cur_verifier_set)?;

            let start_sig_msg = multisig::msg::ExecuteMsg::StartSigningSession {
                verifier_set_id: cur_verifier_set.id(),
                msg: digest.into(),
                sig_verifier: None,
                chain_name: config.chain_name,
            };

            Ok(Response::new()
                .add_submessage(SubMsg::reply_on_success(
                    wasm_execute(config.multisig, &start_sig_msg, vec![])?,
                    START_MULTISIG_REPLY_ID,
                ))
                .add_message(wasm_execute(
                    config.coordinator.clone(),
                    &coordinator::msg::ExecuteMsg::SetNextVerifiers {
                        next_verifier_set: new_verifier_set,
                    },
                    vec![],
                )?))
        }
    }
}

fn ensure_verifier_set_verification(
    verifier_set: &VerifierSet,
    config: &Config,
    deps: &DepsMut,
) -> Result<(), ContractError> {
    let query = voting_verifier::msg::QueryMsg::GetVerifierSetStatus {
        new_verifier_set: verifier_set.clone(),
    };

    let status: VerificationStatus = deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: config.voting_verifier.to_string(),
        msg: to_json_binary(&query)?,
    }))?;

    if status != VerificationStatus::SucceededOnSourceChain {
        Err(ContractError::VerifierSetNotConfirmed)
    } else {
        Ok(())
    }
}

pub fn confirm_verifier_set(deps: DepsMut, sender: Addr) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    let verifier_set = NEXT_VERIFIER_SET.load(deps.storage)?;

    if sender != config.governance {
        ensure_verifier_set_verification(&verifier_set, &config, &deps)?;
    }

    CURRENT_VERIFIER_SET.save(deps.storage, &verifier_set)?;
    NEXT_VERIFIER_SET.remove(deps.storage);

    Ok(Response::new()
        .add_message(wasm_execute(
            config.multisig,
            &multisig::msg::ExecuteMsg::RegisterVerifierSet {
                verifier_set: verifier_set.clone(),
            },
            vec![],
        )?)
        .add_message(wasm_execute(
            config.coordinator,
            &coordinator::msg::ExecuteMsg::SetActiveVerifiers {
                next_verifier_set: verifier_set,
            },
            vec![],
        )?))
}

pub fn should_update_verifier_set(
    new_verifiers: &VerifierSet,
    cur_verifiers: &VerifierSet,
    max_diff: usize,
) -> bool {
    new_verifiers.threshold != cur_verifiers.threshold
        || signers_symetric_difference_count(&new_verifiers.signers, &cur_verifiers.signers)
            > max_diff
}

fn signers_symetric_difference_count(
    s1: &BTreeMap<String, Signer>,
    s2: &BTreeMap<String, Signer>,
) -> usize {
    signers_difference_count(s1, s2).saturating_add(signers_difference_count(s2, s1))
}

fn signers_difference_count(s1: &BTreeMap<String, Signer>, s2: &BTreeMap<String, Signer>) -> usize {
    s1.values().filter(|v| !s2.values().contains(v)).count()
}

// Returns true if there is a different verifier set pending for confirmation, false if there is no
// verifier set pending or if the pending set is the same
fn different_set_in_progress(storage: &dyn Storage, new_verifier_set: &VerifierSet) -> bool {
    if let Ok(Some(next_verifier_set)) = NEXT_VERIFIER_SET.may_load(storage) {
        return next_verifier_set != *new_verifier_set;
    }

    false
}

pub fn update_signing_threshold(
    deps: DepsMut,
    new_signing_threshold: MajorityThreshold,
) -> Result<Response, ContractError> {
    CONFIG.update(
        deps.storage,
        |mut config| -> Result<Config, ContractError> {
            config.signing_threshold = new_signing_threshold;
            Ok(config)
        },
    )?;
    Ok(Response::new())
}

pub fn update_admin(deps: DepsMut, new_admin_address: String) -> Result<Response, ContractError> {
    CONFIG.update(
        deps.storage,
        |mut config| -> Result<Config, ContractError> {
            config.admin = deps.api.addr_validate(&new_admin_address)?;
            Ok(config)
        },
    )?;
    Ok(Response::new())
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::Threshold;
    use cosmwasm_std::{
        testing::{mock_dependencies, mock_env},
        Addr,
    };
    use router_api::ChainName;

    use crate::{
        execute::should_update_verifier_set,
        state::{Config, NEXT_VERIFIER_SET},
        test::test_data,
    };
    use std::collections::BTreeMap;

    use super::{different_set_in_progress, get_next_verifier_set};

    #[test]
    fn should_update_verifier_set_no_change() {
        let verifier_set = test_data::new_verifier_set();
        assert!(!should_update_verifier_set(&verifier_set, &verifier_set, 0));
    }

    #[test]
    fn should_update_verifier_set_one_more() {
        let verifier_set = test_data::new_verifier_set();
        let mut new_verifier_set = verifier_set.clone();
        new_verifier_set.signers.pop_first();
        assert!(should_update_verifier_set(
            &verifier_set,
            &new_verifier_set,
            0
        ));
    }

    #[test]
    fn should_update_verifier_set_one_less() {
        let verifier_set = test_data::new_verifier_set();
        let mut new_verifier_set = verifier_set.clone();
        new_verifier_set.signers.pop_first();
        assert!(should_update_verifier_set(
            &new_verifier_set,
            &verifier_set,
            0
        ));
    }

    #[test]
    fn should_update_verifier_set_one_more_higher_threshold() {
        let verifier_set = test_data::new_verifier_set();
        let mut new_verifier_set = verifier_set.clone();
        new_verifier_set.signers.pop_first();
        assert!(!should_update_verifier_set(
            &verifier_set,
            &new_verifier_set,
            1
        ));
    }

    #[test]
    fn should_update_verifier_set_diff_pub_key() {
        let verifier_set = test_data::new_verifier_set();
        let mut new_verifier_set = verifier_set.clone();
        let mut signers = new_verifier_set.signers.into_iter().collect::<Vec<_>>();
        // swap public keys
        signers[0].1.pub_key = signers[1].1.pub_key.clone();
        signers[1].1.pub_key = signers[0].1.pub_key.clone();
        new_verifier_set.signers = BTreeMap::from_iter(signers);
        assert!(should_update_verifier_set(
            &verifier_set,
            &new_verifier_set,
            0
        ));
    }

    #[test]
    fn test_no_set_pending_confirmation() {
        let deps = mock_dependencies();
        let new_verifier_set = test_data::new_verifier_set();

        assert!(!different_set_in_progress(
            deps.as_ref().storage,
            &new_verifier_set,
        ));
    }

    #[test]
    fn test_same_set_different_nonce() {
        let mut deps = mock_dependencies();
        let mut new_verifier_set = test_data::new_verifier_set();

        NEXT_VERIFIER_SET
            .save(deps.as_mut().storage, &new_verifier_set)
            .unwrap();

        new_verifier_set.created_at += 1;

        assert!(different_set_in_progress(
            deps.as_ref().storage,
            &new_verifier_set,
        ));
    }

    #[test]
    fn test_different_set_pending_confirmation() {
        let mut deps = mock_dependencies();
        let mut new_verifier_set = test_data::new_verifier_set();

        NEXT_VERIFIER_SET
            .save(deps.as_mut().storage, &new_verifier_set)
            .unwrap();

        new_verifier_set.signers.pop_first();

        assert!(different_set_in_progress(
            deps.as_ref().storage,
            &new_verifier_set,
        ));
    }

    #[test]
    fn get_next_verifier_set_should_return_pending() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let new_verifier_set = test_data::new_verifier_set();
        NEXT_VERIFIER_SET
            .save(deps.as_mut().storage, &new_verifier_set)
            .unwrap();
        let ret_verifier_set = get_next_verifier_set(&deps.as_mut(), &env, &mock_config());
        assert_eq!(ret_verifier_set.unwrap().unwrap(), new_verifier_set);
    }

    fn mock_config() -> Config {
        Config {
            admin: Addr::unchecked("doesn't matter"),
            governance: Addr::unchecked("doesn't matter"),
            gateway: Addr::unchecked("doesn't matter"),
            multisig: Addr::unchecked("doesn't matter"),
            coordinator: Addr::unchecked("doesn't matter"),
            service_registry: Addr::unchecked("doesn't matter"),
            voting_verifier: Addr::unchecked("doesn't matter"),
            signing_threshold: Threshold::try_from((2, 3)).unwrap().try_into().unwrap(),
            service_name: "validators".to_string(),
            chain_name: ChainName::try_from("ethereum".to_owned()).unwrap(),
            verifier_set_diff_threshold: 0,
            encoder: crate::encoding::Encoder::Abi,
            key_type: multisig::key::KeyType::Ecdsa,
            domain_separator: [0; 32],
        }
    }
}
