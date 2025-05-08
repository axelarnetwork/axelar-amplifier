use std::collections::{BTreeMap, HashSet};

use axelar_wasm_std::permission_control::Permission;
use axelar_wasm_std::snapshot::{Participant, Snapshot};
use axelar_wasm_std::{
    address, nonempty, permission_control, FnExt, MajorityThreshold, VerificationStatus,
};
use cosmwasm_std::{wasm_execute, Addr, DepsMut, Env, QuerierWrapper, Response, Storage, SubMsg};
use error_stack::{report, Result, ResultExt};
use itertools::Itertools;
use multisig::msg::Signer;
use multisig::verifier_set::VerifierSet;
use router_api::{ChainName, CrossChainId, Message};
use service_registry_api::WeightedVerifier;

use crate::contract::START_MULTISIG_REPLY_ID;
use crate::encoding::EncoderExt;
use crate::error::ContractError;
use crate::state::{
    Config, CONFIG, CURRENT_VERIFIER_SET, NEXT_VERIFIER_SET, PAYLOAD, REPLY_TRACKER,
};
use crate::{Encoder, Payload};

pub fn construct_proof(
    deps: DepsMut,
    message_ids: Vec<CrossChainId>,
) -> error_stack::Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage).map_err(ContractError::from)?;

    let messages = messages(
        deps.querier,
        message_ids,
        config.gateway.clone(),
        config.chain_name.clone(),
    )?;

    let payload = Payload::Messages(messages);
    let payload_id = payload.id();

    match PAYLOAD
        .may_load(deps.storage, &payload_id)
        .map_err(ContractError::from)?
    {
        Some(stored_payload) => {
            if stored_payload != payload {
                return Err(report!(ContractError::PayloadMismatch))
                    .attach_printable_lazy(|| format!("{:?}", stored_payload));
            }
        }
        None => {
            PAYLOAD
                .save(deps.storage, &payload_id, &payload)
                .map_err(ContractError::from)?;
        }
    };

    // keep track of the payload id to use during submessage reply
    REPLY_TRACKER
        .save(deps.storage, &payload_id)
        .map_err(ContractError::from)?;

    let verifier_set = CURRENT_VERIFIER_SET
        .may_load(deps.storage)
        .map_err(ContractError::from)?
        .ok_or(ContractError::NoVerifierSet)?;

    let digest = config
        .encoder
        .digest(&config.domain_separator, &verifier_set, &payload)?;

    let start_sig_msg = multisig::msg::ExecuteMsg::StartSigningSession {
        verifier_set_id: verifier_set.id(),
        msg: digest.into(),
        chain_name: config.chain_name,
        sig_verifier: None,
    };

    let wasm_msg =
        wasm_execute(config.multisig, &start_sig_msg, vec![]).map_err(ContractError::from)?;

    Ok(Response::new().add_submessage(SubMsg::reply_on_success(wasm_msg, START_MULTISIG_REPLY_ID)))
}

fn messages(
    querier: QuerierWrapper,
    message_ids: Vec<CrossChainId>,
    gateway: Addr,
    chain_name: ChainName,
) -> Result<Vec<Message>, ContractError> {
    let length = message_ids.len();

    let gateway: gateway_api::Client = client::ContractClient::new(querier, &gateway).into();

    let messages = gateway
        .outgoing_messages(message_ids)
        .change_context(ContractError::FailedToGetMessages)?;

    assert_eq!(
        messages.len(),
        length,
        "violated invariant: returned gateway messages count mismatch"
    );

    if let Some(wrong_destination) = messages
        .iter()
        .find(|msg| msg.destination_chain != chain_name)
    {
        Err(ContractError::InvalidDestinationChain {
            expected: chain_name,
            actual: wrong_destination.destination_chain.clone(),
        }
        .into())
    } else {
        Ok(messages)
    }
}

fn make_verifier_set(
    deps: &DepsMut,
    env: &Env,
    config: &Config<Encoder>,
) -> Result<VerifierSet, ContractError> {
    let service_registry: service_registry_api::Client =
        client::ContractClient::new(deps.querier, &config.service_registry).into();

    let verifiers: Vec<WeightedVerifier> = service_registry
        .active_verifiers(config.service_name.clone(), config.chain_name.to_owned())
        .change_context(ContractError::FailedToBuildVerifierSet)?;

    let min_num_verifiers = service_registry
        .service(config.service_name.clone())
        .change_context(ContractError::FailedToBuildVerifierSet)?
        .min_num_verifiers;

    let multisig: multisig::Client =
        client::ContractClient::new(deps.querier, &config.multisig).into();

    let participants_with_pubkeys = verifiers
        .into_iter()
        .filter_map(|verifier| {
            match multisig.public_key(verifier.verifier_info.address.to_string(), config.key_type) {
                Ok(pub_key) => Some((Participant::from(verifier), pub_key)),
                Err(_) => None,
            }
        })
        .collect::<Vec<_>>();

    if participants_with_pubkeys.len() < min_num_verifiers as usize {
        return Err(ContractError::NotEnoughVerifiers.into());
    }

    let snapshot = Snapshot::new(
        config.signing_threshold,
        nonempty::Vec::<Participant>::try_from(
            participants_with_pubkeys
                .iter()
                .map(|(participant, _)| participant.clone())
                .collect::<Vec<_>>(),
        )
        .change_context(ContractError::FailedToBuildVerifierSet)?,
    );

    Ok(VerifierSet::new(
        participants_with_pubkeys,
        snapshot.quorum.into(),
        env.block.height,
    ))
}

fn next_verifier_set(
    deps: &DepsMut,
    env: &Env,
    config: &Config<Encoder>,
) -> Result<Option<VerifierSet>, ContractError> {
    // if there's already a pending verifiers set update, just return it
    if let Some(pending_verifier_set) = NEXT_VERIFIER_SET
        .may_load(deps.storage)
        .change_context(ContractError::StorageError)?
    {
        return Ok(Some(pending_verifier_set));
    }
    let cur_verifier_set = CURRENT_VERIFIER_SET
        .may_load(deps.storage)
        .change_context(ContractError::StorageError)?;
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
        None => Err(ContractError::NoVerifierSet.into()),
    }
}

fn save_next_verifier_set(
    storage: &mut dyn Storage,
    new_verifier_set: &VerifierSet,
) -> Result<(), ContractError> {
    if different_set_in_progress(storage, new_verifier_set) {
        return Err(ContractError::VerifierSetConfirmationInProgress.into());
    }

    NEXT_VERIFIER_SET
        .save(storage, new_verifier_set)
        .change_context(ContractError::StorageError)?;
    Ok(())
}

pub fn update_verifier_set(
    deps: DepsMut,
    env: Env,
) -> error_stack::Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage).map_err(ContractError::from)?;

    let coordinator: coordinator::Client =
        client::ContractClient::new(deps.querier, &config.coordinator).into();

    let multisig: multisig::Client =
        client::ContractClient::new(deps.querier, &config.multisig).into();

    let cur_verifier_set = CURRENT_VERIFIER_SET
        .may_load(deps.storage)
        .map_err(ContractError::from)?;

    match cur_verifier_set {
        None => {
            // if no verifier set, just store it and return
            let new_verifier_set = make_verifier_set(&deps, &env, &config)?;
            CURRENT_VERIFIER_SET
                .save(deps.storage, &new_verifier_set)
                .map_err(ContractError::from)?;

            Ok(Response::new()
                .add_message(multisig.register_verifier_set(new_verifier_set.clone()))
                .add_message(
                    coordinator.set_active_verifiers(
                        new_verifier_set
                            .signers
                            .values()
                            .map(|signer| signer.address.to_string())
                            .collect::<HashSet<String>>(),
                    ),
                ))
        }
        Some(cur_verifier_set) => {
            let new_verifier_set = next_verifier_set(&deps, &env, &config)?
                .ok_or(ContractError::VerifierSetUnchanged)?;

            save_next_verifier_set(deps.storage, &new_verifier_set)?;

            let payload = Payload::VerifierSet(new_verifier_set.clone());
            let payload_id = payload.id();
            PAYLOAD
                .save(deps.storage, &payload_id, &payload)
                .map_err(ContractError::from)?;
            REPLY_TRACKER
                .save(deps.storage, &payload_id)
                .map_err(ContractError::from)?;

            let digest =
                config
                    .encoder
                    .digest(&config.domain_separator, &cur_verifier_set, &payload)?;

            let verifier_union_set = all_active_verifiers(deps.storage)?;

            Ok(Response::new()
                .add_submessage(SubMsg::reply_on_success(
                    multisig.start_signing_session(
                        cur_verifier_set.id(),
                        digest.into(),
                        config.chain_name,
                        None,
                    ),
                    START_MULTISIG_REPLY_ID,
                ))
                .add_message(coordinator.set_active_verifiers(
                    verifier_union_set.iter().map(|v| v.to_string()).collect(),
                )))
        }
    }
}

fn ensure_verifier_set_verification(
    verifier_set: &VerifierSet,
    config: &Config<Encoder>,
    deps: &DepsMut,
) -> Result<(), ContractError> {
    let verifier: voting_verifier::Client =
        client::ContractClient::new(deps.querier, &config.voting_verifier).into();
    let status = verifier
        .verifier_set_status(verifier_set.clone())
        .change_context(ContractError::FailedToVerifyVerifierSet)?;

    if status != VerificationStatus::SucceededOnSourceChain {
        Err(ContractError::VerifierSetNotConfirmed.into())
    } else {
        Ok(())
    }
}

pub fn confirm_verifier_set(deps: DepsMut, sender: Addr) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage).expect("failed to load config");

    let verifier_set = NEXT_VERIFIER_SET
        .may_load(deps.storage)
        .change_context(ContractError::StorageError)?
        .ok_or(ContractError::NoVerifierSetToConfirm)?;

    let sender_role = permission_control::sender_role(deps.storage, &sender)
        .change_context(ContractError::StorageError)?;
    if !sender_role.contains(Permission::Governance) {
        ensure_verifier_set_verification(&verifier_set, &config, &deps)?;
    }

    CURRENT_VERIFIER_SET
        .save(deps.storage, &verifier_set)
        .change_context(ContractError::StorageError)?;
    NEXT_VERIFIER_SET.remove(deps.storage);

    let verifier_union_set = all_active_verifiers(deps.storage)?;

    let coordinator: coordinator::Client =
        client::ContractClient::new(deps.querier, &config.coordinator).into();

    let multisig: multisig::Client =
        client::ContractClient::new(deps.querier, &config.multisig).into();

    Ok(Response::new()
        .add_message(multisig.register_verifier_set(verifier_set))
        .add_message(
            coordinator
                .set_active_verifiers(verifier_union_set.iter().map(|v| v.to_string()).collect()),
        ))
}

pub fn all_active_verifiers(storage: &mut dyn Storage) -> Result<HashSet<String>, ContractError> {
    let current_signers = CURRENT_VERIFIER_SET
        .may_load(storage)
        .change_context(ContractError::StorageError)?
        .map(|verifier_set| verifier_set.signers)
        .unwrap_or_default();

    let next_signers = NEXT_VERIFIER_SET
        .may_load(storage)
        .change_context(ContractError::StorageError)?
        .map(|verifier_set| verifier_set.signers)
        .unwrap_or_default();

    current_signers
        .values()
        .chain(next_signers.values())
        .map(|signer| signer.address.to_string())
        .collect::<HashSet<String>>()
        .then(Ok)
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
    CONFIG
        .update(
            deps.storage,
            |mut config| -> std::result::Result<Config<Encoder>, ContractError> {
                config.signing_threshold = new_signing_threshold;
                Ok(config)
            },
        )
        .change_context(ContractError::StorageError)?;
    Ok(Response::new())
}

pub fn update_admin(deps: DepsMut, new_admin_address: String) -> Result<Response, ContractError> {
    let new_admin = address::validate_cosmwasm_address(deps.api, &new_admin_address)
        .change_context(ContractError::FailedToUpdateAdmin)?;
    permission_control::set_admin(deps.storage, &new_admin)
        .change_context(ContractError::FailedToUpdateAdmin)?;
    Ok(Response::new())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use axelar_wasm_std::Threshold;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, MockApi};
    use router_api::ChainName;

    use super::{different_set_in_progress, next_verifier_set, should_update_verifier_set};
    use crate::state::{Config, NEXT_VERIFIER_SET};
    use crate::test::test_data;
    use crate::Encoder;

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
    fn next_verifier_set_should_return_pending() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let new_verifier_set = test_data::new_verifier_set();
        NEXT_VERIFIER_SET
            .save(deps.as_mut().storage, &new_verifier_set)
            .unwrap();
        let ret_verifier_set = next_verifier_set(&deps.as_mut(), &env, &mock_config());
        assert_eq!(ret_verifier_set.unwrap().unwrap(), new_verifier_set);
    }

    fn mock_config() -> Config<Encoder> {
        Config {
            gateway: MockApi::default().addr_make("doesn't matter"),
            multisig: MockApi::default().addr_make("doesn't matter"),
            coordinator: MockApi::default().addr_make("doesn't matter"),
            service_registry: MockApi::default().addr_make("doesn't matter"),
            voting_verifier: MockApi::default().addr_make("doesn't matter"),
            signing_threshold: Threshold::try_from((2, 3)).unwrap().try_into().unwrap(),
            service_name: "validators".to_string(),
            chain_name: ChainName::try_from("ethereum".to_owned()).unwrap(),
            verifier_set_diff_threshold: 0,
            encoder: crate::Encoder::Abi,
            key_type: multisig::key::KeyType::Ecdsa,
            domain_separator: [0; 32],
        }
    }
}
