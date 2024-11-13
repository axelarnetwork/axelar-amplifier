use std::collections::HashSet;

use axelar_wasm_std::{address, permission_control, FnExt, VerificationStatus};
use axelar_wasm_std::MajorityThreshold;
use interchain_token_service::HubMessage;
use router_api::CrossChainId;
use cosmwasm_std::{
    wasm_execute, Addr, DepsMut, Env, HexBinary, Response, Storage, SubMsg, Uint128, Uint256, Uint64
};

use multisig::{key::PublicKey, types::MultisigState};
use sha3::{Keccak256, Digest};
use xrpl_types::error::XRPLError;
use xrpl_types::msg::XRPLMessage;
use xrpl_types::types::canonicalize_coin_amount;
use xrpl_types::types::{
    TxHash, XRPLToken, XRPLSigner, XRPLSignedTransaction, XRPLPaymentAmount, XRPLAccountId,
    XRPLTokenOrXRP
};

use crate::axelar_verifiers;
use crate::error::ContractError;
use crate::querier::Querier;
use crate::state::{self, Config};
use crate::xrpl_multisig;
use crate::xrpl_serialize::XRPLSerialize;

use super::START_MULTISIG_REPLY_ID;

pub fn construct_trust_set_proof(
    storage: &mut dyn Storage,
    self_address: Addr,
    config: &Config,
    xrpl_token: XRPLToken,
) -> Result<Response, ContractError> {
    // TODO: check if trust set already set
    let tx_hash = xrpl_multisig::issue_trust_set(storage, config, xrpl_token)?;

    let cur_verifier_set = state::CURRENT_VERIFIER_SET.load(storage).map_err(|_| ContractError::NoVerifierSet)?;
    let cur_verifier_set_id = Into::<multisig::verifier_set::VerifierSet>::into(cur_verifier_set).id();

    Ok(Response::new().add_submessage(start_signing_session(storage, config, tx_hash, self_address, cur_verifier_set_id)?))
}

pub fn construct_ticket_create_proof(
    storage: &mut dyn Storage,
    self_address: Addr,
    config: &Config,
) -> Result<Response, ContractError> {
    let ticket_count = xrpl_multisig::tickets_available_to_request(storage)?;
    if ticket_count < config.ticket_count_threshold {
        return Err(ContractError::TicketCountThresholdNotReached);
    }

    let tx_hash = xrpl_multisig::issue_ticket_create(storage, config, ticket_count)?;

    let cur_verifier_set = state::CURRENT_VERIFIER_SET.load(storage).map_err(|_| ContractError::NoVerifierSet)?;
    let cur_verifier_set_id = Into::<multisig::verifier_set::VerifierSet>::into(cur_verifier_set).id();

    Ok(Response::new().add_submessage(start_signing_session(storage, config, tx_hash, self_address, cur_verifier_set_id)?))
}

pub fn update_tx_status(
    storage: &mut dyn Storage,
    querier: &Querier,
    config: &Config,
    multisig_session_id: &Uint64,
    signer_public_keys: &[PublicKey],
    tx_id: TxHash,
) -> Result<Response, ContractError> {
    let unsigned_tx_hash =
        state::MULTISIG_SESSION_ID_TO_TX_HASH.load(storage, multisig_session_id.u64())?;
    let tx_info = state::TRANSACTION_INFO.load(storage, &unsigned_tx_hash)?;
    let multisig_session = querier.multisig(multisig_session_id)?;

    let xrpl_signers: Vec<XRPLSigner> = multisig_session
        .verifier_set
        .signers
        .into_iter()
        .filter(|(_, signer)| signer_public_keys.contains(&signer.pub_key))
        .filter_map(|(signer_address, signer)| multisig_session.signatures.get(&signer_address).cloned().zip(Some(signer)))
        .map(XRPLSigner::try_from)
        .collect::<Result<Vec<XRPLSigner>, XRPLError>>()?;

    if xrpl_signers.len() != signer_public_keys.len() {
        return Err(ContractError::SignatureNotFound);
    }

    let signed_tx = XRPLSignedTransaction::new(tx_info.unsigned_contents, xrpl_signers);
    let signed_tx_blob = HexBinary::from(signed_tx.xrpl_serialize()?);
    let signed_tx_hash = xrpl_types::types::hash_signed_tx(signed_tx_blob.as_slice())?;

    if tx_id != signed_tx_hash {
        return Err(ContractError::InvalidTxId(tx_id.to_string()));
    }

    let message = XRPLMessage::ProverMessage(tx_id);
    let status = querier.message_status(message)?;

    match status {
        VerificationStatus::Unknown |
        VerificationStatus::FailedToVerify => {
            return Err(ContractError::TxStatusUnknown);
        },
        VerificationStatus::InProgress => {
            return Err(ContractError::TxStatusVerificationInProgress);
        },
        _ => {}
    }

    Ok(match xrpl_multisig::update_tx_status(storage, unsigned_tx_hash, status.into())? {
        None => Response::default(),
        Some(confirmed_verifier_set) => {
            Response::new()
                .add_message(wasm_execute(
                    config.multisig.clone(),
                    &multisig::msg::ExecuteMsg::RegisterVerifierSet {
                        verifier_set: confirmed_verifier_set.clone().into(),
                    },
                    vec![],
                )?)
                .add_message(wasm_execute(
                    config.coordinator.clone(),
                    &coordinator::msg::ExecuteMsg::SetActiveVerifiers {
                        verifiers: confirmed_verifier_set
                            .signers
                            .iter()
                            .map(|signer| signer.address.to_string())
                            .collect::<HashSet<String>>(),
                    },
                    vec![],
                )?)
        }
    })
}

fn save_next_verifier_set(
    storage: &mut dyn Storage,
    new_verifier_set: &axelar_verifiers::VerifierSet,
) -> Result<(), ContractError> {
    if different_set_in_progress(storage, new_verifier_set) {
        return Err(ContractError::VerifierSetConfirmationInProgress);
    }

    state::NEXT_VERIFIER_SET.save(storage, new_verifier_set)?;
    Ok(())
}

// Returns true if there is a different verifier set pending for confirmation, false if there is no
// verifier set pending or if the pending set is the same
fn different_set_in_progress(storage: &dyn Storage, new_verifier_set: &axelar_verifiers::VerifierSet) -> bool {
    if let Ok(Some(next_verifier_set)) = state::NEXT_VERIFIER_SET.may_load(storage) {
        return next_verifier_set != *new_verifier_set;
    }

    false
}

pub fn update_signing_threshold(
    deps: DepsMut,
    new_signing_threshold: MajorityThreshold,
) -> Result<Response, ContractError> {
    state::CONFIG.update(
        deps.storage,
        |mut config| -> Result<Config, ContractError> {
            config.signing_threshold = new_signing_threshold;
            Ok(config)
        },
    )?;
    Ok(Response::new())
}

pub fn update_admin(deps: DepsMut, new_admin_address: String) -> Result<Response, ContractError> {
    let new_admin = address::validate_cosmwasm_address(deps.api, &new_admin_address)
        .map_err(|_| ContractError::FailedToUpdateAdmin)?;
    permission_control::set_admin(deps.storage, &new_admin)
        .map_err(|_| ContractError::FailedToUpdateAdmin)?;
    Ok(Response::new())
}

const XRP_DECIMALS: u8 = 6;

// TODO: remove: this conversion is temporary--will be handled by ITS Hub
fn scale_down_to_drops(amount: Uint256, from_decimals: u8) -> u64 {
    assert!(from_decimals > XRP_DECIMALS);
    let scaling_factor = Uint256::from(10u128.pow(u32::from(from_decimals - XRP_DECIMALS)));
    let new_amount = Uint128::try_from(amount / scaling_factor).unwrap();
    u64::try_from(new_amount.u128()).unwrap()
}

pub fn construct_payment_proof(
    storage: &mut dyn Storage,
    querier: &Querier,
    self_address: Addr,
    block_height: u64,
    config: &Config,
    message_id: CrossChainId,
    payload: HexBinary,
) -> Result<Response, ContractError> {
    // Prevent creating a duplicate signing session before the previous one expires
    if let Some(multisig_session) =
        state::MESSAGE_ID_TO_MULTISIG_SESSION.may_load(storage, &message_id)?
    {
        match querier.multisig(&Uint64::from(multisig_session.id))?.state {
            MultisigState::Pending => {
                if multisig_session.expires_at <= block_height {
                    return Err(ContractError::PaymentAlreadyHasActiveSigningSession(
                        multisig_session.id,
                    ));
                }
            }
            MultisigState::Completed { .. } => {
                return Err(ContractError::PaymentAlreadyHasCompletedSigningSession(
                    multisig_session.id
                ));
            }
        }
    };

    let message = querier.outgoing_message(&message_id)?;

    // Message source chain (Axelar) and source address (ITS hub) has been validated by the gateway.
    // TODO: Check with Axelar if this destination chain check is necessary.
    if message.destination_chain != config.chain_name {
        return Err(ContractError::InvalidDestinationChain {
            expected: config.chain_name.clone(),
            actual: message.destination_chain,
        });
    }

    let payload_hash: [u8; 32] = Keccak256::digest(payload.as_slice()).into();
    if message.payload_hash != payload_hash {
        return Err(ContractError::PayloadHashMismatch {
            expected: message.payload_hash,
            actual: payload_hash,
        });
    }

    let its_hub_message = HubMessage::abi_decode(payload.as_slice()).map_err(|_| ContractError::InvalidPayload)?;
    match its_hub_message {
        HubMessage::SendToHub { .. } => {
            Err(ContractError::InvalidPayload)
        },
        HubMessage::ReceiveFromHub { source_chain, message } => {
            match message {
                // Source address (ITS on source chain) has been validated by ITS hub.
                interchain_token_service::Message::InterchainTransfer { token_id, source_address: _, destination_address, amount, data: _ } => {
                    // TODO: Consider enforcing that data is None for simple payments.
                    let xrpl_payment_amount = if token_id == XRPLTokenOrXRP::XRP.token_id() { // TODO: Optimize: Do not compute XRP token ID every time.
                        let drops = if source_chain == config.xrpl_evm_sidechain_chain_name {
                            scale_down_to_drops(amount.into(), 18u8)
                        } else {
                            u64::try_from(Uint128::try_from(Uint256::from(amount)).unwrap().u128()).unwrap()
                        };
                        XRPLPaymentAmount::Drops(drops)
                    } else {
                        let token_info = querier.token_info(token_id)?;
                        // TODO: handle decimal precision conversion
                        XRPLPaymentAmount::Token(token_info.xrpl_token, canonicalize_coin_amount(Uint128::try_from(Uint256::from(amount)).unwrap(), token_info.canonical_decimals)?)
                    };

                    let destination_address: XRPLAccountId = destination_address
                        .try_into()
                        .map_err(|_| ContractError::InvalidDestinationAddress)?;

                    let tx_hash = xrpl_multisig::issue_payment(
                        storage,
                        config,
                        destination_address,
                        &xrpl_payment_amount,
                        &message_id,
                        None // TODO: Handle cross-currency payments.
                    )?;

                    let cur_verifier_set = state::CURRENT_VERIFIER_SET.load(storage).map_err(|_| ContractError::NoVerifierSet)?;
                    let cur_verifier_set_id = Into::<multisig::verifier_set::VerifierSet>::into(cur_verifier_set).id();

                    state::REPLY_MESSAGE_ID.save(storage, &message_id)?;
                    Ok(Response::new().add_submessage(start_signing_session(storage, config, tx_hash, self_address, cur_verifier_set_id)?))
                },
                interchain_token_service::Message::DeployInterchainToken { .. } => {
                    Err(ContractError::InvalidPayload)
                },
                interchain_token_service::Message::DeployTokenManager { .. } => {
                    Err(ContractError::InvalidPayload)
                },
            }
        }
    }
}

fn start_signing_session(
    storage: &mut dyn Storage,
    config: &Config,
    tx_hash: TxHash,
    self_address: Addr,
    cur_verifier_set_id: String,
) -> Result<SubMsg<cosmwasm_std::Empty>, ContractError> {
    state::REPLY_TX_HASH.save(storage, &tx_hash)?;

    let start_sig_msg: multisig::msg::ExecuteMsg = multisig::msg::ExecuteMsg::StartSigningSession {
        verifier_set_id: cur_verifier_set_id,
        msg: tx_hash.into(),
        chain_name: config.chain_name.clone(),
        sig_verifier: Some(self_address.into()),
    };

    let wasm_msg = wasm_execute(&config.multisig, &start_sig_msg, vec![])?;

    Ok(SubMsg::reply_on_success(wasm_msg, START_MULTISIG_REPLY_ID))
}

pub fn update_verifier_set(
    storage: &mut dyn Storage,
    querier: &Querier,
    env: Env,
) -> Result<Response, ContractError> {
    let config = state::CONFIG.load(storage).map_err(ContractError::from)?;
    let cur_verifier_set = state::CURRENT_VERIFIER_SET
        .may_load(storage)
        .map_err(ContractError::from)?;

    match cur_verifier_set {
        None => {
            // if no verifier set, just store it and return
            let new_verifier_set = axelar_verifiers::active_verifiers(querier, config.signing_threshold, env.block.height)?;
            state::CURRENT_VERIFIER_SET
                .save(storage, &new_verifier_set)
                .map_err(ContractError::from)?;

            Ok(Response::new().add_message(
                wasm_execute(
                    config.multisig,
                    &multisig::msg::ExecuteMsg::RegisterVerifierSet {
                        verifier_set: new_verifier_set.into(),
                    },
                    vec![],
                )
                .map_err(ContractError::from)?,
            ))
        }
        Some(cur_verifier_set) => {
            let new_verifier_set = next_verifier_set(storage, querier, &env, &config)?
                .ok_or(ContractError::VerifierSetUnchanged)?;

            save_next_verifier_set(storage, &new_verifier_set)?;

            let verifier_union_set = all_active_verifiers(storage)?;
            let tx_hash = xrpl_multisig::issue_signer_list_set(storage, &config, new_verifier_set.clone())?;

            Ok(Response::new()
                .add_submessage(
                    start_signing_session(storage, &config, tx_hash, env.contract.address, multisig::verifier_set::VerifierSet::from(cur_verifier_set).id())?
                )
                .add_message(
                    wasm_execute(
                        config.coordinator,
                        &coordinator::msg::ExecuteMsg::SetActiveVerifiers {
                            verifiers: verifier_union_set,
                        },
                        vec![],
                    )
                    .map_err(ContractError::from)?,
                ))
        }
    }

}

fn all_active_verifiers(storage: &mut dyn Storage) -> Result<HashSet<String>, ContractError> {
    let current_signers = state::CURRENT_VERIFIER_SET
        .may_load(storage)?
        .map(|verifier_set| verifier_set.signers)
        .unwrap_or_default();

    let next_signers = state::NEXT_VERIFIER_SET
        .may_load(storage)?
        .map(|verifier_set| verifier_set.signers)
        .unwrap_or_default();

    current_signers
        .iter()
        .chain(next_signers.iter())
        .map(|signer| signer.address.to_string())
        .collect::<HashSet<String>>()
        .then(Ok)
}

fn next_verifier_set(
    storage: &mut dyn Storage,
    querier: &Querier,
    env: &Env,
    config: &Config,
) -> Result<Option<axelar_verifiers::VerifierSet>, ContractError> {
    // if there's already a pending verifiers set update, just return it
    if let Some(pending_verifier_set) = state::NEXT_VERIFIER_SET.may_load(storage)? {
        return Ok(Some(pending_verifier_set));
    }
    let cur_verifier_set = state::CURRENT_VERIFIER_SET.may_load(storage)?;
    let new_verifier_set = axelar_verifiers::active_verifiers(querier, config.signing_threshold, env.block.height)?;

    match cur_verifier_set {
        Some(cur_verifier_set) => {
            if crate::axelar_verifiers::should_update_verifier_set(
                &new_verifier_set.clone().into(),
                &cur_verifier_set.into(),
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
