use std::collections::HashSet;

use axelar_wasm_std::msg_id::HexTxHash;
use axelar_wasm_std::{address, permission_control, FnExt, MajorityThreshold, VerificationStatus};
use cosmwasm_std::{
    wasm_execute, Addr, DepsMut, Env, HexBinary, QuerierWrapper, Response, Storage, SubMsg,
    Uint256, Uint64,
};
use interchain_token_service::{HubMessage, TokenId};
use multisig::types::MultisigState;
use router_api::{ChainNameRaw, CrossChainId};
use sha3::{Digest, Keccak256};
use xrpl_types::msg::{XRPLAddReservesMessage, XRPLMessage, XRPLProverMessage};
use xrpl_types::types::{
    canonicalize_token_amount, XRPLAccountId, XRPLPaymentAmount, XRPLTxStatus, XRP_MAX_UINT,
};

use super::START_MULTISIG_REPLY_ID;
use crate::error::ContractError;
use crate::state::{self, Config, FEE_RESERVE, FEE_RESERVE_TOP_UP_COUNTED, TRUST_LINE};
use crate::{axelar_verifiers, xrpl_multisig};

pub fn construct_trust_set_proof(
    storage: &mut dyn Storage,
    gateway: xrpl_gateway::Client,
    self_address: Addr,
    config: &Config,
    token_id: TokenId,
) -> Result<Response, ContractError> {
    let xrpl_token = gateway
        .xrpl_token(token_id)
        .map_err(|_| ContractError::FailedToGetXrplToken(token_id))?;
    if xrpl_token.is_remote(config.xrpl_multisig.clone()) {
        return Err(ContractError::TokenNotLocal(xrpl_token));
    }

    if TRUST_LINE.has(storage, &xrpl_token) {
        return Err(ContractError::TrustLineAlreadyExists(xrpl_token));
    }

    let unsigned_tx_hash = xrpl_multisig::issue_trust_set(storage, config, xrpl_token)?;
    Ok(Response::new().add_submessage(start_signing_session(
        storage,
        config,
        unsigned_tx_hash,
        self_address,
        None,
    )?))
}

pub fn construct_ticket_create_proof(
    storage: &mut dyn Storage,
    self_address: Addr,
    config: &Config,
) -> Result<Response, ContractError> {
    let ticket_count = xrpl_multisig::num_of_tickets_to_create(storage)?;
    if ticket_count < config.ticket_count_threshold {
        return Err(ContractError::TicketCountThresholdNotReached);
    }

    let unsigned_tx_hash = xrpl_multisig::issue_ticket_create(storage, config, ticket_count)?;
    Ok(Response::new().add_submessage(start_signing_session(
        storage,
        config,
        unsigned_tx_hash,
        self_address,
        None,
    )?))
}

pub fn confirm_prover_message(
    storage: &mut dyn Storage,
    querier: QuerierWrapper,
    config: &Config,
    prover_message: XRPLProverMessage,
) -> Result<Response, ContractError> {
    let message = XRPLMessage::ProverMessage(prover_message.clone());
    let status = message_status(querier, config, message)?;

    match status {
        VerificationStatus::Unknown | VerificationStatus::FailedToVerify => {
            return Err(ContractError::TxStatusUnknown);
        }
        VerificationStatus::InProgress => {
            return Err(ContractError::TxStatusVerificationInProgress);
        }
        VerificationStatus::SucceededOnSourceChain
        | VerificationStatus::FailedOnSourceChain
        | VerificationStatus::NotFoundOnSourceChain => {}
    }

    if let Some(confirmed_verifier_set) = xrpl_multisig::confirm_prover_message(
        storage,
        prover_message.unsigned_tx_hash,
        status.into(),
    )? {
        let coordinator: coordinator::Client =
            client::ContractClient::new(querier, &config.coordinator).into();

        let multisig: multisig::Client =
            client::ContractClient::new(querier, &config.multisig).into();

        let active_verifiers = confirmed_verifier_set
            .signers
            .iter()
            .map(|signer| signer.address.to_string())
            .collect::<HashSet<String>>();

        return Ok(Response::new()
            .add_message(multisig.register_verifier_set(confirmed_verifier_set.try_into()?))
            .add_message(coordinator.set_active_verifiers(active_verifiers))
        );
    }

    Ok(Response::default())
}

pub fn confirm_add_reserves_message(
    storage: &mut dyn Storage,
    querier: QuerierWrapper,
    config: &Config,
    add_reserves_message: XRPLAddReservesMessage,
) -> Result<Response, ContractError> {
    let message = XRPLMessage::AddReservesMessage(add_reserves_message.clone());
    let status = message_status(querier, config, message)?;

    if status != VerificationStatus::SucceededOnSourceChain {
        return Ok(Response::default());
    }

    let fee_added = add_reserves_message.amount;
    let tx_id = add_reserves_message.tx_id.tx_hash;
    if fee_added != 0u64
        && FEE_RESERVE_TOP_UP_COUNTED
            .may_load(storage, &tx_id)?
            .is_none()
    {
        let new_fee_reserve = match FEE_RESERVE.may_load(storage)? {
            Some(current_fee_reserve) => current_fee_reserve
                .checked_add(fee_added)
                .ok_or(ContractError::Overflow)?,
            None => fee_added,
        };

        FEE_RESERVE.save(storage, &new_fee_reserve)?;
        FEE_RESERVE_TOP_UP_COUNTED.save(storage, &tx_id, &())?;
    }

    Ok(Response::default())
}

fn message_status(
    querier: QuerierWrapper,
    config: &Config,
    message: XRPLMessage,
) -> Result<VerificationStatus, ContractError> {
    let voting_verifier: xrpl_voting_verifier::Client =
        client::ContractClient::new(querier, &config.voting_verifier).into();
    let messages_status = voting_verifier
        .messages_status(vec![message.clone()])
        .map_err(|_| {
            ContractError::FailedToGetMessagesStatus(Box::new(vec![message.to_owned()]))
        })?;
    let status = messages_status
        .first()
        .ok_or(ContractError::FailedToGetMessageStatus(Box::new(message)))?
        .status;

    Ok(status)
}

fn save_next_verifier_set(
    storage: &mut dyn Storage,
    new_verifier_set: &axelar_verifiers::VerifierSet,
) -> Result<(), ContractError> {
    if let Ok(Some(next_verifier_set)) = state::NEXT_VERIFIER_SET.may_load(storage) {
        if next_verifier_set == *new_verifier_set {
            return Ok(());
        } else {
            return Err(ContractError::VerifierSetConfirmationInProgress);
        }
    }

    state::NEXT_VERIFIER_SET.save(storage, new_verifier_set)?;
    Ok(())
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

pub fn update_xrpl_reserves(
    deps: DepsMut,
    new_base_reserve: u64,
    new_owner_reserve: u64,
) -> Result<Response, ContractError> {
    state::CONFIG.update(
        deps.storage,
        |mut config| -> Result<Config, ContractError> {
            config.xrpl_base_reserve = new_base_reserve;
            config.xrpl_owner_reserve = new_owner_reserve;
            Ok(config)
        },
    )?;
    Ok(Response::new())
}

pub fn update_xrpl_transaction_fee(
    deps: DepsMut,
    new_transaction_fee: u64,
) -> Result<Response, ContractError> {
    state::CONFIG.update(
        deps.storage,
        |mut config| -> Result<Config, ContractError> {
            config.xrpl_transaction_fee = new_transaction_fee;
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

fn compute_xrpl_amount(
    gateway: xrpl_gateway::Client,
    token_id: TokenId,
    source_chain: ChainNameRaw,
    source_amount: Uint256,
) -> Result<XRPLPaymentAmount, ContractError> {
    let xrp_token_id = gateway
        .xrp_token_id()
        .map_err(|_| ContractError::FailedToGetXrpTokenId)?;

    let xrpl_amount = if token_id == xrp_token_id {
        if source_amount > Uint256::from(XRP_MAX_UINT) {
            return Err(ContractError::InvalidTransferAmount {
                source_chain: source_chain.to_owned(),
                amount: source_amount,
            });
        }

        let drops = u64::from_be_bytes(source_amount.to_be_bytes()[24..].try_into().unwrap());
        XRPLPaymentAmount::Drops(drops)
    } else {
        let xrpl_token = gateway
            .xrpl_token(token_id)
            .map_err(|_| ContractError::FailedToGetXrplToken(token_id))?;
        let source_decimals = gateway
            .token_instance_decimals(source_chain.clone(), token_id)
            .map_err(|_| ContractError::FailedToGetTokenInstanceDecimals {
                token_id: token_id.to_owned(),
                chain: source_chain.to_owned(),
            })?;
        let (token_amount, _dust) = canonicalize_token_amount(source_amount, source_decimals)
            .map_err(|_| ContractError::InvalidTransferAmount {
                source_chain: source_chain.to_owned(),
                amount: source_amount,
            })?;

        XRPLPaymentAmount::Issued(xrpl_token, token_amount)
    };

    Ok(xrpl_amount)
}

#[allow(clippy::too_many_arguments)]
pub fn construct_payment_proof(
    storage: &mut dyn Storage,
    querier: QuerierWrapper,
    gateway: xrpl_gateway::Client,
    self_address: Addr,
    block_height: u64,
    config: &Config,
    cc_id: CrossChainId, // TODO: Optimize: Source chain is always axelar.
    payload: HexBinary,
) -> Result<Response, ContractError> {
    let multisig: multisig::Client = client::ContractClient::new(querier, &config.multisig).into();
    // Prevent creating a duplicate signing session before the previous one expires
    if let Some(multisig_session) =
        state::CROSS_CHAIN_ID_TO_MULTISIG_SESSION.may_load(storage, &cc_id)?
    {
        match multisig
            .multisig(Uint64::from(multisig_session.id))
            .map_err(|_| ContractError::FailedToGetMultisigSession(multisig_session.id))?
            .state
        {
            MultisigState::Pending => {
                if multisig_session.expires_at <= block_height {
                    return Err(ContractError::PaymentAlreadyHasActiveSigningSession(
                        multisig_session.id,
                    ));
                }
            }
            MultisigState::Completed { .. } => {
                let unsigned_tx_hash = state::MULTISIG_SESSION_ID_TO_UNSIGNED_TX_HASH
                    .load(storage, multisig_session.id)?;
                let tx_info =
                    state::UNSIGNED_TX_HASH_TO_TX_INFO.load(storage, &unsigned_tx_hash)?;
                match tx_info.status {
                    XRPLTxStatus::Succeeded => return Err(ContractError::PaymentAlreadySucceeded(cc_id.to_owned())),
                    XRPLTxStatus::Pending // Fresh payment.
                    | XRPLTxStatus::FailedOnChain // Retry.
                    | XRPLTxStatus::Inconclusive => (),
                }
            }
        }
    };

    let messages = gateway
        .outgoing_messages(vec![cc_id.clone()])
        .map_err(|_| ContractError::FailedToGetMessages)?;

    let message = messages
        .first()
        .ok_or(ContractError::MessageNotFound(cc_id.to_owned()))?;

    // Message source chain (Axelar) and source address (ITS hub) has been validated by the gateway.
    // TODO: Check with Axelar if this destination chain check is necessary.
    if message.destination_chain != config.chain_name {
        return Err(ContractError::InvalidDestinationChain {
            expected: config.chain_name.clone(),
            actual: message.destination_chain.clone(),
        });
    }

    let payload_hash: [u8; 32] = Keccak256::digest(payload.as_slice()).into();
    if message.payload_hash != payload_hash {
        return Err(ContractError::PayloadHashMismatch {
            expected: message.payload_hash,
            actual: payload_hash,
        });
    }

    let its_hub_message =
        HubMessage::abi_decode(payload.as_slice()).map_err(|_| ContractError::InvalidPayload)?;
    match its_hub_message {
        HubMessage::SendToHub { .. } => Err(ContractError::InvalidPayload),
        HubMessage::RegisterTokenMetadata { .. } => Err(ContractError::InvalidPayload),
        HubMessage::ReceiveFromHub {
            source_chain,
            message,
        } => {
            match message {
                // Source address (ITS on source chain) has been validated by ITS hub.
                interchain_token_service::Message::InterchainTransfer(interchain_transfer) => {
                    let destination_address =
                        XRPLAccountId::try_from(interchain_transfer.destination_address)
                            .map_err(|_| ContractError::InvalidDestinationAddress)?;

                    let xrpl_amount = compute_xrpl_amount(
                        gateway,
                        interchain_transfer.token_id,
                        source_chain.clone(),
                        interchain_transfer.amount.into(),
                    )?;

                    if xrpl_amount.is_zero() {
                        return Ok(Response::default());
                    }

                    // TODO: Consider enforcing that data is None for simple payments.
                    let unsigned_tx_hash = xrpl_multisig::issue_payment(
                        storage,
                        config,
                        destination_address,
                        &xrpl_amount,
                        &cc_id,
                        None, // TODO: Handle cross-currency payments.
                    )?;

                    Ok(Response::new().add_submessage(start_signing_session(
                        storage,
                        config,
                        unsigned_tx_hash,
                        self_address,
                        None,
                    )?))
                }
                interchain_token_service::Message::DeployInterchainToken(_) => {
                    Err(ContractError::InvalidPayload)
                }
                interchain_token_service::Message::LinkToken(_) => {
                    Err(ContractError::InvalidPayload)
                }
            }
        }
    }
}

fn start_signing_session(
    storage: &mut dyn Storage,
    config: &Config,
    unsigned_tx_hash: HexTxHash,
    self_address: Addr,
    verifier_set_id: Option<String>,
) -> Result<SubMsg<cosmwasm_std::Empty>, ContractError> {
    state::REPLY_UNSIGNED_TX_HASH.save(storage, &unsigned_tx_hash)?;

    let verifier_set_id = match verifier_set_id {
        Some(id) => id,
        None => {
            let cur_verifier_set: multisig::verifier_set::VerifierSet = state::CURRENT_VERIFIER_SET
                .load(storage)
                .map_err(|_| ContractError::NoVerifierSet)?
                .try_into()?;

            cur_verifier_set.id()
        }
    };

    let start_sig_msg: multisig::msg::ExecuteMsg = multisig::msg::ExecuteMsg::StartSigningSession {
        verifier_set_id,
        msg: unsigned_tx_hash.tx_hash.into(),
        chain_name: config.chain_name.clone(),
        sig_verifier: Some(self_address.into()),
    };

    let wasm_msg = wasm_execute(&config.multisig, &start_sig_msg, vec![])?;

    Ok(SubMsg::reply_on_success(wasm_msg, START_MULTISIG_REPLY_ID))
}

pub fn update_verifier_set(
    storage: &mut dyn Storage,
    querier: QuerierWrapper,
    env: Env,
) -> Result<Response, ContractError> {
    let config = state::CONFIG.load(storage).map_err(ContractError::from)?;

    let coordinator: coordinator::Client =
        client::ContractClient::new(querier, &config.coordinator).into();

    let multisig: multisig::Client =
        client::ContractClient::new(querier, &config.multisig).into();

    let cur_verifier_set = state::CURRENT_VERIFIER_SET
        .may_load(storage)
        .map_err(ContractError::from)?;

    match cur_verifier_set {
        None => {
            // if no verifier set, just store it and return
            let new_verifier_set =
                axelar_verifiers::make_verifier_set(&config, querier, env.block.height)?;
            state::CURRENT_VERIFIER_SET
                .save(storage, &new_verifier_set)
                .map_err(ContractError::from)?;

            Ok(Response::new().add_message(
                multisig.register_verifier_set(new_verifier_set.try_into().map_err(ContractError::from)?)
            ))
        }
        Some(cur_verifier_set) => {
            let new_verifier_set = next_verifier_set(storage, querier, &env, &config)?
                .ok_or(ContractError::VerifierSetUnchanged)?;

            save_next_verifier_set(storage, &new_verifier_set)?;

            let verifier_union_set = all_active_verifiers(storage)?;
            let unsigned_tx_hash =
                xrpl_multisig::issue_signer_list_set(storage, &config, new_verifier_set.clone())?;

            Ok(Response::new()
                .add_submessage(start_signing_session(
                    storage,
                    &config,
                    unsigned_tx_hash,
                    env.contract.address,
                    Some(multisig::verifier_set::VerifierSet::try_from(cur_verifier_set)?.id()),
                )?)
                .add_message(coordinator.set_active_verifiers(verifier_union_set))
            )
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
    querier: QuerierWrapper,
    env: &Env,
    config: &Config,
) -> Result<Option<axelar_verifiers::VerifierSet>, ContractError> {
    // if there's already a pending verifiers set update, just return it
    if let Some(pending_verifier_set) = state::NEXT_VERIFIER_SET.may_load(storage)? {
        return Ok(Some(pending_verifier_set));
    }
    let cur_verifier_set = state::CURRENT_VERIFIER_SET.may_load(storage)?;
    let new_verifier_set = axelar_verifiers::make_verifier_set(config, querier, env.block.height)?;

    match cur_verifier_set {
        Some(cur_verifier_set) => {
            if axelar_verifiers::should_update_verifier_set(
                &new_verifier_set.clone().try_into()?,
                &cur_verifier_set.try_into()?,
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
