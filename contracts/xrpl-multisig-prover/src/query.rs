use connection_router_api::CrossChainId;
use cosmwasm_std::{StdResult, Uint64, HexBinary, Storage};

use multisig::{key::Signature, types::MultisigState};
use multisig::key::PublicKey;

use crate::state::{AVAILABLE_TICKETS, MESSAGE_ID_TO_MULTISIG_SESSION_ID, MESSAGE_ID_TO_TICKET};
use crate::{
    types::*,
    state::{MULTISIG_SESSION_ID_TO_TX_HASH, TRANSACTION_INFO, CURRENT_WORKER_SET}, xrpl_multisig::{self, HASH_PREFIX_UNSIGNED_TX_MULTI_SIGNING}, querier::Querier, msg::GetProofResponse, types::TransactionStatus, error::ContractError,
    xrpl_serialize::XRPLSerialize
};

pub fn get_message_to_sign(storage: &dyn Storage, multisig_session_id: &Uint64, signer_xrpl_address: &XRPLAccountId) -> StdResult<HexBinary> {
    let unsigned_tx_hash = MULTISIG_SESSION_ID_TO_TX_HASH.load(storage, multisig_session_id.u64())?;

    let tx_info = TRANSACTION_INFO.load(storage, &unsigned_tx_hash)?;
    if tx_info.status != TransactionStatus::Pending {
        return Err(ContractError::TransactionStatusNotPending.into());
    }

    let mut tx_blob = tx_info.unsigned_contents.xrpl_serialize()?;
    tx_blob.extend(signer_xrpl_address.to_bytes());

    Ok(xrpl_multisig::xrpl_hash(HASH_PREFIX_UNSIGNED_TX_MULTI_SIGNING, tx_blob.as_slice()).into())
}

pub fn verify_signature(storage: &dyn Storage, multisig_session_id: &Uint64, public_key: &PublicKey, signature: &Signature) -> StdResult<bool> {
    let signer_xrpl_address = XRPLAccountId::from(public_key);
    let tx_hash = get_message_to_sign(storage, multisig_session_id, &signer_xrpl_address)?;

    // m.tx_hash is going to be over 32 bytes due to inclusion of the signer address, so it has to be passed unchecked
    Ok(signature.verify(multisig::types::MsgToSign::unchecked(tx_hash), public_key).is_ok())
}

pub fn get_proof(storage: &dyn Storage, querier: Querier, multisig_session_id: &Uint64) -> StdResult<GetProofResponse> {
    let unsigned_tx_hash = MULTISIG_SESSION_ID_TO_TX_HASH.load(storage, multisig_session_id.u64())?;

    let tx_info = TRANSACTION_INFO.load(storage, &unsigned_tx_hash)?;

    let multisig_session= querier.get_multisig_session(multisig_session_id)?;

    let response = match multisig_session.state {
        MultisigState::Pending => GetProofResponse::Pending { unsigned_tx_hash },
        MultisigState::Completed { .. } => {
            let xrpl_signers: Vec<XRPLSigner> = multisig_session.signers
                .into_iter()
                .filter_map(|(signer, sig)| sig.map(|sig| (signer, sig)))
                .map(XRPLSigner::try_from)
                .collect::<Result<Vec<_>, ContractError>>()?;
            let signed_tx = XRPLSignedTransaction::new(tx_info.unsigned_contents, xrpl_signers);
            let tx_blob: HexBinary = HexBinary::from(signed_tx.xrpl_serialize()?);
            GetProofResponse::Completed { unsigned_tx_hash, tx_blob }
        }
    };

    Ok(response)
}

pub fn get_worker_set(storage: &dyn Storage) -> StdResult<multisig::worker_set::WorkerSet> {
    Ok(CURRENT_WORKER_SET.load(storage)?.into())
}

pub fn get_multisig_session_id(storage: &dyn Storage, message_id: &CrossChainId) -> StdResult<Option<u64>> {
    let existing_ticket_number = MESSAGE_ID_TO_TICKET.may_load(storage, message_id)?;
    let available_tickets = AVAILABLE_TICKETS.may_load(storage)?;
    if existing_ticket_number.is_none() || available_tickets.is_none() {
        return Ok(None);
    }

    if available_tickets.unwrap().contains(&existing_ticket_number.unwrap()) {
        return MESSAGE_ID_TO_MULTISIG_SESSION_ID.may_load(storage, message_id);
    }

    Ok(None)
}
