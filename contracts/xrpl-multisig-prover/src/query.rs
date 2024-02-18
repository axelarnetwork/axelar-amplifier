use cosmwasm_std::{StdResult, Uint64, HexBinary, Storage};

use multisig::{key::Signature, types::MultisigState};
use multisig::key::PublicKey;

use crate::xrpl_multisig::XRPLAccountId;
use crate::{
    state::{MULTISIG_SESSION_TX, TRANSACTION_INFO, CURRENT_WORKER_SET}, xrpl_multisig::{self, XRPLSerialize, HASH_PREFIX_UNSIGNED_TX_MULTI_SIGNING}, querier::Querier, msg::GetProofResponse, types::TransactionStatus, error::ContractError,
};

pub fn get_message_to_sign(storage: &dyn Storage, multisig_session_id: &Uint64, signer_xrpl_address: &XRPLAccountId) -> StdResult<HexBinary> {
    let unsigned_tx_hash = MULTISIG_SESSION_TX.load(storage, multisig_session_id.u64())?;

    let tx_info = TRANSACTION_INFO.load(storage, &unsigned_tx_hash)?;
    if tx_info.status != TransactionStatus::Pending {
        return Err(ContractError::TransactionStatusNotPending.into());
    }

    let serialized_unsigned_tx = tx_info.unsigned_contents.xrpl_serialize()?;

    let serialized_tx = &[serialized_unsigned_tx, signer_xrpl_address.to_bytes().to_vec()].concat();

    Ok(xrpl_multisig::xrpl_hash(HASH_PREFIX_UNSIGNED_TX_MULTI_SIGNING, serialized_tx).into())
}

pub fn verify_message(storage: &dyn Storage, multisig_session_id: &Uint64, public_key: &PublicKey, signature: &Signature) -> StdResult<bool> {
    let signer_xrpl_address = XRPLAccountId::from(public_key);
    let tx_hash = get_message_to_sign(storage, multisig_session_id, &signer_xrpl_address)?;

    // m.tx_hash is going to be over 32 bytes due to inclusion of the signer address, so it has to be passed unchecked 
    signature.verify(&multisig::types::MsgToSign::unchecked(tx_hash), &public_key)
        .map_err(|_e| ContractError::SignatureVerificationFailed.into())
}

pub fn get_proof(storage: &dyn Storage, querier: Querier, multisig_session_id: &Uint64) -> StdResult<GetProofResponse> {
    let unsigned_tx_hash = MULTISIG_SESSION_TX.load(storage, multisig_session_id.u64())?;

    let tx_info = TRANSACTION_INFO.load(storage, &unsigned_tx_hash)?;

    let multisig_session= querier.get_multisig_session(&multisig_session_id)?;

    let response = match multisig_session.state {
        MultisigState::Pending => GetProofResponse::Pending { unsigned_tx_hash },
        MultisigState::Completed { .. } => {
            let axelar_signers: Vec<(multisig::msg::Signer, multisig::key::Signature)> = multisig_session.signers
                .iter()
                .filter(|(_, signature)| signature.is_some())
                .map(|(signer, signature)| (signer.clone(), signature.clone().unwrap()))
                .collect();

            let signed_tx = xrpl_multisig::make_xrpl_signed_tx(tx_info.unsigned_contents, axelar_signers)?;
            let tx_blob: HexBinary = HexBinary::from(signed_tx.xrpl_serialize()?);
            GetProofResponse::Completed { unsigned_tx_hash, tx_blob }
        }
    };

    Ok(response)
}

pub fn get_worker_set(storage: &dyn Storage) -> StdResult<multisig::worker_set::WorkerSet> {
    Ok(CURRENT_WORKER_SET.load(storage)?.into())
}
