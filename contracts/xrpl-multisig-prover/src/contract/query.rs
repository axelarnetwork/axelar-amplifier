use axelar_wasm_std::msg_id::HexTxHash;
use cosmwasm_std::{Addr, HexBinary, QuerierWrapper, StdResult, Storage, Uint64};
use multisig::key::{PublicKey, Signature};
use multisig::types::MultisigState;
use router_api::CrossChainId;
use xrpl_types::error::XRPLError;
use xrpl_types::types::{
    XRPLAccountId, XRPLSignedTx, XRPLSigner, XRPLTxStatus, XRPLUnsignedTxToSign,
};

use crate::error::ContractError;
use crate::msg::{ProofResponse, ProofStatus};
use crate::state::{
    MultisigSession, CROSS_CHAIN_ID_TO_MULTISIG_SESSION, CURRENT_VERIFIER_SET,
    MULTISIG_SESSION_ID_TO_UNSIGNED_TX_HASH, NEXT_VERIFIER_SET, UNSIGNED_TX_HASH_TO_TX_INFO,
};
use crate::xrpl_serialize::XRPLSerialize;

fn message_to_sign(
    storage: &dyn Storage,
    multisig_session_id: &Uint64,
    signer_xrpl_address: &XRPLAccountId,
) -> Result<[u8; 32], ContractError> {
    let unsigned_tx_hash =
        MULTISIG_SESSION_ID_TO_UNSIGNED_TX_HASH.load(storage, multisig_session_id.u64())?;

    let tx_info = UNSIGNED_TX_HASH_TO_TX_INFO.load(storage, &unsigned_tx_hash)?;
    if tx_info.status != XRPLTxStatus::Pending {
        return Err(ContractError::TxStatusNotPending);
    }

    let encoded_unsigned_tx_to_sign = XRPLUnsignedTxToSign {
        unsigned_tx: tx_info.unsigned_tx,
        unsigned_tx_hash: HexTxHash::new(unsigned_tx_hash),
        cc_id: tx_info.original_cc_id,
    }
    .xrpl_serialize()?;
    Ok(xrpl_types::types::message_to_sign(
        encoded_unsigned_tx_to_sign,
        signer_xrpl_address,
    )?)
}

pub fn verify_signature(
    storage: &dyn Storage,
    multisig_session_id: &Uint64,
    public_key: &PublicKey,
    signature: &Signature,
) -> StdResult<bool> {
    let signer_xrpl_address = XRPLAccountId::from(public_key);
    let tx_hash = message_to_sign(storage, multisig_session_id, &signer_xrpl_address)?;
    Ok(signature
        .verify(HexBinary::from(tx_hash), public_key)
        .is_ok())
}

pub fn proof(
    storage: &dyn Storage,
    querier: QuerierWrapper,
    multisig_address: &Addr,
    multisig_session_id: Uint64,
) -> StdResult<ProofResponse> {
    let unsigned_tx_hash =
        MULTISIG_SESSION_ID_TO_UNSIGNED_TX_HASH.load(storage, multisig_session_id.u64())?;

    let tx_info = UNSIGNED_TX_HASH_TO_TX_INFO.load(storage, &unsigned_tx_hash)?;

    let multisig: multisig::Client = client::ContractClient::new(querier, multisig_address).into();

    let multisig_session = multisig
        .multisig(multisig_session_id)
        .map_err(|_| ContractError::FailedToGetMultisigSession(multisig_session_id.u64()))?;

    let status = match multisig_session.state {
        MultisigState::Pending => ProofStatus::Pending,
        MultisigState::Completed { .. } => {
            let xrpl_signers: Vec<XRPLSigner> = multisig_session
                .verifier_set
                .signers
                .into_iter()
                .filter_map(|(signer_address, signer)| {
                    multisig_session
                        .signatures
                        .get(&signer_address)
                        .cloned()
                        .zip(Some(signer))
                })
                .map(XRPLSigner::try_from)
                .collect::<Result<Vec<_>, XRPLError>>()?;

            let signed_tx = XRPLSignedTx::new(
                tx_info.unsigned_tx,
                xrpl_signers,
                HexTxHash::new(unsigned_tx_hash),
                tx_info.original_cc_id,
            );
            let execute_data = HexBinary::from(signed_tx.xrpl_serialize()?);
            ProofStatus::Completed { execute_data }
        }
    };

    Ok(ProofResponse {
        unsigned_tx_hash: HexTxHash::new(unsigned_tx_hash),
        status,
    })
}

pub fn current_verifier_set(
    storage: &dyn Storage,
) -> StdResult<Option<multisig::verifier_set::VerifierSet>> {
    CURRENT_VERIFIER_SET
        .may_load(storage)
        .map(|op| op.map(|set| set.into()))
}

pub fn next_verifier_set(
    storage: &dyn Storage,
) -> StdResult<Option<multisig::verifier_set::VerifierSet>> {
    NEXT_VERIFIER_SET
        .may_load(storage)
        .map(|op| op.map(|set| set.into()))
}

pub fn multisig_session(
    storage: &dyn Storage,
    cc_id: &CrossChainId,
) -> StdResult<Option<MultisigSession>> {
    CROSS_CHAIN_ID_TO_MULTISIG_SESSION.may_load(storage, cc_id)
}
