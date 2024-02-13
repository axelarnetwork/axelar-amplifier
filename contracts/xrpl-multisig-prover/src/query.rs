use cosmwasm_std::{StdResult, Uint64, HexBinary, Storage};

use multisig::{key::Signature, types::MultisigState};
use multisig::key::PublicKey;

// TODO: remove dependency?
use k256::{ecdsa, schnorr::signature::SignatureEncoding};

use crate::{
    state::{MULTISIG_SESSION_TX, TRANSACTION_INFO, CURRENT_WORKER_SET}, xrpl_multisig::{XRPLUnsignedTx, XRPLSignedTransaction, XRPLSigner, self, XRPLSerialize}, querier::Querier, msg::{GetProofResponse, GetMessageToSignResponse}, types::TransactionStatus, error::ContractError,
};

pub fn make_xrpl_signed_tx(unsigned_tx: XRPLUnsignedTx, axelar_signers: Vec<(multisig::msg::Signer, multisig::key::Signature)>, multisig_session_id: &Uint64) -> Result<XRPLSignedTransaction, ContractError> {
    let xrpl_signers: Vec<XRPLSigner> = axelar_signers
        .iter()
        .map(|(axelar_signer, signature)| -> Result<XRPLSigner, ContractError> {
            let xrpl_address = xrpl_multisig::public_key_to_xrpl_address(&axelar_signer.pub_key);
            let txn_signature = match signature {
                // TODO: use unwrapped signature instead of ignoring it
                multisig::key::Signature::Ecdsa(_) |
                multisig::key::Signature::EcdsaRecoverable(_) => HexBinary::from(ecdsa::Signature::to_der(
                    &ecdsa::Signature::try_from(signature.clone().as_ref())
                        .map_err(|_| ContractError::FailedToEncodeSignature)?
                ).to_vec()),
                _ => unimplemented!("Unsupported signature type"),
            };

            Ok(XRPLSigner {
                account: xrpl_address,
                signing_pub_key: axelar_signer.pub_key.clone().into(),
                txn_signature,
            })
        })
        .collect::<Result<Vec<XRPLSigner>, ContractError>>()?;

    Ok(XRPLSignedTransaction {
        unsigned_tx,
        signers: xrpl_signers,
    })
}

pub fn get_message_to_sign(storage: &dyn Storage, multisig_session_id: &Uint64, signer_xrpl_address: &String) -> StdResult<GetMessageToSignResponse> {
    let unsigned_tx_hash = MULTISIG_SESSION_TX.load(storage, multisig_session_id.u64())?;

    let tx_info = TRANSACTION_INFO.load(storage, unsigned_tx_hash.clone())?;
    if tx_info.status != TransactionStatus::Pending {
        return Err(ContractError::TransactionStatusNotPending.into());
    }

    let serialized_unsigned_tx = tx_info.unsigned_contents.xrpl_serialize()?;
    let serialized_signer_xrpl_address = xrpl_multisig::decode_address(signer_xrpl_address)?;

    let serialized_tx = &[serialized_unsigned_tx, serialized_signer_xrpl_address.to_vec()].concat();

    Ok(GetMessageToSignResponse {
        tx_hash: xrpl_multisig::xrpl_hash(serialized_tx).into()
    })
}

pub fn verify_message(storage: &dyn Storage, multisig_session_id: &Uint64, public_key: PublicKey, signature: Signature) -> StdResult<bool> {
    let signer_xrpl_address = xrpl_multisig::public_key_to_xrpl_address(&public_key);
    let m = get_message_to_sign(storage, multisig_session_id, &signer_xrpl_address)?;

    // m.tx_hash is going to be over 32 bytes due to inclusion of the signer address, so it has to be passed unchecked 
    signature.verify(&multisig::types::MsgToSign::unchecked(m.tx_hash), &public_key)
        .map_err(|_e| ContractError::SignatureVerificationFailed.into())
}

pub fn get_proof(storage: &dyn Storage, querier: Querier, multisig_session_id: &Uint64) -> StdResult<GetProofResponse> {
    let unsigned_tx_hash = MULTISIG_SESSION_TX.load(storage, multisig_session_id.u64())?;

    let tx_info = TRANSACTION_INFO.load(storage, unsigned_tx_hash.clone())?;

    let multisig_session= querier.get_multisig_session(multisig_session_id.clone())?;

    let response = match multisig_session.state {
        MultisigState::Pending => GetProofResponse::Pending { unsigned_tx_hash },
        MultisigState::Completed { .. } => {
            let axelar_signers: Vec<(multisig::msg::Signer, multisig::key::Signature)> = multisig_session.signers
                .iter()
                .filter(|(_, signature)| signature.is_some())
                .map(|(signer, signature)| (signer.clone(), signature.clone().unwrap()))
                .collect();

            let signed_tx = make_xrpl_signed_tx(tx_info.unsigned_contents, axelar_signers, multisig_session_id)?;
            let tx_blob: HexBinary = HexBinary::from(signed_tx.xrpl_serialize()?);
            GetProofResponse::Completed { unsigned_tx_hash, tx_blob }
        }
    };

    Ok(response)
}

pub fn get_worker_set(storage: &dyn Storage) -> StdResult<multisig::worker_set::WorkerSet> {
    Ok(CURRENT_WORKER_SET.load(storage)?.into())
}
