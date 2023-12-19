use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{StdResult, Uint64, HexBinary, Storage};

use multisig::types::MultisigState;

use crate::{
    state::{MULTISIG_SESSION_TX, TRANSACTION_INFO}, types::TxHash, xrpl_multisig::{XRPLUnsignedTx, XRPLSignedTransaction, XRPLSigner, self}, querier::Querier,
};

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(GetProofResponse)]
    GetProof { multisig_session_id: Uint64 },
}

#[cw_serde]
#[serde(tag = "status")]
pub enum GetProofResponse {
    Completed { unsigned_tx_hash: TxHash, tx_blob: HexBinary},
    Pending { unsigned_tx_hash: TxHash },
}

pub fn make_xrpl_signed_tx(unsigned_tx: XRPLUnsignedTx, axelar_signers: Vec<(multisig::msg::Signer, multisig::key::Signature)>) -> XRPLSignedTransaction {
    let xrpl_signers: Vec<XRPLSigner> = axelar_signers
        .iter()
        .map(|(axelar_signer, signature)| {
            let xrpl_address = xrpl_multisig::public_key_to_xrpl_address(axelar_signer.pub_key.clone());
            XRPLSigner {
                account: xrpl_address,
                signing_pub_key: axelar_signer.pub_key.clone().into(),
                txn_signature: HexBinary::from(signature.clone().as_ref())
            }
        })
        .collect::<Vec<XRPLSigner>>();

    XRPLSignedTransaction {
        unsigned_tx,
        signers: xrpl_signers,
    }
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

            let signed_tx = make_xrpl_signed_tx(tx_info.unsigned_contents, axelar_signers);
            let tx_blob: HexBinary = HexBinary::from(xrpl_multisig::serialize_signed_tx(signed_tx)?);
            GetProofResponse::Completed { unsigned_tx_hash, tx_blob }
        }
    };

    Ok(response)
}
