use cosmwasm_crypto::secp256k1_verify;

// TODO: Logic specific to secp256k1 will most likely be handled by core in the future.
use crate::key::Signature;
use crate::ContractError;

pub fn ecdsa_verify(
    msg_hash: &[u8],
    sig: &Signature,
    pub_key: &[u8],
) -> Result<bool, ContractError> {
    secp256k1_verify(msg_hash, sig.as_ref(), pub_key).map_err(|err| {
        ContractError::SignatureVerificationFailed {
            reason: err.to_string(),
        }
    })
}
