use cosmwasm_crypto::secp256k1_verify;

// TODO: Logic specific to secp256k1 will most likely be handled by core in the future.
use crate::ContractError;

const ECDSA_SIGNATURE_LEN: usize = 64;

pub fn ecdsa_verify(msg_hash: &[u8], sig: &[u8], pub_key: &[u8]) -> Result<bool, ContractError> {
    secp256k1_verify(msg_hash, &sig[0..ECDSA_SIGNATURE_LEN], pub_key).map_err(|e| {
        ContractError::SignatureVerificationFailed {
            reason: e.to_string(),
        }
    })
}
