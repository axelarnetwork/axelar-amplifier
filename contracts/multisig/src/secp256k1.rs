use cosmwasm_crypto::secp256k1_verify;

use crate::ContractError;

pub fn ecdsa_verify(msg_hash: &[u8], sig: &[u8], pub_key: &[u8]) -> Result<bool, ContractError> {
    secp256k1_verify(msg_hash, sig, pub_key).map_err(|err| {
        ContractError::SignatureVerificationFailed {
            reason: err.to_string(),
        }
    })
}

#[cfg(test)]
mod test {
    use cosmwasm_std::HexBinary;

    use super::*;
    use crate::test::common::ecdsa_test_data;

    #[test]
    fn should_fail_sig_verification_instead_of_truncating() {
        let sig_with_extra_byte = ecdsa_test_data::signature().to_hex() + "00";

        let signature = HexBinary::from_hex(&sig_with_extra_byte).unwrap().to_vec();
        let message = ecdsa_test_data::message().to_vec();
        let public_key = ecdsa_test_data::pub_key().to_vec();

        let result = ecdsa_verify(&message, &signature, &public_key);
        assert_eq!(
            result.unwrap_err(),
            ContractError::SignatureVerificationFailed {
                reason: "Invalid signature format".into(),
            }
        );
    }
}
