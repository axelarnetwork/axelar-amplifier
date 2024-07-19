use crate::ContractError;

pub const ED25519_SIGNATURE_LEN: usize = 64;

pub fn ed25519_verify(msg_hash: &[u8], sig: &[u8], pub_key: &[u8]) -> Result<bool, ContractError> {
    cosmwasm_crypto::ed25519_verify(msg_hash, sig, pub_key).map_err(|e| {
        ContractError::SignatureVerificationFailed {
            reason: e.to_string(),
        }
    })
}

#[cfg(test)]
mod test {
    use cosmwasm_std::HexBinary;

    use super::*;
    use crate::test::common::ed25519_test_data;

    #[test]
    fn should_fail_sig_verification_instead_of_truncating() {
        let sig_with_extra_byte = ed25519_test_data::signature().to_hex() + "00";

        let signature = HexBinary::from_hex(&sig_with_extra_byte).unwrap().to_vec();
        let message = ed25519_test_data::message().to_vec();
        let public_key = ed25519_test_data::pub_key().to_vec();

        let result = ed25519_verify(&message, &signature, &public_key);
        assert_eq!(
            result.unwrap_err(),
            ContractError::SignatureVerificationFailed {
                reason: "Invalid signature format".into(),
            }
        );
    }
}
