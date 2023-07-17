use cosmwasm_crypto::secp256k1_verify;
use cosmwasm_std::HexBinary;

// TODO: Logic specific to secp256k1 will most likely be handled by core in the future.
use crate::{
    types::{MsgToSign, PublicKey, Signature, VerifiableSignature},
    ContractError,
};

const MESSAGE_HASH_LEN: usize = 32;
const COMPRESSED_PUBKEY_LEN: usize = 33;
const UNCOMPRESSED_PUBKEY_LEN: usize = 65;
const EVM_SIGNATURE_LEN: usize = 65;
const ECDSA_SIGNATURE_LEN: usize = 64;

impl TryFrom<HexBinary> for PublicKey {
    type Error = ContractError;

    fn try_from(other: HexBinary) -> Result<Self, Self::Error> {
        if other.len() != COMPRESSED_PUBKEY_LEN && other.len() != UNCOMPRESSED_PUBKEY_LEN {
            return Err(ContractError::InvalidPublicKeyFormat {
                reason: "Invalid input length".into(),
            });
        }

        Ok(PublicKey::unchecked(other))
    }
}

impl TryFrom<HexBinary> for MsgToSign {
    type Error = ContractError;

    fn try_from(other: HexBinary) -> Result<Self, Self::Error> {
        if other.len() != MESSAGE_HASH_LEN {
            return Err(ContractError::InvalidMessageFormat {
                reason: "Invalid input length".into(),
            });
        }

        Ok(MsgToSign::unchecked(other))
    }
}

impl TryFrom<HexBinary> for Signature {
    type Error = ContractError;

    fn try_from(other: HexBinary) -> Result<Self, Self::Error> {
        if other.len() != EVM_SIGNATURE_LEN {
            return Err(ContractError::InvalidSignatureFormat {
                reason: "Invalid input length".into(),
            });
        }

        Ok(Signature::unchecked(other))
    }
}

impl VerifiableSignature for Signature {
    fn verify(&self, msg: &MsgToSign, pub_key: &PublicKey) -> Result<bool, ContractError> {
        let signature: &[u8] = self.into();
        secp256k1_verify(
            msg.into(),
            &signature[0..ECDSA_SIGNATURE_LEN],
            pub_key.into(),
        )
        .map_err(|e| ContractError::SignatureVerificationFailed {
            reason: e.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test::common::test_data;

    #[test]
    fn test_try_from_hexbinary_to_public_key() {
        let hex = test_data::pub_key();
        let pub_key = PublicKey::try_from(hex.clone()).unwrap();
        assert_eq!(HexBinary::from(pub_key), hex);
    }

    #[test]
    fn test_try_from_hexbinary_to_public_key_fails() {
        let hex = HexBinary::from_hex("049b").unwrap();
        assert_eq!(
            PublicKey::try_from(hex.clone()).unwrap_err(),
            ContractError::InvalidPublicKeyFormat {
                reason: "Invalid input length".into()
            }
        );
    }

    #[test]
    fn test_try_from_hexbinary_to_message() {
        let hex = test_data::message();
        let message = MsgToSign::try_from(hex.clone()).unwrap();
        assert_eq!(HexBinary::from(message), hex);
    }

    #[test]
    fn test_try_from_hexbinary_to_message_fails() {
        let hex = HexBinary::from_hex("283786d844a7c4d1d424837074d0c8ec71becdcba4dd42b5307cb543a0e2c8b81c10ad541defd5ce84d2a608fc454827d0b65b4865c8192a2ea1736a5c4b72021b").unwrap();
        assert_eq!(
            MsgToSign::try_from(hex.clone()).unwrap_err(),
            ContractError::InvalidMessageFormat {
                reason: "Invalid input length".into()
            }
        );
    }

    #[test]
    fn test_try_from_hexbinary_to_signature() {
        let hex = test_data::signature();
        let signature = Signature::try_from(hex.clone()).unwrap();
        assert_eq!(HexBinary::from(signature), hex);
    }

    #[test]
    fn test_try_from_hexbinary_to_signature_fails() {
        let hex =
            HexBinary::from_hex("283786d844a7c4d1d424837074d0c8ec71becdcba4dd42b5307cb543a0e2c8b81c10ad541defd5ce84d2a608fc454827d0b65b4865c8192a2ea1736a5c4b72")
                .unwrap();
        assert_eq!(
            Signature::try_from(hex.clone()).unwrap_err(),
            ContractError::InvalidSignatureFormat {
                reason: "Invalid input length".into()
            }
        );
    }

    #[test]
    fn test_verify_signature() {
        let signature = Signature::try_from(test_data::signature()).unwrap();
        let message = MsgToSign::try_from(test_data::message()).unwrap();
        let public_key = PublicKey::try_from(test_data::pub_key()).unwrap();
        let result = signature.verify(&message, &public_key).unwrap();
        assert_eq!(result, true);
    }

    #[test]
    fn test_verify_signature_invalid_signature() {
        let invalid_signature = HexBinary::from_hex(
            "a112231719403227b297139cc6beef82a4e034663bfe48cf732687860b16227a51e4bd6be96fceeecf8e77fe7cdd4f5567d71aed5388484d1f2ba355298c954e1b",
        )
        .unwrap();

        let signature = Signature::try_from(invalid_signature).unwrap();
        let message = MsgToSign::try_from(test_data::message()).unwrap();
        let public_key = PublicKey::try_from(test_data::pub_key()).unwrap();
        let result = signature.verify(&message, &public_key).unwrap();
        assert_eq!(result, false);
    }

    #[test]
    fn test_verify_signature_invalid_pub_key() {
        let invalid_pub_key = HexBinary::from_hex(
            "03cd0b61b25b11c59323602dad24336edb9b9a40fb00fdd32c94908967ec16989e",
        )
        .unwrap();

        let signature = Signature::try_from(test_data::signature()).unwrap();
        let message = MsgToSign::try_from(test_data::message()).unwrap();
        let public_key = PublicKey::try_from(invalid_pub_key).unwrap();
        let result = signature.verify(&message, &public_key).unwrap();
        assert_eq!(result, false);
    }
}
