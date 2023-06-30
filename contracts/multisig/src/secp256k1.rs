use cosmwasm_std::HexBinary;

// TODO: Logic specific to secp256k1 will most likely be handled by core in the future.
use crate::{
    types::{Message, PublicKey, Signature, VerifiableSignature},
    ContractError,
};

impl TryFrom<HexBinary> for PublicKey {
    type Error = ContractError;

    fn try_from(other: HexBinary) -> Result<Self, Self::Error> {
        let pub_key = PublicKey::unchecked(other);
        let _validated: secp256k1::PublicKey = (&pub_key).try_into()?;
        Ok(pub_key)
    }
}

impl TryFrom<&PublicKey> for secp256k1::PublicKey {
    type Error = ContractError;

    fn try_from(other: &PublicKey) -> Result<Self, Self::Error> {
        secp256k1::PublicKey::parse_slice(other.into(), None).map_err(|err| {
            ContractError::InvalidPublicKeyFormat {
                context: err.to_string(),
            }
        })
    }
}

impl TryFrom<HexBinary> for Message {
    type Error = ContractError;

    fn try_from(other: HexBinary) -> Result<Self, Self::Error> {
        let msg = Message::unchecked(other);
        let _validated: secp256k1::Message = (&msg).try_into()?;
        Ok(msg)
    }
}

impl TryFrom<&Message> for secp256k1::Message {
    type Error = ContractError;

    fn try_from(other: &Message) -> Result<Self, Self::Error> {
        secp256k1::Message::parse_slice(other.into()).map_err(|err| {
            ContractError::InvalidMessageFormat {
                context: err.to_string(),
            }
        })
    }
}

impl TryFrom<HexBinary> for Signature {
    type Error = ContractError;

    fn try_from(other: HexBinary) -> Result<Self, Self::Error> {
        let sig = Signature::unchecked(other);
        let _validated: secp256k1::Signature = (&sig).try_into()?;
        Ok(sig)
    }
}

impl TryFrom<&Signature> for secp256k1::Signature {
    type Error = ContractError;

    fn try_from(other: &Signature) -> Result<Self, Self::Error> {
        let sig: &[u8] = other.into();

        if sig.len() < 64 {
            return Err(ContractError::InvalidSignatureFormat {
                context: "Invalid input length".into(),
            });
        }

        secp256k1::Signature::parse_slice(&sig[0..64]).map_err(|err| {
            ContractError::InvalidSignatureFormat {
                context: err.to_string(),
            }
        })
    }
}

impl VerifiableSignature for Signature {
    fn verify(&self, msg: &Message, pub_key: &PublicKey) -> Result<bool, ContractError> {
        Ok(secp256k1::verify(
            &msg.try_into()?,
            &self.try_into()?,
            &pub_key.try_into()?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_public_key() -> HexBinary {
        HexBinary::from_hex("03f57d1a813febaccbe6429603f9ec57969511b76cd680452dba91fa01f54e756d")
            .unwrap()
    }

    fn valid_message() -> HexBinary {
        HexBinary::from_hex("fa0609efd1dfeedfdcc8ba51520fae2d5176b7621d2560f071e801b0817e1537")
            .unwrap()
    }

    fn valid_signature() -> HexBinary {
        HexBinary::from_hex("283786d844a7c4d1d424837074d0c8ec71becdcba4dd42b5307cb543a0e2c8b81c10ad541defd5ce84d2a608fc454827d0b65b4865c8192a2ea1736a5c4b72021b")
            .unwrap()
    }

    #[test]
    fn test_try_from_hexbinary_to_public_key() {
        let hex = valid_public_key();
        let pub_key = PublicKey::try_from(hex.clone()).unwrap();
        assert_eq!(HexBinary::from(pub_key), hex);
    }

    #[test]
    fn test_try_from_hexbinary_to_public_key_fails() {
        let hex = HexBinary::from_hex("049b").unwrap();
        assert_eq!(
            PublicKey::try_from(hex.clone()).unwrap_err(),
            ContractError::InvalidPublicKeyFormat {
                context: "Invalid input length".into()
            }
        );
    }

    #[test]
    fn test_try_from_hexbinary_to_message() {
        let hex = valid_message();
        let message = Message::try_from(hex.clone()).unwrap();
        assert_eq!(HexBinary::from(message), hex);
    }

    #[test]
    fn test_try_from_hexbinary_to_message_fails() {
        let hex = HexBinary::from_hex("283786d844a7c4d1d424837074d0c8ec71becdcba4dd42b5307cb543a0e2c8b81c10ad541defd5ce84d2a608fc454827d0b65b4865c8192a2ea1736a5c4b72021b").unwrap();
        assert_eq!(
            Message::try_from(hex.clone()).unwrap_err(),
            ContractError::InvalidMessageFormat {
                context: "Invalid input length".into()
            }
        );
    }

    #[test]
    fn test_try_from_hexbinary_to_signature() {
        let hex = valid_signature();
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
                context: "Invalid input length".into()
            }
        );
    }

    #[test]
    fn test_verify_signature() {
        let signature = Signature::try_from(valid_signature()).unwrap();
        let message = Message::try_from(valid_message()).unwrap();
        let public_key = PublicKey::try_from(valid_public_key()).unwrap();
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
        let message = Message::try_from(valid_message()).unwrap();
        let public_key = PublicKey::try_from(valid_public_key()).unwrap();
        let result = signature.verify(&message, &public_key).unwrap();
        assert_eq!(result, false);
    }

    #[test]
    fn test_verify_signature_invalid_pub_key() {
        let invalid_pub_key = HexBinary::from_hex(
            "03cd0b61b25b11c59323602dad24336edb9b9a40fb00fdd32c94908967ec16989e",
        )
        .unwrap();

        let signature = Signature::try_from(valid_signature()).unwrap();
        let message = Message::try_from(valid_message()).unwrap();
        let public_key = PublicKey::try_from(invalid_pub_key).unwrap();
        let result = signature.verify(&message, &public_key).unwrap();
        assert_eq!(result, false);
    }
}
