use std::convert::TryFrom;

use axelar_wasm_std::FnExt;
use ecdsa::{RecoveryId, VerifyingKey};
use error_stack::{Report, ResultExt};
use hex::{self, FromHex};
use k256::Secp256k1;
use serde::Deserialize;

use crate::tofnd::error::Error::ParsingFailed;
use crate::types::PublicKey;
use crate::url::Url;
use error::Error;

pub mod error;
pub mod grpc;

#[allow(non_snake_case)]
mod proto {
    tonic::include_proto!("tofnd");
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub url: Url,
    pub party_uid: String,
    pub key_uid: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            url: "http://localhost:50051/".parse().unwrap(),
            party_uid: "ampd".into(),
            key_uid: "axelar".into(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Signature(ecdsa::Signature<Secp256k1>);

impl Signature {
    pub fn from_der(signature: Vec<u8>) -> error_stack::Result<Self, Error> {
        Ok(Signature(
            ecdsa::Signature::<Secp256k1>::from_der(&signature).change_context(ParsingFailed)?,
        ))
    }

    pub fn to_recoverable(
        &self,
        digest: &MessageDigest,
        pub_key: &PublicKey,
    ) -> error_stack::Result<Vec<u8>, Error> {
        let recovery_id = VerifyingKey::from_sec1_bytes(pub_key.to_bytes().as_ref())
            .change_context(ParsingFailed)?
            .then(|k| {
                RecoveryId::trial_recovery_from_prehash(&k, digest.as_ref(), &self.0)
                    .change_context(ParsingFailed)
            })?;

        let mut recoverable = self.0.to_vec();
        //  We have to make v 27 or 28 due to openzeppelin's implementation
        recoverable.push(recovery_id.to_byte() + 27);

        Ok(recoverable)
    }
}

impl From<ecdsa::Signature<Secp256k1>> for Signature {
    fn from(signature: ecdsa::Signature<Secp256k1>) -> Self {
        Signature(signature)
    }
}

impl From<Signature> for Vec<u8> {
    fn from(signature: Signature) -> Self {
        signature.0.to_vec()
    }
}

impl TryFrom<Vec<u8>> for Signature {
    type Error = Report<Error>;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Signature(
            ecdsa::Signature::<Secp256k1>::from_slice(&value).change_context(ParsingFailed)?,
        ))
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct MessageDigest([u8; 32]);

impl FromHex for MessageDigest {
    type Error = error::Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        Ok(MessageDigest(<[u8; 32]>::from_hex(hex)?))
    }
}

impl From<MessageDigest> for Vec<u8> {
    fn from(val: MessageDigest) -> Vec<u8> {
        val.0.into()
    }
}

impl From<[u8; 32]> for MessageDigest {
    fn from(digest: [u8; 32]) -> Self {
        MessageDigest(digest)
    }
}

impl AsRef<[u8]> for MessageDigest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::consts::U32;
    use ethers::types::Signature as EthersSignature;
    use generic_array::GenericArray;
    use hex::FromHex;
    use k256::ecdsa::{Signature as K256Signature, VerifyingKey};
    use std::str::FromStr;

    #[test]
    fn should_convert_signature_to_recoverable() {
        let ethers_signature = EthersSignature::from_str("74ab5ec395cdafd861dec309c30f6cf8884fc9905eb861171e636d9797478adb60b2bfceb7db0a08769ed7a60006096d3e0f6d3783d125600ac6306180ecbc6f1b").unwrap();
        let pub_key =
            Vec::from_hex("03571a2dcec96eecc7950c9f36367fd459b8d334bac01ac153b7ed3dcf4025fc22")
                .unwrap();

        let digest = "6ac52b00f4256d98d53c256949288135c14242a39001d5fdfa564ea003ccaf92";

        let signature = {
            let mut r_bytes = [0u8; 32];
            let mut s_bytes = [0u8; 32];
            ethers_signature.r.to_big_endian(&mut r_bytes);
            ethers_signature.s.to_big_endian(&mut s_bytes);
            let gar: &GenericArray<u8, U32> = GenericArray::from_slice(&r_bytes);
            let gas: &GenericArray<u8, U32> = GenericArray::from_slice(&s_bytes);

            K256Signature::from_scalars(*gar, *gas).unwrap()
        };

        let recoverable_signature = Signature(signature)
            .to_recoverable(
                &MessageDigest::from_hex(digest).unwrap(),
                &VerifyingKey::from_sec1_bytes(pub_key.as_ref())
                    .unwrap()
                    .into(),
            )
            .unwrap();

        assert_eq!(recoverable_signature, ethers_signature.to_vec());
    }
}
