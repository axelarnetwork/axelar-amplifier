use std::fmt;
use std::fmt::Debug;
use std::time::Duration;

use async_trait::async_trait;
use error_stack::ResultExt;
use mockall::automock;
use report::ErrorExt;
use tonic::transport::Channel;
use tonic::Status;

use super::error::{Error, TofndError};
use super::proto::keygen_response::KeygenResponse;
use super::proto::sign_response::SignResponse;
use super::proto::{multisig_client, Algorithm, KeygenRequest, SignRequest};
use super::{MessageDigest, Signature};
use crate::types::debug::REDACTED_VALUE;
use crate::types::PublicKey;

type Result<T> = error_stack::Result<T, Error>;

#[automock]
#[async_trait]
pub trait Multisig {
    async fn keygen(&self, key_uid: &str, algorithm: Algorithm) -> Result<PublicKey>;
    async fn sign(
        &self,
        key_uid: &str,
        data: MessageDigest,
        pub_key: PublicKey,
        algorithm: Algorithm,
    ) -> Result<Signature>;
}

#[derive(Clone)]
pub struct MultisigClient {
    party_uid: String,
    client: multisig_client::MultisigClient<Channel>,
}

impl MultisigClient {
    pub async fn new(party_uid: String, url: &str, timeout: Duration) -> Result<Self> {
        let endpoint: tonic::transport::Endpoint = url.parse().map_err(ErrorExt::into_report)?;
        let conn = endpoint
            .timeout(timeout)
            .connect_timeout(timeout)
            .connect()
            .await
            .map_err(ErrorExt::into_report)?;

        Ok(Self {
            party_uid,
            client: multisig_client::MultisigClient::new(conn),
        })
    }
}

#[async_trait]
impl Multisig for MultisigClient {
    async fn keygen(&self, key_uid: &str, algorithm: Algorithm) -> Result<PublicKey> {
        let request = KeygenRequest {
            key_uid: key_uid.to_string(),
            party_uid: self.party_uid.to_string(),
            algorithm: algorithm.into(),
        };

        self.client
            .clone()
            .keygen(request)
            .await
            .and_then(|response| {
                response
                    .into_inner()
                    .keygen_response
                    .ok_or_else(|| Status::internal("keygen response is empty"))
            })
            .map_err(ErrorExt::into_report)
            .and_then(|response| match response {
                KeygenResponse::PubKey(pub_key) => match algorithm {
                    Algorithm::Ecdsa => PublicKey::new_secp256k1(&pub_key),
                    Algorithm::Ed25519 => PublicKey::new_ed25519(&pub_key),
                }
                .change_context(Error::ParsingFailed)
                .attach_printable(format!("{{ invalid_value = {:?} }}", pub_key)),
                KeygenResponse::Error(error_msg) => {
                    Err(TofndError::ExecutionFailed(error_msg)).change_context(Error::KeygenFailed)
                }
            })
    }

    async fn sign(
        &self,
        key_uid: &str,
        data: MessageDigest,
        pub_key: PublicKey,
        algorithm: Algorithm,
    ) -> Result<Signature> {
        let request = SignRequest {
            key_uid: key_uid.to_string(),
            msg_to_sign: data.into(),
            party_uid: self.party_uid.to_string(),
            pub_key: pub_key.to_bytes(),
            algorithm: algorithm.into(),
        };

        self.client
            .clone()
            .sign(request)
            .await
            .and_then(|response| {
                response
                    .into_inner()
                    .sign_response
                    .ok_or_else(|| Status::internal("sign response is empty"))
            })
            .map_err(ErrorExt::into_report)
            .and_then(|response| match response {
                SignResponse::Signature(signature) => match algorithm {
                    Algorithm::Ecdsa => {
                        k256::ecdsa::Signature::from_der(&signature).map(|sig| sig.to_vec())
                    }
                    Algorithm::Ed25519 => {
                        ed25519_dalek::Signature::from_slice(&signature).map(|sig| sig.to_vec())
                    }
                }
                .change_context(Error::ParsingFailed),

                SignResponse::Error(error_msg) => {
                    Err(TofndError::ExecutionFailed(error_msg)).change_context(Error::SignFailed)
                }
            })
    }
}

impl Debug for MultisigClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MultisigClient")
            .field("party_uid", &self.party_uid)
            .field("client", &REDACTED_VALUE)
            .finish()
    }
}
