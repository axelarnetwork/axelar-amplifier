use std::sync::Arc;

use async_trait::async_trait;
use cosmrs::tendermint::public_key::PublicKey as TMPublicKey;
use error_stack::{Report, ResultExt};
use k256::Secp256k1;
use mockall::automock;
use tokio::sync::Mutex;
use tonic::transport::Channel;
use tonic::Status;

use super::error::{Error, TofndError};
use super::proto::keygen_response::KeygenResponse;
use super::proto::sign_response::SignResponse;
use super::proto::{multisig_client, Algorithm, KeygenRequest, SignRequest};
use super::{MessageDigest, Signature};
use crate::types::PublicKey;
use crate::url::Url;

type Result<T> = error_stack::Result<T, Error>;

#[automock]
#[async_trait]
pub trait Multisig {
    async fn keygen(&self, key_uid: &str, algorithm: Algorithm) -> Result<PublicKey>;
    async fn sign(
        &self,
        key_uid: &str,
        data: MessageDigest,
        pub_key: &PublicKey,
        algorithm: Algorithm,
    ) -> Result<Signature>;
}

#[derive(Clone)]
pub struct MultisigClient {
    party_uid: String,
    client: Arc<Mutex<multisig_client::MultisigClient<Channel>>>,
}

impl MultisigClient {
    pub async fn new(party_uid: String, url: Url) -> Result<Self> {
        Ok(Self {
            party_uid,
            client: Arc::new(Mutex::new(
                multisig_client::MultisigClient::connect(url.to_string())
                    .await
                    .change_context(Error::Grpc)?,
            )),
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
            .lock()
            .await
            .keygen(request)
            .await
            .and_then(|response| {
                response
                    .into_inner()
                    .keygen_response
                    .ok_or_else(|| Status::internal("keygen response is empty"))
            })
            .change_context(Error::Grpc)
            .and_then(|response| match response {
                KeygenResponse::PubKey(pub_key) => match algorithm {
                    Algorithm::Ecdsa => TMPublicKey::from_raw_secp256k1(&pub_key),
                    Algorithm::Ed25519 => TMPublicKey::from_raw_ed25519(&pub_key),
                }
                .ok_or_else(|| Report::new(Error::ParsingFailed))
                .attach_printable(format!("{{ invalid_value = {:?} }}", pub_key))
                .map(Into::into),
                KeygenResponse::Error(error_msg) => {
                    Err(TofndError::ExecutionFailed(error_msg)).change_context(Error::KeygenFailed)
                }
            })
    }

    async fn sign(
        &self,
        key_uid: &str,
        data: MessageDigest,
        pub_key: &PublicKey,
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
            .lock()
            .await
            .sign(request)
            .await
            .and_then(|response| {
                response
                    .into_inner()
                    .sign_response
                    .ok_or_else(|| Status::internal("sign response is empty"))
            })
            .change_context(Error::Grpc)
            .and_then(|response| match response {
                SignResponse::Signature(signature) => match algorithm {
                    Algorithm::Ecdsa => ecdsa::Signature::<Secp256k1>::from_der(&signature)
                        .map(|sig| sig.to_vec())
                        .change_context(Error::ParsingFailed),
                    Algorithm::Ed25519 => ed25519::Signature::from_slice(&signature)
                        .map(|sig| sig.to_vec())
                        .change_context(Error::ParsingFailed),
                },

                SignResponse::Error(error_msg) => {
                    Err(TofndError::ExecutionFailed(error_msg)).change_context(Error::SignFailed)
                }
            })
    }
}
