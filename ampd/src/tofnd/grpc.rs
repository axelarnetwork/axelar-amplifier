use async_trait::async_trait;
use ecdsa::VerifyingKey;
use error_stack::{IntoReport, ResultExt};
use mockall::automock;
use tonic::{transport::Channel, Status};

use crate::{types::PublicKey, url::Url};

use super::proto::{
    keygen_response::KeygenResponse, multisig_client, sign_response::SignResponse, KeygenRequest,
    SignRequest,
};
use super::{error::Error, error::TofndError, MessageDigest, Signature};

type Result<T> = error_stack::Result<T, Error>;
type StatusResult<T> = error_stack::Result<T, Status>;

#[automock]
#[async_trait]
pub trait EcdsaClient {
    async fn keygen(&mut self, key_uid: &str, party_uid: &str) -> Result<PublicKey>;
    async fn sign(
        &mut self,
        key_uid: &str,
        party_uid: &str,
        data: MessageDigest,
        pub_key: &PublicKey,
    ) -> Result<Signature>;
}

pub struct MultisigClient(multisig_client::MultisigClient<Channel>);

impl MultisigClient {
    pub async fn connect(url: Url) -> Result<Self> {
        Ok(Self(
            multisig_client::MultisigClient::connect(url.to_string())
                .await
                .into_report()
                .change_context(Error::Grpc)?,
        ))
    }

    async fn keygen(&mut self, request: KeygenRequest) -> StatusResult<KeygenResponse> {
        self.0
            .keygen(request)
            .await
            .and_then(|response| {
                response
                    .into_inner()
                    .keygen_response
                    .ok_or_else(|| Status::internal("keygen response is empty"))
            })
            .into_report()
    }

    async fn sign(&mut self, request: SignRequest) -> StatusResult<SignResponse> {
        self.0
            .sign(request)
            .await
            .and_then(|response| {
                response
                    .into_inner()
                    .sign_response
                    .ok_or_else(|| Status::internal("sign response is empty"))
            })
            .into_report()
    }
}

#[async_trait]
impl EcdsaClient for MultisigClient {
    async fn keygen(&mut self, key_uid: &str, party_uid: &str) -> Result<PublicKey> {
        let request = KeygenRequest {
            key_uid: key_uid.to_string(),
            party_uid: party_uid.to_string(),
        };

        self.keygen(request)
            .await
            .change_context(Error::Grpc)
            .and_then(|response| match response {
                KeygenResponse::PubKey(pub_key) => {
                    VerifyingKey::from_sec1_bytes(pub_key.as_slice())
                        .into_report()
                        .change_context(Error::ParsingFailed)
                        .attach_printable(format!("{{ invalid_value = {:?} }}", pub_key))
                        .map(Into::into)
                }
                KeygenResponse::Error(error_msg) => Err(TofndError::ExecutionFailed(error_msg))
                    .into_report()
                    .change_context(Error::KeygenFailed),
            })
    }

    async fn sign(
        &mut self,
        key_uid: &str,
        party_uid: &str,
        data: MessageDigest,
        pub_key: &PublicKey,
    ) -> Result<Signature> {
        let request = SignRequest {
            key_uid: key_uid.to_string(),
            msg_to_sign: data.to_bytes(),
            party_uid: party_uid.to_string(),
            pub_key: pub_key.to_bytes(),
        };

        self.sign(request)
            .await
            .change_context(Error::Grpc)
            .and_then(|response| match response {
                SignResponse::Signature(signature) => Ok(signature),
                SignResponse::Error(error_msg) => Err(TofndError::ExecutionFailed(error_msg))
                    .into_report()
                    .change_context(Error::SignFailed),
            })
    }
}
