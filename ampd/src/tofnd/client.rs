#![allow(dead_code)]

use std::convert::TryInto;

use async_trait::async_trait;
use error_stack::{FutureExt, IntoReport, Report, Result, ResultExt};
use mockall::automock;
use tonic::transport::Channel;
use tonic::{Response, Status};

use super::proto::{
    key_presence_response::Response as KeyPresenceEnum, keygen_response::KeygenResponse, multisig_client,
    sign_response::SignResponse, KeyPresenceRequest, KeygenRequest, SignRequest,
};
use super::{error::Error, error::TofndError, PublicKey, Signature};

#[automock]
#[async_trait]
pub trait MultisigClient {
    async fn keygen(&mut self, request: KeygenRequest) -> Result<KeygenResponse, Status>;
    async fn sign(&mut self, request: SignRequest) -> Result<SignResponse, Status>;
    async fn key_presence(&mut self, request: KeyPresenceRequest) -> Result<KeyPresenceEnum, Status>;
}

#[async_trait]
impl MultisigClient for multisig_client::MultisigClient<Channel> {
    async fn keygen(&mut self, request: KeygenRequest) -> Result<KeygenResponse, Status> {
        self.keygen(request)
            .await
            .and_then(|response| {
                response
                    .into_inner()
                    .keygen_response
                    .ok_or_else(|| Status::internal("keygen response is empty"))
            })
            .into_report()
    }

    async fn sign(&mut self, request: SignRequest) -> Result<SignResponse, Status> {
        self.sign(request)
            .await
            .and_then(|response| {
                response
                    .into_inner()
                    .sign_response
                    .ok_or_else(|| Status::internal("sign response is empty"))
            })
            .into_report()
    }

    async fn key_presence(&mut self, request: KeyPresenceRequest) -> Result<KeyPresenceEnum, Status> {
        self.key_presence(request)
            .await
            .map(Response::into_inner)
            .and_then(|response| {
                KeyPresenceEnum::from_i32(response.response)
                    .ok_or_else(|| Status::internal("invalid key presence response"))
            })
            .into_report()
    }
}

pub struct Client<T: MultisigClient> {
    client: T,
    party_uid: String,
}

impl<T: MultisigClient> Client<T> {
    pub fn new(client: T, party_uid: String) -> Self {
        Self { client, party_uid }
    }

    pub async fn keygen(&mut self, key_uid: String) -> Result<PublicKey, Error> {
        let req = KeygenRequest {
            key_uid,
            party_uid: self.party_uid.clone(),
        };

        self.client
            .keygen(req)
            .change_context(Error::Grpc)
            .await
            .and_then(|response| match response {
                KeygenResponse::PubKey(pub_key) => pub_key.try_into().map_err(|val| {
                    Report::from(Error::KeygenFailed).attach_printable(format!("{{ invalid_value = {:?} }}", val))
                }),
                KeygenResponse::Error(error_msg) => Err(TofndError::ExecutionFailed(error_msg))
                    .into_report()
                    .change_context(Error::KeygenFailed),
            })
    }

    pub async fn sign(&mut self, key_uid: String, data: Vec<u8>, pub_key: PublicKey) -> Result<Signature, Error> {
        let req = SignRequest {
            key_uid,
            msg_to_sign: data,
            party_uid: self.party_uid.clone(),
            pub_key: pub_key.to_vec(),
        };

        self.client
            .sign(req)
            .change_context(Error::Grpc)
            .await
            .and_then(|response| match response {
                SignResponse::Signature(signature) => Ok(signature),
                SignResponse::Error(error_msg) => Err(TofndError::ExecutionFailed(error_msg))
                    .into_report()
                    .change_context(Error::SignFailed),
            })
    }

    pub async fn key_presence(&mut self, key_uid: String, pub_key: PublicKey) -> Result<KeyPresenceEnum, Error> {
        let req = KeyPresenceRequest {
            key_uid,
            pub_key: pub_key.to_vec(),
        };

        self.client.key_presence(req).change_context(Error::Grpc).await
    }
}

#[cfg(test)]
mod tests {
    use error_stack::IntoReport;
    use rand::Rng;
    use tokio::test;
    use tonic::Status;

    use crate::tofnd::client::{Client, MockMultisigClient};
    use crate::tofnd::error::Error;
    use crate::tofnd::proto::{key_presence_response, keygen_response, sign_response};
    use crate::tofnd::PublicKey;

    #[test]
    async fn keygen_empty_response() {
        let mut client = MockMultisigClient::new();
        client
            .expect_keygen()
            .returning(|_| Err(Status::internal("keygen response is empty")).into_report());

        let mut client = Client::new(client, "party_uid".to_string());
        assert!(matches!(
            client.keygen("key".to_string()).await.unwrap_err().current_context(),
            Error::Grpc
        ));
    }

    #[test]
    async fn keygen_invalid_pubkey() {
        let mut client = MockMultisigClient::new();
        client
            .expect_keygen()
            .returning(|_| Ok(keygen_response::KeygenResponse::PubKey(vec![0, 1, 2, 3])));

        let mut client = Client::new(client, "party_uid".to_string());
        assert!(matches!(
            client.keygen("key".to_string()).await.unwrap_err().current_context(),
            Error::KeygenFailed
        ));
    }

    #[test]
    async fn keygen_error_response() {
        let mut client = MockMultisigClient::new();
        client.expect_keygen().returning(|_| {
            Ok(keygen_response::KeygenResponse::Error(String::from(
                "failed to generate key",
            )))
        });

        let mut client = Client::new(client, "party_uid".to_string());
        assert!(matches!(
            client.keygen("key".to_string()).await.unwrap_err().current_context(),
            Error::KeygenFailed
        ));
    }

    #[test]
    async fn keygen_succeeded() {
        let mut rand_pub_key = [0u8; 33];
        rand::thread_rng().fill(&mut rand_pub_key[..]);

        let mut client = MockMultisigClient::new();
        client
            .expect_keygen()
            .returning(move |_| Ok(keygen_response::KeygenResponse::PubKey(rand_pub_key.to_vec())));

        let mut client = Client::new(client, "party_uid".to_string());

        assert_eq!(client.keygen("key".to_string()).await.unwrap(), PublicKey(rand_pub_key));
    }

    #[test]
    async fn sign_empty_response() {
        let mut client = MockMultisigClient::new();
        client
            .expect_sign()
            .returning(|_| Err(Status::internal("sign response is empty")).into_report());

        let mut client = Client::new(client, "party_uid".to_string());
        let digest: [u8; 32] = rand::random();
        assert!(matches!(
            client
                .sign("key".to_string(), digest.to_vec(), PublicKey([0u8; 33]))
                .await
                .unwrap_err()
                .current_context(),
            Error::Grpc
        ));
    }

    #[test]
    async fn sign_error_response() {
        let err_str = "failed to sign";
        let mut client = MockMultisigClient::new();
        client
            .expect_sign()
            .returning(move |_| Ok(sign_response::SignResponse::Error(String::from(err_str))));

        let mut client = Client::new(client, "party_uid".to_string());
        let digest: [u8; 32] = rand::random();
        assert!(matches!(
            client
                .sign("key".to_string(), digest.to_vec(), PublicKey([0u8; 33]))
                .await
                .unwrap_err()
                .current_context(),
            Error::SignFailed
        ));
    }

    #[test]
    async fn sign_succeeded() {
        let mut client = MockMultisigClient::new();
        client
            .expect_sign()
            .returning(move |_| Ok(sign_response::SignResponse::Signature(vec![0, 1, 2, 3])));

        let mut client = Client::new(client, "party_uid".to_string());
        let digest: [u8; 32] = rand::random();
        assert_eq!(
            client
                .sign("key".to_string(), digest.to_vec(), PublicKey([0u8; 33]))
                .await
                .unwrap(),
            vec![0, 1, 2, 3]
        );
    }

    #[test]
    async fn key_presence_succeeded() {
        let mut client = MockMultisigClient::new();
        client
            .expect_key_presence()
            .returning(|_| Ok(key_presence_response::Response::Present));

        let mut client = Client::new(client, "party_uid".to_string());

        assert_eq!(
            client
                .key_presence("key".to_string(), PublicKey([0u8; 33]))
                .await
                .unwrap(),
            key_presence_response::Response::Present
        );
    }
}
