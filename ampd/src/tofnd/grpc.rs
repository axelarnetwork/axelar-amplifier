use std::sync::Arc;

use async_trait::async_trait;
use ecdsa::VerifyingKey;
use error_stack::ResultExt;
use k256::Secp256k1;
use mockall::automock;
use tokio::sync::Mutex;
use tonic::{transport::Channel, Status};

use super::proto::{
    keygen_response::KeygenResponse, multisig_client, sign_response::SignResponse, KeygenRequest,
    SignRequest,
};
use super::{error::Error, error::TofndError, MessageDigest, Signature};
use crate::{types::PublicKey, url::Url};

type Result<T> = error_stack::Result<T, Error>;

#[automock]
#[async_trait]
pub trait EcdsaClient: Send {
    async fn keygen(&mut self, key_uid: &str) -> Result<PublicKey>;
    async fn sign(
        &mut self,
        key_uid: &str,
        data: MessageDigest,
        pub_key: &PublicKey,
    ) -> Result<Signature>;
}

pub struct MultisigClient {
    client: multisig_client::MultisigClient<Channel>,
    party_uid: String,
}

impl MultisigClient {
    pub async fn connect(party_uid: String, url: Url) -> Result<Self> {
        Ok(Self {
            party_uid,
            client: multisig_client::MultisigClient::connect(url.to_string())
                .await
                .change_context(Error::Grpc)?,
        })
    }
}

#[async_trait]
impl EcdsaClient for MultisigClient {
    async fn keygen(&mut self, key_uid: &str) -> Result<PublicKey> {
        let request = KeygenRequest {
            key_uid: key_uid.to_string(),
            party_uid: self.party_uid.to_string(),
        };

        self.client
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
                KeygenResponse::PubKey(pub_key) => {
                    VerifyingKey::from_sec1_bytes(pub_key.as_slice())
                        .change_context(Error::ParsingFailed)
                        .attach_printable(format!("{{ invalid_value = {:?} }}", pub_key))
                        .map(Into::into)
                }
                KeygenResponse::Error(error_msg) => {
                    Err(TofndError::ExecutionFailed(error_msg)).change_context(Error::KeygenFailed)
                }
            })
    }

    async fn sign(
        &mut self,
        key_uid: &str,
        data: MessageDigest,
        pub_key: &PublicKey,
    ) -> Result<Signature> {
        let request = SignRequest {
            key_uid: key_uid.to_string(),
            msg_to_sign: data.into(),
            party_uid: self.party_uid.to_string(),
            pub_key: pub_key.to_bytes(),
        };

        self.client
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
                SignResponse::Signature(signature) => {
                    ecdsa::Signature::<Secp256k1>::from_der(&signature)
                        .change_context(Error::ParsingFailed)
                        .map(|sig| sig.to_vec())
                        .map(Into::into)
                }
                SignResponse::Error(error_msg) => {
                    Err(TofndError::ExecutionFailed(error_msg)).change_context(Error::SignFailed)
                }
            })
    }
}

#[derive(Clone)]
pub struct SharableEcdsaClient(Arc<Mutex<dyn EcdsaClient>>);

impl SharableEcdsaClient {
    pub fn new(client: impl EcdsaClient + 'static) -> Self {
        Self(Arc::new(Mutex::new(client)))
    }

    pub async fn keygen(&self, key_uid: &str) -> Result<PublicKey> {
        self.0.lock().await.keygen(key_uid).await
    }

    pub async fn sign(
        &self,
        key_uid: &str,
        data: MessageDigest,
        pub_key: &PublicKey,
    ) -> Result<Signature> {
        self.0.lock().await.sign(key_uid, data, pub_key).await
    }
}

#[cfg(test)]
mod tests {
    use ecdsa::SigningKey;
    use error_stack::Report;
    use futures::future::join_all;
    use k256::Secp256k1;
    use rand::rngs::OsRng;
    use rand::{thread_rng, RngCore};
    use tokio::test;

    use crate::tofnd::{
        error::Error,
        grpc::{MockEcdsaClient, SharableEcdsaClient},
        MessageDigest, Signature,
    };

    const KEY_UID: &str = "key_1";

    #[test]
    async fn keygen_error_response() {
        let mut client = MockEcdsaClient::new();
        client
            .expect_keygen()
            .returning(|_| Err(Report::from(Error::KeygenFailed)));

        assert!(matches!(
            SharableEcdsaClient::new(client)
                .keygen(KEY_UID)
                .await
                .unwrap_err()
                .current_context(),
            Error::KeygenFailed
        ));
    }

    #[test]
    async fn keygen_succeeded() {
        let rand_pub_key = SigningKey::random(&mut OsRng).verifying_key().into();

        let mut client = MockEcdsaClient::new();
        client.expect_keygen().returning(move |_| Ok(rand_pub_key));

        assert_eq!(
            SharableEcdsaClient::new(client)
                .keygen(KEY_UID)
                .await
                .unwrap(),
            rand_pub_key
        );
    }

    #[test]
    async fn sign_error_response() {
        let mut client = MockEcdsaClient::new();
        client
            .expect_sign()
            .returning(move |_, _, _| Err(Report::from(Error::SignFailed)));

        let digest: MessageDigest = rand::random::<[u8; 32]>().into();
        assert!(matches!(
            SharableEcdsaClient::new(client)
                .sign(
                    KEY_UID,
                    digest,
                    &SigningKey::random(&mut OsRng).verifying_key().into()
                )
                .await
                .unwrap_err()
                .current_context(),
            Error::SignFailed
        ));
    }

    #[test]
    async fn sign_succeeded() {
        let mut hash = [0u8; 64];
        thread_rng().fill_bytes(&mut hash);

        let priv_key = SigningKey::<Secp256k1>::random(&mut OsRng);
        let (signature, _) = priv_key.sign_prehash_recoverable(&hash.as_ref()).unwrap();

        let mut client = MockEcdsaClient::new();
        client
            .expect_sign()
            .returning(move |_, _, _| Ok(signature.to_vec().into()));

        let digest: MessageDigest = rand::random::<[u8; 32]>().into();

        assert_eq!(
            SharableEcdsaClient::new(client)
                .sign(
                    KEY_UID,
                    digest,
                    &SigningKey::random(&mut OsRng).verifying_key().into(),
                )
                .await
                .unwrap(),
            Signature::from(signature.to_vec()),
        );
    }

    #[test]
    async fn share_across_threads() {
        let mut hash = [0u8; 64];
        thread_rng().fill_bytes(&mut hash);

        let priv_key = SigningKey::<Secp256k1>::random(&mut OsRng);
        let (signature, _) = priv_key.sign_prehash_recoverable(&hash).unwrap();

        let mut client = MockEcdsaClient::new();
        client
            .expect_sign()
            .returning(move |_, _, _| Ok(signature.to_vec().into()));

        let client = SharableEcdsaClient::new(client);

        let mut handles = Vec::new();
        for _ in 0..5 {
            let cloned = client.clone();
            let handle = tokio::spawn(async move {
                let digest: MessageDigest = rand::random::<[u8; 32]>().into();
                assert_eq!(
                    cloned
                        .sign(
                            KEY_UID,
                            digest,
                            &SigningKey::random(&mut OsRng).verifying_key().into()
                        )
                        .await
                        .unwrap(),
                    Signature::from(signature.to_vec()),
                )
            });
            handles.push(handle);
        }

        join_all(handles).await;
    }
}
