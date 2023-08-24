#![allow(dead_code)]

use async_trait::async_trait;
use error_stack::{IntoReport, ResultExt};
use mockall::automock;
use tokio::{sync::mpsc, sync::oneshot};

use super::{error::Error, grpc, MessageDigest, Signature};
use crate::types::PublicKey;

type Result<T> = error_stack::Result<T, Error>;

type Handle<T> = oneshot::Sender<Result<T>>;

#[automock]
#[async_trait]
pub trait EcdsaClient {
    async fn keygen(&self, key_uid: &str) -> Result<PublicKey>;
    async fn sign(
        &self,
        key_uid: &str,
        data: MessageDigest,
        pub_key: &PublicKey,
    ) -> Result<Signature>;
}

enum Request {
    Keygen {
        params: (String, String),
        handle: Handle<PublicKey>,
    },
    Sign {
        params: (String, String, MessageDigest, PublicKey),
        handle: Handle<Signature>,
    },
}

pub struct TofndClient {
    party_uid: String,
    sender: mpsc::Sender<Request>,
}

#[async_trait]
impl EcdsaClient for TofndClient {
    async fn keygen(&self, key_uid: &str) -> Result<PublicKey> {
        self.send(|handle| Request::Keygen {
            params: (key_uid.to_string(), self.party_uid.to_string()),
            handle,
        })
        .await
    }

    async fn sign(
        &self,
        key_uid: &str,
        data: MessageDigest,
        pub_key: &PublicKey,
    ) -> Result<Signature> {
        self.send(|handle| Request::Sign {
            params: (
                key_uid.to_string(),
                self.party_uid.to_string(),
                data,
                *pub_key,
            ),
            handle,
        })
        .await
    }
}

impl TofndClient {
    async fn send<T>(&self, with_handle: impl FnOnce(Handle<T>) -> Request) -> Result<T> {
        let (tx, rx) = oneshot::channel();

        self.sender
            .send(with_handle(tx))
            .await
            .into_report()
            .change_context(Error::SendFailed)?;

        rx.await.into_report().change_context(Error::RecvFailed)?
    }
}

pub struct Tofnd<T: grpc::EcdsaClient> {
    party_uid: String,
    client: T,
    channel: (mpsc::Sender<Request>, mpsc::Receiver<Request>),
}

impl<T: grpc::EcdsaClient> Tofnd<T> {
    pub fn new(client: T, party_uid: String, capacity: usize) -> Self {
        Self {
            party_uid,
            client,
            channel: mpsc::channel(capacity),
        }
    }

    pub async fn run(self) -> error_stack::Result<(), Error> {
        let (tx, mut rx) = self.channel;
        drop(tx);

        let mut client = self.client;

        while let Some(request) = rx.recv().await {
            match request {
                Request::Sign {
                    params: (key_uid, party_uid, data, pub_key),
                    handle,
                } => handle
                    .send(client.sign(&key_uid, &party_uid, data, &pub_key).await)
                    .map_err(|_| Error::SendFailed)?,
                Request::Keygen {
                    params: (key_uid, party_uid),
                    handle,
                } => handle
                    .send(client.keygen(&key_uid, &party_uid).await)
                    .map_err(|_| Error::SendFailed)?,
            }
        }

        Ok(())
    }

    pub fn client(&self) -> TofndClient {
        TofndClient {
            sender: self.channel.0.clone(),
            party_uid: self.party_uid.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use error_stack::Report;
    use rand::{thread_rng, RngCore};
    use tokio::{task::JoinHandle, test};

    use crate::broadcaster::key::ECDSASigningKey;
    use crate::tofnd::{
        client::{EcdsaClient, Tofnd, TofndClient},
        error::Error,
        grpc::{self, MockEcdsaClient},
        MessageDigest,
    };

    const KEY_UID: &str = "key";

    fn init_client<T: grpc::EcdsaClient + Send + 'static>(
        client: T,
    ) -> (TofndClient, JoinHandle<()>) {
        let tofnd_client = Tofnd::new(client, "party_uid".to_string(), 1000);
        let client = tofnd_client.client();

        let handler = tokio::spawn(async move {
            assert!(tofnd_client.run().await.is_ok());
        });

        (client, handler)
    }

    #[test]
    async fn keygen_error_response() {
        let mut client = MockEcdsaClient::new();
        client
            .expect_keygen()
            .returning(|_, _| Err(Report::from(Error::KeygenFailed)));

        let (client, handler) = init_client(client);

        assert!(matches!(
            client.keygen(KEY_UID).await.unwrap_err().current_context(),
            Error::KeygenFailed
        ));

        drop(client);
        assert!(handler.await.is_ok());
    }

    #[test]
    async fn keygen_succeeded() {
        let rand_pub_key = ECDSASigningKey::random().public_key();

        let mut client = MockEcdsaClient::new();
        client
            .expect_keygen()
            .returning(move |_, _| Ok(rand_pub_key));

        let (client, handler) = init_client(client);

        assert_eq!(client.keygen(KEY_UID).await.unwrap(), rand_pub_key);

        drop(client);
        assert!(handler.await.is_ok());
    }

    #[test]
    async fn sign_error_response() {
        let mut client = MockEcdsaClient::new();
        client
            .expect_sign()
            .returning(move |_, _, _, _| Err(Report::from(Error::SignFailed)));

        let (client, handler) = init_client(client);

        let digest: MessageDigest = rand::random::<[u8; 32]>().into();
        assert!(matches!(
            client
                .sign(KEY_UID, digest, &ECDSASigningKey::random().public_key())
                .await
                .unwrap_err()
                .current_context(),
            Error::SignFailed
        ));

        drop(client);
        assert!(handler.await.is_ok());
    }

    #[test]
    async fn sign_succeeded() {
        let mut sig = [0u8; 64];
        thread_rng().fill_bytes(&mut sig);

        let mut client = MockEcdsaClient::new();
        client
            .expect_sign()
            .returning(move |_, _, _, _| Ok(Vec::from(sig)));

        let (client, handler) = init_client(client);

        let digest: MessageDigest = rand::random::<[u8; 32]>().into();
        assert_eq!(
            client
                .sign(KEY_UID, digest, &ECDSASigningKey::random().public_key(),)
                .await
                .unwrap(),
            Vec::from(sig)
        );

        drop(client);
        assert!(handler.await.is_ok());
    }
}
