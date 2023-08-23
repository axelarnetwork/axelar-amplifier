#![allow(dead_code)]

use ecdsa::VerifyingKey;
use error_stack::{FutureExt, IntoReport, ResultExt};
use tokio::{sync::mpsc, sync::oneshot};

use super::proto::{
    keygen_response::KeygenResponse, sign_response::SignResponse, KeygenRequest, SignRequest,
};
use super::{error::Error, error::TofndError, grpc::MultisigClient, Signature};
use crate::types::PublicKey;

type Result<T> = error_stack::Result<T, Error>;

type Handle<T> = oneshot::Sender<Result<T>>;

enum Request {
    Keygen {
        request: KeygenRequest,
        handle: Handle<PublicKey>,
    },
    Sign {
        request: SignRequest,
        handle: Handle<Signature>,
    },
}

pub struct Client {
    party_uid: String,
    sender: mpsc::Sender<Request>,
}

impl Client {
    pub async fn keygen(&self, key_uid: &str) -> Result<PublicKey> {
        self.send(|handle| Request::Keygen {
            request: KeygenRequest {
                key_uid: key_uid.to_string(),
                party_uid: self.party_uid.clone(),
            },
            handle,
        })
        .await
    }

    pub async fn sign(
        &self,
        key_uid: &str,
        data: Vec<u8>,
        pub_key: &PublicKey,
    ) -> Result<Signature> {
        self.send(|handle| Request::Sign {
            request: SignRequest {
                key_uid: key_uid.to_string(),
                msg_to_sign: data,
                party_uid: self.party_uid.clone(),
                pub_key: pub_key.to_bytes(),
            },
            handle,
        })
        .await
    }

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

pub struct TofndClient<T: MultisigClient> {
    party_uid: String,
    client: T,
    channel: (mpsc::Sender<Request>, mpsc::Receiver<Request>),
}

impl<T: MultisigClient> TofndClient<T> {
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
                Request::Sign { request, handle } => handle
                    .send(sign(&mut client, request).await)
                    .map_err(|_| Error::SendFailed)?,
                Request::Keygen { request, handle } => handle
                    .send(keygen(&mut client, request).await)
                    .map_err(|_| Error::SendFailed)?,
            }
        }

        Ok(())
    }

    pub fn client(&self) -> Client {
        Client {
            sender: self.channel.0.clone(),
            party_uid: self.party_uid.clone(),
        }
    }
}

async fn sign<T>(client: &mut T, request: SignRequest) -> Result<Signature>
where
    T: MultisigClient,
{
    client
        .sign(request)
        .change_context(Error::Grpc)
        .await
        .and_then(|response| match response {
            SignResponse::Signature(signature) => Ok(signature),
            SignResponse::Error(error_msg) => Err(TofndError::ExecutionFailed(error_msg))
                .into_report()
                .change_context(Error::SignFailed),
        })
}

async fn keygen<T>(client: &mut T, request: KeygenRequest) -> Result<PublicKey>
where
    T: MultisigClient,
{
    client
        .keygen(request)
        .change_context(Error::Grpc)
        .await
        .and_then(|response| match response {
            KeygenResponse::PubKey(pub_key) => VerifyingKey::from_sec1_bytes(pub_key.as_slice())
                .into_report()
                .change_context(Error::ParsingFailed)
                .attach_printable(format!("{{ invalid_value = {:?} }}", pub_key))
                .map(Into::into),
            KeygenResponse::Error(error_msg) => Err(TofndError::ExecutionFailed(error_msg))
                .into_report()
                .change_context(Error::KeygenFailed),
        })
}

#[cfg(test)]
mod tests {
    use error_stack::IntoReport;
    use tokio::{task::JoinHandle, test};
    use tonic::Status;

    use crate::broadcaster::key::ECDSASigningKey;
    use crate::tofnd::{
        client::{Client, TofndClient},
        error::Error,
        grpc::{MockMultisigClient, MultisigClient},
        proto::{keygen_response, sign_response},
    };

    fn init_client<T: MultisigClient + Send + 'static>(client: T) -> (Client, JoinHandle<()>) {
        let tofnd_client = TofndClient::new(client, "party_uid".to_string(), 1000);
        let client = tofnd_client.client();

        let handler = tokio::spawn(async move {
            assert!(tofnd_client.run().await.is_ok());
        });

        (client, handler)
    }

    #[test]
    async fn keygen_empty_response() {
        let mut client = MockMultisigClient::new();
        client
            .expect_keygen()
            .returning(|_| Err(Status::internal("keygen response is empty")).into_report());

        let (client, handler) = init_client(client);

        assert!(matches!(
            client.keygen("key").await.unwrap_err().current_context(),
            Error::Grpc
        ));

        drop(client);
        assert!(handler.await.is_ok());
    }

    #[test]
    async fn keygen_invalid_pubkey() {
        let mut client = MockMultisigClient::new();
        client
            .expect_keygen()
            .returning(|_| Ok(keygen_response::KeygenResponse::PubKey(vec![0, 1, 2, 3])));

        let (client, handler) = init_client(client);

        assert!(matches!(
            client.keygen("key").await.unwrap_err().current_context(),
            Error::ParsingFailed
        ));

        drop(client);
        assert!(handler.await.is_ok());
    }

    #[test]
    async fn keygen_error_response() {
        let mut client = MockMultisigClient::new();
        client.expect_keygen().returning(|_| {
            Ok(keygen_response::KeygenResponse::Error(String::from(
                "failed to generate key",
            )))
        });

        let (client, handler) = init_client(client);

        assert!(matches!(
            client.keygen("key").await.unwrap_err().current_context(),
            Error::KeygenFailed
        ));

        drop(client);
        assert!(handler.await.is_ok());
    }

    #[test]
    async fn keygen_succeeded() {
        let rand_pub_key = ECDSASigningKey::random().public_key();

        let mut client = MockMultisigClient::new();
        client.expect_keygen().returning(move |_| {
            Ok(keygen_response::KeygenResponse::PubKey(
                rand_pub_key.to_bytes(),
            ))
        });

        let (client, handler) = init_client(client);

        assert_eq!(client.keygen("key").await.unwrap(), rand_pub_key);

        drop(client);
        assert!(handler.await.is_ok());
    }

    #[test]
    async fn sign_empty_response() {
        let mut client = MockMultisigClient::new();
        client
            .expect_sign()
            .returning(|_| Err(Status::internal("sign response is empty")).into_report());

        let (client, handler) = init_client(client);

        let digest: [u8; 32] = rand::random();
        assert!(matches!(
            client
                .sign(
                    "key",
                    digest.to_vec(),
                    &ECDSASigningKey::random().public_key()
                )
                .await
                .unwrap_err()
                .current_context(),
            Error::Grpc
        ));

        drop(client);
        assert!(handler.await.is_ok());
    }

    #[test]
    async fn sign_error_response() {
        let err_str = "failed to sign";
        let mut client = MockMultisigClient::new();
        client
            .expect_sign()
            .returning(move |_| Ok(sign_response::SignResponse::Error(String::from(err_str))));

        let (client, handler) = init_client(client);

        let digest: [u8; 32] = rand::random();
        assert!(matches!(
            client
                .sign(
                    "key",
                    digest.to_vec(),
                    &ECDSASigningKey::random().public_key()
                )
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
        let mut client = MockMultisigClient::new();
        client
            .expect_sign()
            .returning(move |_| Ok(sign_response::SignResponse::Signature(vec![0, 1, 2, 3])));

        let (client, handler) = init_client(client);

        let digest: [u8; 32] = rand::random();
        assert_eq!(
            client
                .sign(
                    "key",
                    digest.to_vec(),
                    &ECDSASigningKey::random().public_key(),
                )
                .await
                .unwrap(),
            vec![0, 1, 2, 3]
        );

        drop(client);
        assert!(handler.await.is_ok());
    }
}
