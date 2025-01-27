use error_stack::{Report, Result};
use tonic::{codegen, transport};

use super::proto::ampd_client::AmpdClient;
use super::proto::crypto_client::CryptoClient;

pub struct Client {
    pub ampd: AmpdClient<transport::Channel>,
    pub crypto: CryptoClient<transport::Channel>,
}

pub async fn new<D>(dst: D) -> Result<Client, transport::Error>
where
    D: TryInto<transport::Endpoint>,
    D::Error: Into<codegen::StdError>,
{
    let conn = transport::Endpoint::new(dst)
        .map_err(Report::new)?
        .connect()
        .await
        .map_err(Report::new)?;

    let ampd = AmpdClient::new(conn.clone());
    let crypto = CryptoClient::new(conn);

    Ok(Client { ampd, crypto })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use cosmrs::bank::MsgSend;
    use cosmrs::tx::Msg;
    use cosmrs::{AccountId, Any};
    use error_stack::Report;
    use events::Event;
    use futures::StreamExt;
    use k256::ecdsa::SigningKey;
    use k256::sha2::{Digest, Sha256};
    use mockall::predicate;
    use rand::rngs::OsRng;
    use tokio::net::TcpListener;
    use tokio::sync::{mpsc, oneshot};
    use tokio::{test, time};
    use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
    use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
    use tonic::Code;
    use url::Url;

    use crate::event_sub::MockEventSub;
    use crate::grpc;
    use crate::proto::{
        Algorithm, BroadcastRequest, BroadcastResponse, KeyRequest, KeyResponse, SignRequest,
        SignResponse, SubscribeRequest,
    };
    use crate::queue::queued_broadcaster::MockBroadcasterClient;
    use crate::tofnd::grpc::MockMultisig;
    use crate::tofnd::{self};
    use crate::types::PublicKey;

    async fn start_server(
        event_sub: MockEventSub,
        broadcaster: MockBroadcasterClient,
        multisig_client: MockMultisig,
    ) -> (Url, oneshot::Sender<()>) {
        let (tx, rx) = oneshot::channel::<()>();
        let server = grpc::server::new(event_sub, broadcaster, multisig_client);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(
            server.serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                drop(rx.await)
            }),
        );
        time::sleep(Duration::from_millis(100)).await;

        (format!("http://{addr}").parse().unwrap(), tx)
    }

    #[test]
    async fn key_should_work() {
        let key_id = "key_id";
        let key: PublicKey = SigningKey::random(&mut OsRng).verifying_key().into();
        let algorithm = Algorithm::Ed25519;

        let mut multisig_client = MockMultisig::new();
        multisig_client
            .expect_keygen()
            .with(
                predicate::eq(key_id),
                predicate::eq(tofnd::Algorithm::from(algorithm)),
            )
            .return_once(move |_, _| Ok(key));

        let (url, tx) = start_server(
            MockEventSub::new(),
            MockBroadcasterClient::new(),
            multisig_client,
        )
        .await;
        assert_eq!(
            grpc::client::new(url.to_string())
                .await
                .unwrap()
                .crypto
                .key(KeyRequest {
                    key_id: key_id.to_string(),
                    algorithm: algorithm.into(),
                })
                .await
                .unwrap()
                .into_inner(),
            KeyResponse {
                pub_key: key.to_bytes()
            }
        );

        tx.send(()).unwrap();
    }

    #[test]
    async fn sign_should_work() {
        let key_id = "key_id";
        let algorithm = Algorithm::Ed25519;
        let key: PublicKey = SigningKey::random(&mut OsRng).verifying_key().into();
        let msg = b"message";
        let mut hasher = Sha256::new();
        hasher.update(msg);
        let sign_digest: [u8; 32] = hasher.finalize().to_vec().try_into().unwrap();

        let mut multisig_client = MockMultisig::new();
        multisig_client
            .expect_keygen()
            .with(
                predicate::eq(key_id),
                predicate::eq(tofnd::Algorithm::from(algorithm)),
            )
            .return_once(move |_, _| Ok(key));
        multisig_client
            .expect_sign()
            .with(
                predicate::eq(key_id),
                predicate::eq(tofnd::MessageDigest::from(sign_digest)),
                predicate::function(move |actual: &PublicKey| actual == &key),
                predicate::eq(tofnd::Algorithm::from(algorithm)),
            )
            .return_once(|_, _, _, _| Ok(vec![1; 64]));

        let (url, tx) = start_server(
            MockEventSub::new(),
            MockBroadcasterClient::new(),
            multisig_client,
        )
        .await;
        assert_eq!(
            grpc::client::new(url.to_string())
                .await
                .unwrap()
                .crypto
                .sign(SignRequest {
                    key_id: key_id.to_string(),
                    msg: msg.to_vec(),
                    algorithm: algorithm.into(),
                })
                .await
                .unwrap()
                .into_inner(),
            SignResponse {
                signature: vec![1; 64]
            }
        );

        tx.send(()).unwrap();
    }

    #[test]
    async fn broadcast_should_work() {
        let msg = dummy_msg();

        let mut broadcaster = MockBroadcasterClient::new();
        broadcaster
            .expect_broadcast()
            .with(predicate::eq(msg.clone()))
            .return_once(|_| Ok(()));

        let (url, tx) = start_server(MockEventSub::new(), broadcaster, MockMultisig::new()).await;
        assert_eq!(
            grpc::client::new(url.to_string())
                .await
                .unwrap()
                .ampd
                .broadcast(BroadcastRequest { msg: Some(msg) })
                .await
                .unwrap()
                .into_inner(),
            BroadcastResponse {}
        );

        tx.send(()).unwrap();
    }

    #[test]
    async fn subscribe_should_work() {
        let mut event_sub = MockEventSub::new();
        let (event_tx, event_rx) = mpsc::channel(1);
        event_sub
            .expect_subscribe()
            .return_once(|| Box::pin(ReceiverStream::new(event_rx)));

        let (url, tx) =
            start_server(event_sub, MockBroadcasterClient::new(), MockMultisig::new()).await;
        let mut stream = grpc::client::new(url.to_string())
            .await
            .unwrap()
            .ampd
            .subscribe(SubscribeRequest {
                event_filters: vec![],
                include_block_begin_end: true,
            })
            .await
            .unwrap()
            .into_inner();

        let event = Event::BlockBegin(1u32.into());
        event_tx.send(Ok(event.clone())).await.unwrap();
        assert_eq!(
            stream.next().await.unwrap().unwrap().event,
            Some(event.into())
        );

        let event = Event::Abci {
            event_type: "some_event".into(),
            attributes: serde_json::from_str("{\"key_1\":\"value_1\",\"key_2\":\"value_2\"}")
                .unwrap(),
        };
        event_tx.send(Ok(event.clone())).await.unwrap();
        assert_eq!(
            stream.next().await.unwrap().unwrap().event,
            Some(event.into())
        );

        let event = Event::BlockEnd(1u32.into());
        event_tx.send(Ok(event.clone())).await.unwrap();
        assert_eq!(
            stream.next().await.unwrap().unwrap().event,
            Some(event.into())
        );

        event_tx
            .send(Err(Report::new(BroadcastStreamRecvError::Lagged(10))))
            .await
            .unwrap();
        assert_eq!(
            stream.next().await.unwrap().unwrap_err().code(),
            Code::Internal
        );

        let event = Event::BlockBegin(2u32.into());
        assert!(event_tx.send(Ok(event.clone())).await.is_err());

        drop(stream);
        tx.send(()).unwrap();
    }

    fn dummy_msg() -> Any {
        MsgSend {
            from_address: AccountId::new("", &[1, 2, 3]).unwrap(),
            to_address: AccountId::new("", &[4, 5, 6]).unwrap(),
            amount: vec![],
        }
        .to_any()
        .unwrap()
    }
}
