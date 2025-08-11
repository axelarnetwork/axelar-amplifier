use ampd_proto::crypto_service_server::CryptoService;
use ampd_proto::{KeyRequest, KeyResponse, SignRequest, SignResponse};
use async_trait::async_trait;
use tonic::{Request, Response, Status};

use crate::grpc::reqs::Validate;
use crate::grpc::status;
use crate::monitoring;
use crate::monitoring::metrics::Msg;
use crate::tofnd::Multisig;

pub struct Service<T>
where
    T: Multisig,
{
    multisig_client: T,
    monitoring_client: monitoring::Client,
}

impl<T> Service<T>
where
    T: Multisig,
{
    pub fn new(multisig_client: T, monitoring_client: monitoring::Client) -> Self {
        Self {
            multisig_client,
            monitoring_client,
        }
    }
}

#[async_trait]
impl<T> CryptoService for Service<T>
where
    T: Multisig + Send + Sync + 'static,
{
    async fn sign(&self, req: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let (id, algorithm, msg_hash) = req
            .validate()
            .inspect_err(status::log("invalid sign request"))
            .map_err(status::StatusExt::into_status)?;
        // TODO: memoize the key
        let pub_key = self
            .multisig_client
            .keygen(&id, algorithm)
            .await
            .inspect_err(|err| {
                self.monitoring_client
                    .metrics()
                    .record_metric(Msg::GrpcServiceError);
                status::log("querying the public key of the signer failed")(err)
            })
            .map_err(status::StatusExt::into_status)?;

        self.multisig_client
            .sign(&id, msg_hash, pub_key, algorithm)
            .await
            .map(|signature| SignResponse { signature })
            .map(Response::new)
            .inspect_err(|err| {
                self.monitoring_client
                    .metrics()
                    .record_metric(Msg::GrpcServiceError);
                status::log("signing failed")(err)
            })
            .map_err(status::StatusExt::into_status)
    }

    async fn key(&self, req: Request<KeyRequest>) -> Result<Response<KeyResponse>, Status> {
        let (id, algorithm) = req
            .validate()
            .inspect_err(status::log("invalid key request"))
            .map_err(status::StatusExt::into_status)?;

        self.multisig_client
            .keygen(&id, algorithm)
            .await
            .map(|pub_key| KeyResponse {
                pub_key: pub_key.to_bytes(),
            })
            .map(Response::new)
            .inspect_err(|err| {
                self.monitoring_client
                    .metrics()
                    .record_metric(Msg::GrpcServiceError);
                status::log("querying the public key failed")(err)
            })
            .map_err(status::StatusExt::into_status)
    }
}

#[cfg(test)]
mod tests {
    use ampd_proto::{Algorithm, KeyId, KeyRequest, SignRequest};
    use error_stack::report;
    use mockall::predicate;
    use rand::rngs::OsRng;
    use tonic::{Code, Request};

    use super::*;
    use crate::monitoring::test_utils;
    use crate::tofnd::{self, MockMultisig};
    use crate::types::PublicKey;

    #[tokio::test]
    async fn key_should_return_public_key_on_valid_request() {
        let key_id = "test_key";
        let algorithm = Algorithm::Ecdsa;
        let signing_key = k256::ecdsa::SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let expected_pub_key = PublicKey::new_secp256k1(verifying_key.to_sec1_bytes()).unwrap();

        let mut multisig = MockMultisig::new();
        multisig
            .expect_keygen()
            .with(
                predicate::eq(key_id),
                predicate::eq(tofnd::Algorithm::Ecdsa),
            )
            .return_once(move |_, _| Ok(expected_pub_key));

        let (monitoring_client, _) = test_utils::monitoring_client();
        let service = Service::new(multisig, monitoring_client);
        let request = Request::new(KeyRequest {
            key_id: Some(KeyId {
                id: key_id.to_string(),
                algorithm: algorithm.into(),
            }),
        });

        let res = service.key(request).await.unwrap();
        assert_eq!(res.get_ref().pub_key, expected_pub_key.to_bytes());
    }

    #[tokio::test]
    async fn key_should_return_error_on_invalid_key_id() {
        let multisig = MockMultisig::new();
        let (monitoring_client, _) = test_utils::monitoring_client();
        let service = Service::new(multisig, monitoring_client);

        let request = Request::new(KeyRequest {
            key_id: Some(KeyId {
                id: "".to_string(),
                algorithm: Algorithm::Ecdsa.into(),
            }),
        });

        let err = service.key(request).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn key_should_return_error_on_invalid_algorithm() {
        let multisig = MockMultisig::new();
        let (monitoring_client, _) = test_utils::monitoring_client();
        let service = Service::new(multisig, monitoring_client);

        let request = Request::new(KeyRequest {
            key_id: Some(KeyId {
                id: "test_key".to_string(),
                algorithm: 999,
            }),
        });

        let err = service.key(request).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn key_should_return_internal_error_when_tofnd_errors() {
        let key_id = "test_key";
        let algorithm = Algorithm::Ecdsa;

        let mut multisig = MockMultisig::new();
        multisig
            .expect_keygen()
            .with(
                predicate::eq(key_id),
                predicate::eq(tofnd::Algorithm::Ecdsa),
            )
            .return_once(|_, _| Err(report!(tofnd::Error::InvalidKeygenResponse)));

        let (monitoring_client, _) = test_utils::monitoring_client();
        let service = Service::new(multisig, monitoring_client);
        let request = Request::new(KeyRequest {
            key_id: Some(KeyId {
                id: key_id.to_string(),
                algorithm: algorithm.into(),
            }),
        });

        let err = service.key(request).await.unwrap_err();
        assert_eq!(err.code(), Code::Internal);
    }

    #[tokio::test]
    async fn sign_should_return_signature_on_valid_request() {
        let key_id = "test_key";
        let algorithm = Algorithm::Ecdsa;
        let message = vec![0; 32];
        let signing_key = k256::ecdsa::SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pub_key = PublicKey::new_secp256k1(verifying_key.to_sec1_bytes()).unwrap();
        let expected_signature_val = vec![5, 6, 7, 8]; // Mock signature

        let expected_msg = <[u8; 32]>::try_from(message.as_slice()).unwrap();

        let mut multisig = MockMultisig::new();
        multisig
            .expect_keygen()
            .with(
                predicate::eq(key_id),
                predicate::eq(tofnd::Algorithm::Ecdsa),
            )
            .return_once(move |_, _| Ok(pub_key));
        multisig
            .expect_sign()
            .with(
                predicate::eq(key_id),
                predicate::eq(expected_msg),
                predicate::eq(pub_key),
                predicate::eq(tofnd::Algorithm::Ecdsa),
            )
            .return_once(move |_, _, _, _| Ok(expected_signature_val.clone()));

        let (monitoring_client, _) = test_utils::monitoring_client();
        let service = Service::new(multisig, monitoring_client);
        let request = Request::new(SignRequest {
            key_id: Some(KeyId {
                id: key_id.to_string(),
                algorithm: algorithm.into(),
            }),
            msg: message,
        });

        let res = service.sign(request).await.unwrap();
        assert_eq!(res.get_ref().signature, vec![5, 6, 7, 8]);
    }

    #[tokio::test]
    async fn sign_should_return_error_on_invalid_request() {
        let multisig = MockMultisig::new();
        let (monitoring_client, _) = test_utils::monitoring_client();
        let service = Service::new(multisig, monitoring_client);

        let request = Request::new(SignRequest {
            key_id: Some(KeyId {
                id: "".to_string(),
                algorithm: Algorithm::Ecdsa.into(),
            }),
            msg: vec![0; 32],
        });

        let err = service.sign(request).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);

        let request = Request::new(SignRequest {
            key_id: Some(KeyId {
                id: "test_key".to_string(),
                algorithm: Algorithm::Ecdsa.into(),
            }),
            msg: vec![],
        });

        let err = service.sign(request).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn sign_should_return_error_on_invalid_algorithm() {
        let multisig = MockMultisig::new();
        let (monitoring_client, _) = test_utils::monitoring_client();
        let service = Service::new(multisig, monitoring_client);

        let request = Request::new(SignRequest {
            key_id: Some(KeyId {
                id: "test_key".to_string(),
                algorithm: 999,
            }),
            msg: vec![0; 32],
        });

        let err = service.sign(request).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn sign_should_return_internal_error_when_tofnd_keygen_errors() {
        let key_id = "test_key";
        let algorithm = Algorithm::Ecdsa;
        let message = vec![0; 32];

        let mut multisig = MockMultisig::new();
        multisig
            .expect_keygen()
            .with(
                predicate::eq(key_id),
                predicate::eq(tofnd::Algorithm::Ecdsa),
            )
            .return_once(|_, _| Err(report!(tofnd::Error::InvalidKeygenResponse)));

        let (monitoring_client, _) = test_utils::monitoring_client();
        let service = Service::new(multisig, monitoring_client);
        let request = Request::new(SignRequest {
            key_id: Some(KeyId {
                id: key_id.to_string(),
                algorithm: algorithm.into(),
            }),
            msg: message,
        });

        let err = service.sign(request).await.unwrap_err();
        assert_eq!(err.code(), Code::Internal);
    }

    #[tokio::test]
    async fn sign_should_return_internal_error_when_tofnd_sign_errors() {
        let key_id = "test_key";
        let algorithm = Algorithm::Ecdsa;
        let message = vec![0; 32];
        let signing_key = k256::ecdsa::SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pub_key = PublicKey::new_secp256k1(verifying_key.to_sec1_bytes()).unwrap();

        let expected_msg = <[u8; 32]>::try_from(message.as_slice()).unwrap();

        let mut multisig = MockMultisig::new();
        multisig
            .expect_keygen()
            .with(
                predicate::eq(key_id),
                predicate::eq(tofnd::Algorithm::Ecdsa),
            )
            .return_once(move |_, _| Ok(pub_key));
        multisig
            .expect_sign()
            .with(
                predicate::eq(key_id),
                predicate::eq(expected_msg),
                predicate::eq(pub_key),
                predicate::eq(tofnd::Algorithm::Ecdsa),
            )
            .return_once(|_, _, _, _| Err(report!(tofnd::Error::InvalidSignResponse)));

        let (monitoring_client, _) = test_utils::monitoring_client();
        let service = Service::new(multisig, monitoring_client);
        let request = Request::new(SignRequest {
            key_id: Some(KeyId {
                id: key_id.to_string(),
                algorithm: algorithm.into(),
            }),
            msg: message,
        });

        let err = service.sign(request).await.unwrap_err();
        assert_eq!(err.code(), Code::Internal);
    }

    #[tokio::test]
    async fn should_record_grpc_service_metrics_when_keygen_failed() {
        let key_id = "test_key";
        let algorithm = Algorithm::Ecdsa;
        let message = vec![0; 32];

        let mut multisig = MockMultisig::new();
        multisig
            .expect_keygen()
            .times(2)
            .with(
                predicate::eq(key_id),
                predicate::eq(tofnd::Algorithm::Ecdsa),
            )
            .returning(|_, _| Err(report!(tofnd::Error::InvalidKeygenResponse)));

        let (monitoring_client, mut metrics_rx) = test_utils::monitoring_client();
        let service = Service::new(multisig, monitoring_client);
        let request_1 = Request::new(SignRequest {
            key_id: Some(KeyId {
                id: key_id.to_string(),
                algorithm: algorithm.into(),
            }),
            msg: message,
        });

        let _ = service.sign(request_1).await.unwrap_err();

        let res = metrics_rx.recv().await.unwrap();
        assert_eq!(res, Msg::GrpcServiceError);

        let request_2 = Request::new(KeyRequest {
            key_id: Some(KeyId {
                id: key_id.to_string(),
                algorithm: algorithm.into(),
            }),
        });

        let _ = service.key(request_2).await.unwrap_err();
        let res = metrics_rx.recv().await.unwrap();
        assert_eq!(res, Msg::GrpcServiceError);

        assert!(metrics_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn should_record_grpc_service_err_when_sign_failed() {
        let key_id = "test_key";
        let algorithm = Algorithm::Ecdsa;
        let message = vec![0; 32];
        let signing_key = k256::ecdsa::SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pub_key = PublicKey::new_secp256k1(verifying_key.to_sec1_bytes()).unwrap();

        let expected_msg = <[u8; 32]>::try_from(message.as_slice()).unwrap();

        let mut multisig = MockMultisig::new();
        multisig
            .expect_keygen()
            .with(
                predicate::eq(key_id),
                predicate::eq(tofnd::Algorithm::Ecdsa),
            )
            .return_once(move |_, _| Ok(pub_key));
        multisig
            .expect_sign()
            .with(
                predicate::eq(key_id),
                predicate::eq(expected_msg),
                predicate::eq(pub_key),
                predicate::eq(tofnd::Algorithm::Ecdsa),
            )
            .return_once(|_, _, _, _| Err(report!(tofnd::Error::InvalidSignResponse)));

        let (monitoring_client, mut metrics_rx) = test_utils::monitoring_client();
        let service = Service::new(multisig, monitoring_client);
        let request = Request::new(SignRequest {
            key_id: Some(KeyId {
                id: key_id.to_string(),
                algorithm: algorithm.into(),
            }),
            msg: message,
        });

        let _ = service.sign(request).await.unwrap_err();

        let res = metrics_rx.recv().await.unwrap();
        assert_eq!(res, Msg::GrpcServiceError);

        assert!(metrics_rx.try_recv().is_err());
    }
}
