use ampd_proto::crypto_service_server::CryptoService;
use ampd_proto::{KeyRequest, KeyResponse, SignRequest, SignResponse};
use async_trait::async_trait;
use sha3::{Digest, Keccak256};
use tonic::{Request, Response, Status};

use crate::grpc::{reqs, status};
use crate::tofnd::Multisig;

pub struct Service<T>(T)
where
    T: Multisig;

impl<T> From<T> for Service<T>
where
    T: Multisig,
{
    fn from(inner: T) -> Self {
        Self(inner)
    }
}

#[async_trait]
impl<T> CryptoService for Service<T>
where
    T: Multisig + Send + Sync + 'static,
{
    async fn sign(&self, req: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let (id, algorithm, msg) = reqs::validate_sign(req)
            .inspect_err(status::log("invalid sign request"))
            .map_err(status::StatusExt::into_status)?;
        // TODO: memoize the key
        let pub_key = self
            .0
            .keygen(&id, algorithm)
            .await
            .inspect_err(status::log("query key error"))
            .map_err(status::StatusExt::into_status)?;
        let msg_hash: [u8; 32] = Keccak256::digest(msg.as_ref()).into();

        self.0
            .sign(&id, msg_hash, pub_key, algorithm)
            .await
            .map(|signature| SignResponse { signature })
            .map(Response::new)
            .inspect_err(status::log("sign error"))
            .map_err(status::StatusExt::into_status)
    }

    async fn key(&self, req: Request<KeyRequest>) -> Result<Response<KeyResponse>, Status> {
        let (id, algorithm) = reqs::validate_key(req)
            .inspect_err(status::log("invalid key request"))
            .map_err(status::StatusExt::into_status)?;

        self.0
            .keygen(&id, algorithm)
            .await
            .map(|pub_key| KeyResponse {
                pub_key: pub_key.to_bytes(),
            })
            .map(Response::new)
            .inspect_err(status::log("query key error"))
            .map_err(status::StatusExt::into_status)
    }
}

#[cfg(test)]
mod tests {
    use ampd_proto::{Algorithm, KeyId, KeyRequest, SignRequest};
    use error_stack::report;
    use mockall::predicate;
    use rand::rngs::OsRng;
    use sha3::{Digest, Keccak256};
    use tonic::{Code, Request};

    use super::*;
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

        let service = Service::from(multisig);
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
        let service = Service::from(multisig);

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
        let service = Service::from(multisig);

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
    async fn key_should_propagate_tofnd_errors() {
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

        let service = Service::from(multisig);
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
        let message = vec![1, 2, 3, 4];
        let signing_key = k256::ecdsa::SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pub_key = PublicKey::new_secp256k1(verifying_key.to_sec1_bytes()).unwrap();
        let expected_signature_val = vec![5, 6, 7, 8]; // Mock signature

        let msg_hash: [u8; 32] = Keccak256::digest(&message).into();

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
                predicate::eq(msg_hash),
                predicate::eq(pub_key),
                predicate::eq(tofnd::Algorithm::Ecdsa),
            )
            .return_once(move |_, _, _, _| Ok(expected_signature_val.clone()));

        let service = Service::from(multisig);
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
        let service = Service::from(multisig);

        let request = Request::new(SignRequest {
            key_id: Some(KeyId {
                id: "".to_string(),
                algorithm: Algorithm::Ecdsa.into(),
            }),
            msg: vec![1, 2, 3, 4],
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
        let service = Service::from(multisig);

        let request = Request::new(SignRequest {
            key_id: Some(KeyId {
                id: "test_key".to_string(),
                algorithm: 999,
            }),
            msg: vec![1, 2, 3, 4],
        });

        let err = service.sign(request).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn sign_should_propagate_keygen_errors() {
        let key_id = "test_key";
        let algorithm = Algorithm::Ecdsa;
        let message = vec![1, 2, 3, 4];

        let mut multisig = MockMultisig::new();
        multisig
            .expect_keygen()
            .with(
                predicate::eq(key_id),
                predicate::eq(tofnd::Algorithm::Ecdsa),
            )
            .return_once(|_, _| Err(report!(tofnd::Error::InvalidKeygenResponse)));

        let service = Service::from(multisig);
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
    async fn sign_should_propagate_sign_errors() {
        let key_id = "test_key";
        let algorithm = Algorithm::Ecdsa;
        let message = vec![1, 2, 3, 4];
        let signing_key = k256::ecdsa::SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pub_key = PublicKey::new_secp256k1(verifying_key.to_sec1_bytes()).unwrap();

        let msg_hash: [u8; 32] = Keccak256::digest(&message).into();

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
                predicate::eq(msg_hash),
                predicate::eq(pub_key),
                predicate::eq(tofnd::Algorithm::Ecdsa),
            )
            .return_once(|_, _, _, _| Err(report!(tofnd::Error::InvalidSignResponse)));

        let service = Service::from(multisig);
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
}
