use ampd_proto::crypto_service_server::CryptoService;
use ampd_proto::{KeyRequest, KeyResponse, SignRequest, SignResponse};
use async_trait::async_trait;
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
    async fn sign(&self, _req: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        todo!("implement sign method")
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
            .inspect_err(status::log("message broadcast error"))
            .map_err(status::StatusExt::into_status)
    }
}

#[cfg(test)]
mod tests {
    use ampd_proto::{Algorithm, KeyId, KeyRequest};
    use error_stack::report;
    use mockall::predicate;
    use rand::rngs::OsRng;
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
        let expected_pub_key = PublicKey::new_secp256k1(&verifying_key.to_sec1_bytes()).unwrap();

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
}
