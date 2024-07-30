use async_trait::async_trait;
use k256::sha2::{Digest, Sha256};
use tonic::{Request, Response, Status};

use super::proto;
use crate::tofnd::grpc::Multisig;
use crate::tofnd::{self};
use crate::types::PublicKey;

impl From<proto::Algorithm> for tofnd::Algorithm {
    fn from(algorithm: proto::Algorithm) -> Self {
        match algorithm {
            proto::Algorithm::Ed25519 => Self::Ed25519,
            proto::Algorithm::Ecdsa => Self::Ecdsa,
        }
    }
}

pub struct Server<M> {
    multisig_client: M,
}

impl<M> Server<M>
where
    M: Multisig,
{
    pub fn new(multisig_client: M) -> Self {
        Self { multisig_client }
    }

    async fn key(&self, key_id: &str, algorithm: proto::Algorithm) -> Result<PublicKey, Status> {
        self.multisig_client
            .keygen(key_id, algorithm.into())
            .await
            .map_err(|err| Status::internal(err.to_string()))
    }
}

#[async_trait]
impl<M> proto::crypto_server::Crypto for Server<M>
where
    M: Multisig + Send + Sync + 'static,
{
    async fn sign(
        &self,
        req: Request<proto::SignRequest>,
    ) -> Result<Response<proto::SignResponse>, Status> {
        let req = req.into_inner();

        let mut hasher = Sha256::new();
        hasher.update(req.msg);
        let sign_digest: [u8; 32] = hasher
            .finalize()
            .to_vec()
            .try_into()
            .expect("hash size must be 32");

        let algorithm = proto::Algorithm::from_i32(req.algorithm)
            .ok_or(Status::invalid_argument("invalid algorithm"))?;
        let key = self.key(&req.key_id, algorithm).await?;
        let signature = self
            .multisig_client
            .sign(&req.key_id, sign_digest.into(), &key, algorithm.into())
            .await
            .map_err(|err| Status::internal(err.to_string()))?;

        Ok(Response::new(proto::SignResponse { signature }))
    }

    async fn key(
        &self,
        req: Request<proto::KeyRequest>,
    ) -> Result<Response<proto::KeyResponse>, Status> {
        let req = req.into_inner();

        let algorithm = proto::Algorithm::from_i32(req.algorithm)
            .ok_or(Status::invalid_argument("invalid algorithm"))?;
        let key = self.key(&req.key_id, algorithm).await?;

        Ok(Response::new(proto::KeyResponse {
            pub_key: key.to_bytes(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use ecdsa::SigningKey;
    use k256::sha2::{Digest, Sha256};
    use mockall::predicate;
    use rand::rngs::OsRng;
    use tokio::test;
    use tonic::Code;

    use super::proto::{self};
    use super::Server;
    use crate::proto::crypto_server;
    use crate::proto::crypto_server::Crypto;
    use crate::tofnd;
    use crate::tofnd::grpc::MockMultisig;
    use crate::types::PublicKey;

    #[test]
    async fn sign_should_return_correct_signature() {
        let key_id = "key_id";
        let algorithm = proto::Algorithm::Ecdsa;
        let key: PublicKey = SigningKey::random(&mut OsRng).verifying_key().into();
        let msg = b"message";
        let mut hasher = Sha256::new();
        hasher.update(msg);
        let sign_digest: [u8; 32] = hasher.finalize().to_vec().try_into().unwrap();

        let mut multisig_client = MockMultisig::default();
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
        let server = Server::new(multisig_client);

        let req = tonic::Request::new(proto::SignRequest {
            key_id: key_id.to_string(),
            msg: msg.to_vec(),
            algorithm: algorithm.into(),
        });
        let res = server.sign(req).await.unwrap().into_inner();

        assert_eq!(res.signature, vec![1; 64]);
    }

    #[test]
    async fn sign_should_return_error_when_algorithm_is_invalid() {
        let key_id = "key_id";
        let algorithm = 2;
        let msg = b"message";

        let multisig_client = MockMultisig::default();
        let server = Server::new(multisig_client);

        let req = tonic::Request::new(proto::SignRequest {
            key_id: key_id.to_string(),
            msg: msg.to_vec(),
            algorithm,
        });
        let res = server.sign(req).await.unwrap_err();

        assert_eq!(res.code(), Code::InvalidArgument);
    }

    #[test]
    async fn key_should_return_correct_key() {
        let key_id = "key_id";
        let algorithm = proto::Algorithm::Ecdsa;
        let key: PublicKey = SigningKey::random(&mut OsRng).verifying_key().into();

        let mut multisig_client = MockMultisig::default();
        multisig_client
            .expect_keygen()
            .with(
                predicate::eq(key_id),
                predicate::eq(tofnd::Algorithm::from(algorithm)),
            )
            .return_once(move |_, _| Ok(key));
        let server = Server::new(multisig_client);

        let req = tonic::Request::new(proto::KeyRequest {
            key_id: key_id.to_string(),
            algorithm: algorithm.into(),
        });
        let res = crypto_server::Crypto::key(&server, req)
            .await
            .unwrap()
            .into_inner();

        assert_eq!(res.pub_key, key.to_bytes());
    }

    #[test]
    async fn key_should_return_error_when_algorithm_is_invalid() {
        let key_id = "key_id";

        let multisig_client = MockMultisig::default();
        let server = Server::new(multisig_client);

        let req = tonic::Request::new(proto::KeyRequest {
            key_id: key_id.to_string(),
            algorithm: 2,
        });
        let res = crypto_server::Crypto::key(&server, req).await.unwrap_err();

        assert_eq!(res.code(), Code::InvalidArgument);
    }
}
