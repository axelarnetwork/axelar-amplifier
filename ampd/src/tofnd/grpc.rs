use std::fmt;
use std::fmt::Debug;
use std::time::Duration;

use async_trait::async_trait;
use error_stack::{report, ResultExt};
use mockall::automock;
use report::{ErrorExt, LoggableError};
use snarkvm::prelude::{FromBytes as _, ToBytes};
use tonic::transport::Channel;
use tracing::{error, instrument};
use valuable::Valuable;

use super::proto::keygen_response::KeygenResponse;
use super::proto::sign_response::SignResponse;
use super::proto::{multisig_client, Algorithm, KeygenRequest, SignRequest};
use super::Error;
use crate::types::debug::REDACTED_VALUE;
use crate::types::PublicKey;

type Result<T> = error_stack::Result<T, Error>;

#[automock]
#[async_trait]
pub trait Multisig {
    async fn keygen(&self, key_uid: &str, algorithm: Algorithm) -> Result<PublicKey>;
    async fn sign(
        &self,
        key_uid: &str,
        data: [u8; 32],
        pub_key: PublicKey,
        algorithm: Algorithm,
    ) -> Result<Vec<u8>>;
}

#[derive(Clone)]
pub struct MultisigClient {
    party_uid: String,
    client: multisig_client::MultisigClient<Channel>,
}

impl MultisigClient {
    pub async fn new(party_uid: String, url: &str, timeout: Duration) -> Result<Self> {
        let endpoint: tonic::transport::Endpoint = url.parse().map_err(ErrorExt::into_report)?;
        let conn = endpoint
            .timeout(timeout)
            .connect_timeout(timeout)
            .connect()
            .await
            .map_err(ErrorExt::into_report)?;

        Ok(Self {
            party_uid,
            client: multisig_client::MultisigClient::new(conn),
        })
    }
}

#[async_trait]
impl Multisig for MultisigClient {
    #[instrument]
    async fn keygen(&self, key_uid: &str, algorithm: Algorithm) -> Result<PublicKey> {
        let request = KeygenRequest {
            key_uid: key_uid.to_string(),
            party_uid: self.party_uid.to_string(),
            algorithm: algorithm.into(),
        };

        self.client
            .clone()
            .keygen(request)
            .await
            .map_err(ErrorExt::into_report)
            .and_then(|res| {
                let res = res.into_inner();

                res.clone()
                    .keygen_response
                    .ok_or(report!(Error::InvalidKeygenResponse))
                    .inspect_err(|err| {
                        error!(
                            err = LoggableError::from(err).as_value(),
                            res = ?res,
                            "invalid keygen response"
                        )
                    })
            })
            .and_then(|res| match &res {
                KeygenResponse::PubKey(pub_key) => match algorithm {
                    Algorithm::Ecdsa => PublicKey::new_secp256k1(pub_key),
                    Algorithm::Ed25519 => PublicKey::new_ed25519(pub_key),
                    Algorithm::AleoSchnorr => PublicKey::new_aleo_schnorr(pub_key),
                }
                .change_context(Error::InvalidKeygenResponse)
                .inspect_err(|err| {
                    error!(
                        err = LoggableError::from(err).as_value(),
                        res = ?res,
                        "invalid keygen response"
                    )
                }),
                KeygenResponse::Error(error) => Err(report!(Error::ExecutionFailed(error.clone()))),
            })
    }

    #[instrument]
    async fn sign(
        &self,
        key_uid: &str,
        data: [u8; 32],
        pub_key: PublicKey,
        algorithm: Algorithm,
    ) -> Result<Vec<u8>> {
        let request = SignRequest {
            key_uid: key_uid.to_string(),
            msg_to_sign: data.into(),
            party_uid: self.party_uid.to_string(),
            pub_key: pub_key.to_bytes(),
            algorithm: algorithm.into(),
        };

        self.client
            .clone()
            .sign(request)
            .await
            .map_err(ErrorExt::into_report)
            .and_then(|res| {
                let res = res.into_inner();

                res.clone()
                    .sign_response
                    .ok_or(report!(Error::InvalidSignResponse))
                    .inspect_err(|err| {
                        error!(
                            err = LoggableError::from(err).as_value(),
                            res = ?res,
                            "invalid sign response"
                        )
                    })
            })
            .and_then(|res| match &res {
                SignResponse::Signature(signature) => match algorithm {
                    Algorithm::Ecdsa => {
                        k256::ecdsa::Signature::from_der(signature).map(|sig| sig.to_vec())
                    }
                    Algorithm::Ed25519 => {
                        ed25519_dalek::Signature::from_slice(signature).map(|sig| sig.to_vec())
                    }
                    Algorithm::AleoSchnorr => {
                        let res = snarkvm::prelude::Signature::<snarkvm::prelude::TestnetV0>::from_bytes_le(signature)
                            .map(|sig| sig.to_bytes_le()).unwrap().unwrap();

                        Ok(res)
                    }
                }
                .change_context(Error::InvalidSignResponse)
                .inspect_err(|err| {
                    error!(
                        err = LoggableError::from(err).as_value(),
                        res = ?res,
                        "invalid sign response"
                    )
                }),
                SignResponse::Error(error) => Err(report!(Error::ExecutionFailed(error.clone()))),
            })
    }
}

impl Debug for MultisigClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MultisigClient")
            .field("party_uid", &self.party_uid)
            .field("client", &REDACTED_VALUE)
            .finish()
    }
}
