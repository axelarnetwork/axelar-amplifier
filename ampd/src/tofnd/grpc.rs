use async_trait::async_trait;
use error_stack::{IntoReport, Result};
use mockall::automock;
use tonic::transport::Channel;
use tonic::{Response, Status};

use super::proto::{
    key_presence_response::Response as KeyPresenceEnum, keygen_response::KeygenResponse,
    multisig_client, sign_response::SignResponse, KeyPresenceRequest, KeygenRequest, SignRequest,
};

#[automock]
#[async_trait]
pub trait MultisigClient {
    async fn keygen(&mut self, request: KeygenRequest) -> Result<KeygenResponse, Status>;
    async fn sign(&mut self, request: SignRequest) -> Result<SignResponse, Status>;
    async fn key_presence(
        &mut self,
        request: KeyPresenceRequest,
    ) -> Result<KeyPresenceEnum, Status>;
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

    async fn key_presence(
        &mut self,
        request: KeyPresenceRequest,
    ) -> Result<KeyPresenceEnum, Status> {
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
