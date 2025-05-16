use ampd_proto::crypto_service_server::CryptoService;
use ampd_proto::{KeyRequest, KeyResponse, SignRequest, SignResponse};
use async_trait::async_trait;
use tonic::{Request, Response, Status};

pub struct Service {}

impl Service {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl CryptoService for Service {
    async fn sign(&self, _req: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("sign method is not implemented yet"))
    }

    async fn key(&self, _req: Request<KeyRequest>) -> Result<Response<KeyResponse>, Status> {
        Err(Status::unimplemented("key method is not implemented yet"))
    }
}
