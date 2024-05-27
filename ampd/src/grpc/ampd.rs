use std::pin::Pin;

use async_trait::async_trait;
use futures::Stream;
use tonic::{Request, Response, Status};

pub mod proto {
    tonic::include_proto!("ampd");
}

pub struct Ampd {}

impl Ampd {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl proto::ampd_server::Ampd for Ampd {
    type SubscribeStream =
        Pin<Box<dyn Stream<Item = Result<proto::SubscribeResponse, Status>> + Send + 'static>>;

    async fn subscribe(
        &self,
        _req: Request<proto::SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        todo!()
    }

    async fn broadcast(
        &self,
        _req: Request<proto::BroadcastRequest>,
    ) -> Result<Response<proto::BroadcastResponse>, Status> {
        todo!()
    }
}
