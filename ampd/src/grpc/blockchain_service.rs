use std::pin::Pin;
use std::time::Duration;

use ampd_proto::blockchain_service_server::BlockchainService;
use ampd_proto::{
    AddressRequest, AddressResponse, BroadcastRequest, BroadcastResponse, ContractsRequest,
    ContractsResponse, QueryRequest, QueryResponse, SubscribeRequest, SubscribeResponse,
};
use async_trait::async_trait;
use cosmrs::tendermint::block;
use futures::{Stream, StreamExt};
use tokio::sync::mpsc;
use tokio::time;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

pub struct Service {}

impl Service {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl BlockchainService for Service {
    type SubscribeStream =
        Pin<Box<dyn Stream<Item = Result<SubscribeResponse, Status>> + Send + 'static>>;

    async fn subscribe(
        &self,
        _req: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        // TODO: replace the dummy implementation
        let (tx, rx) = mpsc::channel(10000);

        tokio::spawn(async move {
            let mut height: block::Height = 10u32.into();
            let duration = Duration::from_secs(3);
            let mut interval = time::interval(duration);

            loop {
                let _ = tx
                    .send(ampd_proto::subscribe_response::Event::BlockBegin(
                        ampd_proto::EventBlockBegin {
                            height: height.value(),
                        },
                    ))
                    .await;
                interval.tick().await;

                let _ = tx
                    .send(ampd_proto::subscribe_response::Event::BlockEnd(
                        ampd_proto::EventBlockEnd {
                            height: height.value(),
                        },
                    ))
                    .await;
                interval.tick().await;

                height = height.increment();
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx).map(
            |event| Ok(SubscribeResponse { event: Some(event) }),
        ))))
    }

    async fn broadcast(
        &self,
        _req: Request<BroadcastRequest>,
    ) -> Result<Response<BroadcastResponse>, Status> {
        todo!("implement broadcast method")
    }

    async fn query(&self, _req: Request<QueryRequest>) -> Result<Response<QueryResponse>, Status> {
        todo!("implement query method")
    }

    async fn address(
        &self,
        _req: Request<AddressRequest>,
    ) -> Result<Response<AddressResponse>, Status> {
        todo!("implement address method")
    }

    async fn contracts(
        &self,
        _req: Request<ContractsRequest>,
    ) -> Result<Response<ContractsResponse>, Status> {
        todo!("implement contracts method")
    }
}
