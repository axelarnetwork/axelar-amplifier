use tonic::transport::server::Router;
use tonic::transport::Server;

use super::proto;
use crate::event_sub::EventSub;
use crate::queue::queued_broadcaster::BroadcasterClient;
use crate::tofnd::grpc::Multisig;

mod ampd;
mod crypto;

#[allow(dead_code)]
pub fn new<S, B, M>(event_subscriber: S, broadcaster: B, multisig_client: M) -> Router
where
    S: EventSub + Send + Sync + 'static,
    B: BroadcasterClient + Send + Sync + 'static,
    M: Multisig + Send + Sync + 'static,
{
    Server::builder()
        .add_service(proto::ampd_server::AmpdServer::new(ampd::Server::new(
            event_subscriber,
            broadcaster,
        )))
        .add_service(proto::crypto_server::CryptoServer::new(
            crypto::Server::new(multisig_client),
        ))
}
