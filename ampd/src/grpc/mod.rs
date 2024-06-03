use tonic::transport::{server::Router, Server};

use crate::event_sub::EventSubscriber;
use crate::queue::queued_broadcaster::QueuedBroadcasterClient;
use crate::tofnd::grpc::MultisigClient;

mod proto {
    tonic::include_proto!("ampd");
}
mod ampd;
mod crypto;

#[allow(dead_code)]
pub fn new_server(
    event_subscriber: EventSubscriber,
    broadcaster: QueuedBroadcasterClient,
    multisig_client: MultisigClient,
) -> Router {
    Server::builder()
        .add_service(proto::ampd_server::AmpdServer::new(ampd::Server::new(
            event_subscriber,
            broadcaster,
        )))
        .add_service(proto::crypto_server::CryptoServer::new(
            crypto::Server::new(multisig_client),
        ))
}
