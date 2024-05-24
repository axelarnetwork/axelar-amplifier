use tonic::transport::{server::Router, Server};

use crate::{event_sub::EventSubscriber, queue::queued_broadcaster::QueuedBroadcasterClient};

mod ampd;

#[allow(dead_code)]
pub fn new_server(
    event_subscriber: EventSubscriber,
    broadcaster: QueuedBroadcasterClient,
) -> Router {
    Server::builder().add_service(ampd::proto::ampd_server::AmpdServer::new(
        ampd::Server::new(event_subscriber, broadcaster),
    ))
}
