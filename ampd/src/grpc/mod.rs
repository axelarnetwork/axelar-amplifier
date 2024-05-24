use tonic::transport::{server::Router, Server};

mod ampd;

#[allow(dead_code)]
pub fn new_server() -> Router {
    Server::builder().add_service(ampd::proto::ampd_server::AmpdServer::new(ampd::Ampd::new()))
}
