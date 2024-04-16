use error_stack::Result;
use std::{io, net::SocketAddrV4};
use thiserror::Error;
use tracing::info;

use axum::{http::StatusCode, routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

pub struct Server {
    listener: tokio::net::TcpListener,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to start the health check server")]
    Start,
    #[error("health check server failed unexpectedly")]
    WhileRunning
}

impl Server {
    pub async fn new(bind_addr: SocketAddrV4) -> Result<Self, HealthCheckError> {
        Ok(Self {
            listener: tokio::net::TcpListener::bind(bind_addr)
                .await
                .map_err(HealthCheckError::from)?,
        })
    }

    pub async fn run(self, cancel: CancellationToken) -> Result<(), HealthCheckError> {
        let app = Router::new().route("/status", get(status));
        let bind_address = self.listener.local_addr().change_context(Error::Start)?;

        info!(address = bind_address.to_string(), "starting health check server");

        Ok(axum::serve(self.listener, app)
            .with_graceful_shutdown(async move { cancel.cancelled().await })
            .await
            .change_context(Error::WhileRunning)?)
    }
}

// basic handler that responds with a static string
async fn status() -> (StatusCode, Json<Status>) {
    (StatusCode::OK, Json(Status { ok: true }))
}

#[derive(Serialize, Deserialize)]
struct Status {
    ok: bool,
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::io;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::time::Duration;
    use tokio::test as async_test;

    impl Server {
        fn listening_addr(&self) -> io::Result<SocketAddr> {
            self.listener.local_addr()
        }
    }

    #[async_test]
    async fn server_lifecycle() {
        let server = Server::new(SocketAddrV4::from_str("127.0.0.1:0").unwrap())
            .await
            .unwrap();
        let listening_addr = server.listening_addr().unwrap();

        let cancel = CancellationToken::new();

        tokio::spawn(server.run(cancel.clone()));

        let url = format!("http://{}/status", listening_addr);

        tokio::time::sleep(Duration::from_millis(100)).await;

        let response = reqwest::get(&url).await.unwrap();
        assert_eq!(reqwest::StatusCode::OK, response.status());

        let status = response.json::<Status>().await.unwrap();
        assert!(status.ok);

        cancel.cancel();

        tokio::time::sleep(Duration::from_millis(100)).await;

        match reqwest::get(&url).await {
            Ok(_) => panic!("health check server should be closed by now"),
            Err(error) => assert!(error.is_connect()),
        };
    }
}
