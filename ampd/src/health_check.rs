use error_stack::{Result, ResultExt};
use std::{fmt::Display, net::SocketAddrV4};
use thiserror::Error;
use tracing::info;

use axum::{http::StatusCode, routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

#[cfg(test)]
use std::net::SocketAddr;

pub struct Server {
    listener: tokio::net::TcpListener,
}

#[derive(Error, Debug)]
pub struct HealthCheckError {
    msg: String,
}

impl HealthCheckError {
    pub fn new(msg: String) -> Self {
        Self { msg }
    }
}

impl Display for HealthCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl Server {
    pub async fn new(bind_addr: SocketAddrV4) -> Result<Self, HealthCheckError> {
        Ok(Self {
            listener: tokio::net::TcpListener::bind(bind_addr)
                .await
                .change_context(HealthCheckError::new(format!(
                    "Failed binding to addr: {}",
                    bind_addr
                )))?,
        })
    }

    #[cfg(test)]
    pub fn listening_addr(&self) -> Result<SocketAddr, HealthCheckError> {
        Ok(self
            .listener
            .local_addr()
            .map_err(|e| HealthCheckError::new(e.to_string()))?)
    }
    pub async fn run(self, cancel: CancellationToken) -> Result<(), HealthCheckError> {
        let app = Router::new().route("/status", get(status));
        let bind_address = self
            .listener
            .local_addr()
            .change_context(HealthCheckError::new(
                "Failed getting local address".to_string(),
            ))?;
        info!("Starting health check server at: {}", bind_address);
        axum::serve(self.listener, app)
            .with_graceful_shutdown(async move { cancel.cancelled().await })
            .await
            .change_context(HealthCheckError::new("Failed executing server".to_string()))
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
    use std::str::FromStr;
    use std::time::Duration;
    use tokio::test as async_test;

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
