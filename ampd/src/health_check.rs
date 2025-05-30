use std::net::SocketAddrV4;
use std::sync::Arc;

// use axum::extract::Extension;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use error_stack::{Result, ResultExt};
use prometheus_client::encoding::EncodeLabelSet;
// use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use tracing::info;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to start the health check server")]
    Start,
    #[error("health check server failed unexpectedly")]
    WhileRunning,
}

pub struct Server {
    bind_address: SocketAddrV4,
    registry: Arc<Registry>,
    test_counter: Arc<Family<TestLabel, Counter>>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct TestLabel {
    path: String,
}

impl Server {
    pub fn new(bind_address: SocketAddrV4) -> Self {
        let mut registry = Registry::default();

        let test_counter = Family::<TestLabel, Counter>::default();

        registry.register(
            "current_time",
            "Current date and time EST",
            test_counter.clone(),
        );

        Self {
            bind_address,
            registry: Arc::new(registry),
            test_counter: Arc::new(test_counter),
        }
    }

    pub async fn run(self, cancel: CancellationToken) -> Result<(), Error> {
        let listener = tokio::net::TcpListener::bind(self.bind_address)
            .await
            .change_context(Error::Start)?;

        info!(
            address = self.bind_address.to_string(),
            "starting health check server"
        );

        let app = Router::new().route("/status", get(status));
        // .route("/bump", get(bump))
        // .route("/metrics", get(metrics))
        // .layer(Extension(self.registry.clone()))
        // .layer(Extension(self.test_counter.clone()));

        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                cancel.cancelled().await;
                info!("exiting health check server")
            })
            .await
            .change_context(Error::WhileRunning)
    }
}

// basic handler that responds with a static string
async fn status() -> (StatusCode, Json<Status>) {
    (StatusCode::OK, Json(Status { ok: true }))
}

// async fn bump(
//     Extension(test_counter): Extension<Arc<Family<TestLabel, Counter>>>,
// ) {
//     let label = TestLabel {
//         path: "/bump".to_string(),
//     };

//     test_counter
//         .get_or_create(&label)
//         .inc();
// }

// async fn metrics(
//     Extension(registry): Extension<Arc<Registry>>,
// ) -> String {
//     let mut buffer = String::new();
//     encode(&mut buffer, &registry).unwrap();
//     buffer
// }

#[derive(Serialize, Deserialize)]
struct Status {
    ok: bool,
}

#[cfg(test)]
mod tests {

    use std::net::{SocketAddr, TcpListener};
    use std::time::Duration;

    use tokio::test as async_test;

    use super::*;

    #[async_test]
    async fn server_lifecycle() {
        let bind_address = test_bind_addr();

        let server = Server::new(bind_address);

        let cancel = CancellationToken::new();

        tokio::spawn(server.run(cancel.clone()));

        let url = format!("http://{}/status", bind_address);

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

    fn test_bind_addr() -> SocketAddrV4 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();

        match listener.local_addr().unwrap() {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => panic!("unexpected address"),
        }
    }
}
