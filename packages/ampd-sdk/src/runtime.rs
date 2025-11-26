use std::fmt::Debug;

use ampd::monitoring;
use ampd::url::Url;
use cosmrs::AccountId;
use error_stack::{Report, Result, ResultExt};
use events::Event;
use thiserror::Error;
use tokio::signal::unix::{signal, SignalKind};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use valuable::Valuable;

use crate::config::Config;
use crate::event::event_handler::{EventHandler, HandlerTask};
use crate::grpc::client::types::ContractsAddresses;
use crate::grpc::client::{EventHandlerClient, GrpcClient, HandlerTaskClient};
use crate::grpc::connection_pool::ConnectionPool;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to start handler runtime")]
    RuntimeStart,
    #[error("failed to run handler")]
    HandlerRun,
}

#[non_exhaustive] // prevents creating the runtime using struct expression from outside this crate
#[derive(Debug, Clone)]
pub struct HandlerRuntime {
    pub monitoring_client: monitoring::Client,
    pub grpc_client: GrpcClient,
    pub contracts: ContractsAddresses,
    pub verifier: AccountId,
}

impl HandlerRuntime {
    /// Starts and creates the handler runtime. This will do the following:
    /// - Start the shutdown signal monitor
    /// - Start the monitoring server
    /// - Start the connection pool
    /// - Fetch the contracts addresses and verifier address from the ampd server
    /// - Return the handler runtime
    ///
    /// # Examples
    /// ```rust, no_run
    /// use ampd_sdk::config;
    /// use ampd_sdk::runtime::HandlerRuntime;
    /// # use std::error::Error;
    /// use tokio_util::sync::CancellationToken;
    ///
    /// # #[tokio::main]
    /// async fn main() {
    ///     let config = config::Config::from_default_sources().unwrap();
    ///     let token = CancellationToken::new();
    ///
    ///     let runtime = HandlerRuntime::start(&config, token).await.unwrap();
    /// }
    /// ```
    pub async fn start(config: &Config, token: CancellationToken) -> Result<Self, Error> {
        info!("Starting handler runtime");

        start_shutdown_signal_monitor(token.clone());
        let monitoring_client =
            start_monitoring_server(config.monitoring_server.to_owned(), token.clone());
        let mut grpc_client = start_connection_pool(config.ampd_url.to_owned(), token.clone());
        let contracts = grpc_client
            .contracts(config.chain_name.to_owned())
            .await
            .change_context(Error::RuntimeStart)?;
        let verifier_address = grpc_client
            .address()
            .await
            .change_context(Error::RuntimeStart)?;

        Ok(Self {
            monitoring_client,
            grpc_client,
            contracts,
            verifier: verifier_address,
        })
    }

    /// Use the started runtime to create and run the handler task
    pub async fn run_handler<H>(
        &self,
        handler: H,
        config: Config,
        token: CancellationToken,
    ) -> Result<(), Error>
    where
        H: EventHandler + Debug,
        H::Event: TryFrom<Event, Error = Report<events::Error>>,
        H::Event: Debug + Clone,
    {
        let task = HandlerTask::builder()
            .handler(handler)
            .config(config.event_handler)
            .build();

        // Clone the gRPC client so multiple handlers can share the same runtime
        let mut grpc_client = self.grpc_client.clone();
        task.run(&mut grpc_client, token)
            .await
            .change_context(Error::HandlerRun)?;

        Ok(())
    }
}

fn start_connection_pool(ampd_url: Url, token: CancellationToken) -> GrpcClient {
    let (pool, handle) = ConnectionPool::new(ampd_url);

    tokio::spawn(async move {
        let _ = pool.run(token).await.inspect_err(|err| {
            error!(
                err = report::LoggableError::from(err).as_value(),
                "connection pool failed"
            )
        });
    });

    GrpcClient::new(handle)
}

fn start_monitoring_server(
    config: monitoring::Config,
    token: CancellationToken,
) -> monitoring::Client {
    let (server, client) =
        monitoring::Server::new(config).expect("failed to create monitoring server");

    tokio::spawn(async move {
        let _ = server.run(token).await.inspect_err(|err| {
            error!(
                err = report::LoggableError::from(err).as_value(),
                "monitoring server failed"
            )
        });
    });

    client
}

fn start_shutdown_signal_monitor(token: CancellationToken) {
    tokio::spawn(async move {
        let mut sigint = signal(SignalKind::interrupt()).expect("failed to capture SIGINT");
        let mut sigterm = signal(SignalKind::terminate()).expect("failed to capture SIGTERM");

        tokio::select! {
            _ = sigint.recv() => {},
            _ = sigterm.recv() => {},
        }

        info!("signal received, waiting for program to exit gracefully");

        token.cancel();
    });
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::time::Duration;

    use ampd_proto::blockchain_service_server::BlockchainServiceServer;
    use ampd_proto::crypto_service_server::CryptoServiceServer;
    use ampd_proto::{AddressResponse, ContractsResponse, SubscribeResponse};
    use axelar_wasm_std::nonempty_str;
    use events::AbciEventTypeFilter;
    use tokio_util::sync::CancellationToken;
    use tonic::{transport, Response};
    use tracing_test::traced_test;

    use super::*;
    use crate::config;
    use crate::event::event_handler::test_utils::MockEventHandler;
    use crate::event::event_handler::SubscriptionParams;
    use crate::grpc::client::test_utils::{MockBlockchainService, MockCryptoService};
    use crate::grpc::client::GrpcClient;

    async fn test_setup() -> config::Config {
        let chain_name = "some-chain";

        let mut mock_blockchain = MockBlockchainService::new();
        let mock_crypto = MockCryptoService::new();

        mock_blockchain.expect_address().return_once(|_request| {
            Ok(Response::new(AddressResponse {
                address: "axelar1hg8mfs0pauxmxt5n76ndnlrye235zgz877l727".to_string(),
            }))
        });

        mock_blockchain.expect_contracts().return_once(|_request| {
            Ok(Response::new(ContractsResponse {
                voting_verifier:
                    "axelar1252ahkw208d08ls64atp2pql4cnl9naxy7ahhq3lrthvq3spseys26l8xj".to_string(),
                multisig_prover:
                    "axelar1p22kz5jr7a9ruu8ypg40smual0uagl64dwvz5xt042vu8fa7l7dsl3wx8q".to_string(),
                service_registry:
                    "axelar1c9fkszt5lq34vvvlat3fxj6yv7ejtqapz04e97vtc9m5z9cwnamq8zjlhz".to_string(),
                rewards: "axelar1vaj9sfzc3z0gpel90wu4ljutncutv0wuhvvwfsh30rqxq422z89qnd989l"
                    .to_string(),
                multisig: "axelar19jxy26z0qnnspa45y5nru0l5rmy9d637z5km2ndjxthfxf5qaswst9290r"
                    .to_string(),
                event_verifier: None,
            }))
        });

        mock_blockchain
            .expect_subscribe()
            .return_once(move |_request| {
                let subscribe_responses: Vec<SubscribeResponse> = vec![
                    Event::BlockBegin(1u64.try_into().unwrap()),
                    Event::BlockEnd(1u64.try_into().unwrap()),
                ]
                .into_iter()
                .map(|event| SubscribeResponse {
                    event: Some(event.into()),
                })
                .collect();

                Ok(Response::new(Box::pin(tokio_stream::iter(
                    subscribe_responses.into_iter().map(Ok),
                ))))
            });

        let server = transport::Server::builder()
            .add_service(BlockchainServiceServer::new(mock_blockchain))
            .add_service(CryptoServiceServer::new(mock_crypto));

        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let bound_server =
            server.serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener));

        tokio::spawn(bound_server);

        temp_env::with_vars(
            vec![
                (
                    format!("{}_AMPD_URL", config::DEFAULT_CONFIG_PREFIX),
                    Some(format!("http://{}", server_addr)),
                ),
                (
                    format!("{}_CHAIN_NAME", config::DEFAULT_CONFIG_PREFIX),
                    Some(chain_name.to_string()),
                ),
            ],
            || config::Config::from_default_sources().unwrap(),
        )
    }

    fn handler_setup() -> MockEventHandler {
        let mut handler = MockEventHandler::new();
        handler.expect_subscription_params().returning(|| {
            SubscriptionParams::new(
                vec![AbciEventTypeFilter {
                    event_type: nonempty_str!("mock-event"),
                    contract: AccountId::from_str(
                        "axelar1252ahkw208d08ls64atp2pql4cnl9naxy7ahhq3lrthvq3spseys26l8xj",
                    )
                    .unwrap(),
                    attributes: HashMap::new(),
                }],
                true,
            )
        });

        handler
            .expect_handle::<GrpcClient>()
            .times(..)
            .returning(|_, _| Ok(vec![]));

        handler
            .expect_fmt()
            .returning(|f| write!(f, "MockEventHandler"));

        handler
    }

    #[tokio::test]
    async fn runtime_should_start_successfully() {
        let config = test_setup().await;
        let token = CancellationToken::new();

        let result = HandlerRuntime::start(&config, token).await;
        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
    }

    #[tokio::test]
    #[traced_test]
    async fn runtime_should_return_error() {
        let config = test_setup().await;
        let token = CancellationToken::new();
        token.cancel(); // force runtime to return error

        let result = HandlerRuntime::start(&config, token).await;
        assert!(result.is_err(), "unexpected Ok result");
        assert!(logs_contain("connection pool shutting down"));
    }

    #[tokio::test]
    #[traced_test]
    async fn runtime_should_shutdown_gracefully() {
        let config = test_setup().await;
        let token = CancellationToken::new();

        let result = HandlerRuntime::start(&config, token.clone()).await;
        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());

        assert!(!logs_contain("connection pool shutting down"));
        token.cancel();
        tokio::time::sleep(Duration::from_millis(100)).await; // wait for runtime to shutdown
        assert!(logs_contain("connection pool shutting down"));
    }

    #[tokio::test]
    async fn handler_should_run_successfully() {
        let config = test_setup().await;
        let token = CancellationToken::new();

        let runtime = HandlerRuntime::start(&config, token.clone()).await.unwrap();
        let handler = handler_setup();

        let result = runtime.run_handler(handler, config, token).await;
        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
    }
}
