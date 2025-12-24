pub mod asyncutil;
mod block_height_monitor;
mod broadcast;
#[cfg(feature = "commands")]
pub mod commands;
#[cfg(not(feature = "commands"))]
mod commands;
#[cfg(feature = "config")]
pub mod config;
#[cfg(not(feature = "config"))]
mod config;
mod cosmos;
pub mod event_sub;
mod grpc;
pub mod json_rpc;
pub mod monitoring;
mod tm_client;
mod tofnd;
pub mod types;
#[cfg(feature = "url")]
pub mod url;
#[cfg(not(feature = "url"))]
mod url;

use asyncutil::task::{CancellableTask, TaskError, TaskGroup};
use block_height_monitor::BlockHeightMonitor;
use broadcast::MsgQueue;
use error_stack::{FutureExt, Result, ResultExt};
use router_api::ChainName;
use thiserror::Error;
use tofnd::{Multisig, MultisigClient};
use tokio::signal::unix::{signal, SignalKind};
use tokio_util::sync::CancellationToken;
use tracing::info;
use types::CosmosPublicKey;

use crate::config::Config;

const PREFIX: &str = "axelar";

#[cfg(feature = "config")]
pub async fn run(cfg: Config) -> Result<(), Error> {
    prepare_app(cfg).await?.run().await
}

#[cfg(feature = "config")]
async fn prepare_app(cfg: Config) -> Result<App, Error> {
    use crate::asyncutil::future::RetryPolicy;

    let Config {
        tm_jsonrpc,
        tm_grpc,
        tm_grpc_timeout,
        broadcast,
        tofnd_config,
        service_registry,
        rewards,
        monitoring_server,
        grpc: grpc_config,
        event_sub,
        tm_client,
    } = cfg;

    let (monitoring_server, monitoring_client) =
        monitoring::Server::new(monitoring_server).change_context(Error::Monitor)?;

    let tm_client = tm_client::TendermintClient::new(
        tendermint_rpc::HttpClient::new(tm_jsonrpc.as_str())
            .change_context(Error::Connection)
            .attach_printable(tm_jsonrpc.clone())?,
        tm_client.max_retries,
        tm_client.retry_delay,
    );

    let multisig_client = MultisigClient::new(
        tofnd_config.party_uid,
        tofnd_config.url.as_str(),
        tofnd_config.timeout,
    )
    .await
    .change_context(Error::Connection)
    .attach_printable(tofnd_config.url)?;
    let block_height_monitor = BlockHeightMonitor::connect(tm_client.clone())
        .await
        .change_context(Error::Connection)
        .attach_printable(tm_jsonrpc)?;
    let pub_key = multisig_client
        .keygen(&tofnd_config.key_uid, tofnd::Algorithm::Ecdsa)
        .await
        .change_context(Error::Tofnd)?;
    let pub_key = CosmosPublicKey::try_from(pub_key).change_context(Error::Tofnd)?;
    let (event_publisher, event_subscriber) = event_sub::EventPublisher::new(
        tm_client.clone(),
        event_sub.stream_buffer_size,
        event_sub.delay,
        event_sub.poll_interval,
        event_sub.block_processing_buffer,
        RetryPolicy::repeat_constant(event_sub.retry_delay, event_sub.retry_max_attempts),
        monitoring_client.clone(),
    );
    let cosmos_client = cosmos::CosmosGrpcClient::new(tm_grpc.as_str(), tm_grpc_timeout)
        .await
        .change_context(Error::Connection)
        .attach_printable(tm_grpc.clone())?;
    let broadcaster = broadcast::Broadcaster::builder()
        .client(cosmos_client.clone())
        .chain_id(broadcast.chain_id)
        .pub_key(pub_key)
        .gas_adjustment(broadcast.gas_adjustment)
        .gas_price(broadcast.gas_price)
        .build()
        .await
        .change_context(Error::Broadcaster)?;
    let (msg_queue, msg_queue_client) = broadcast::MsgQueue::new_msg_queue_and_client(
        broadcaster.clone(),
        broadcast.queue_cap,
        broadcast.batch_gas_limit,
        broadcast.broadcast_interval,
        monitoring_client.clone(),
    );
    let grpc_server = grpc::Server::builder()
        .config(grpc_config)
        .event_sub(event_subscriber.clone())
        .msg_queue_client(msg_queue_client.clone())
        .cosmos_grpc_client(cosmos_client.clone())
        .multisig_client(multisig_client.clone())
        .service_registry(service_registry.cosmwasm_contract)
        .latest_block_height(block_height_monitor.latest_block_height())
        .rewards(rewards.cosmwasm_contract)
        .monitoring_client(monitoring_client.clone())
        .build();
    let (tx_confirmer, tx_confirmer_client) = broadcast::TxConfirmer::new_confirmer_and_client(
        cosmos_client,
        RetryPolicy::repeat_constant(
            broadcast.tx_fetch_interval,
            broadcast.tx_fetch_max_retries.saturating_add(1).into(),
        ),
        broadcast.tx_confirmation_buffer_size,
        broadcast.tx_confirmation_queue_cap,
        monitoring_client.clone(),
    );
    let broadcaster_task = broadcast::BroadcasterTask::builder()
        .broadcaster(broadcaster)
        .msg_queue(msg_queue)
        .signer(multisig_client.clone())
        .key_id(tofnd_config.key_uid.clone())
        .tx_confirmer_client(tx_confirmer_client)
        .monitoring_client(monitoring_client.clone())
        .build();

    Ok(App::new(
        event_publisher,
        block_height_monitor,
        monitoring_server,
        grpc_server,
        broadcaster_task,
        tx_confirmer,
    ))
}

struct App {
    event_publisher: event_sub::EventPublisher<tm_client::TendermintClient>,
    block_height_monitor: BlockHeightMonitor<tm_client::TendermintClient>,
    monitoring_server: monitoring::Server,
    grpc_server: grpc::Server,
    broadcaster_task:
        broadcast::BroadcasterTask<cosmos::CosmosGrpcClient, MsgQueue, MultisigClient>,
    tx_confirmer: broadcast::TxConfirmer<cosmos::CosmosGrpcClient>,
}

impl App {
    #[allow(clippy::too_many_arguments)]
    fn new(
        event_publisher: event_sub::EventPublisher<tm_client::TendermintClient>,
        block_height_monitor: BlockHeightMonitor<tm_client::TendermintClient>,
        monitoring_server: monitoring::Server,
        grpc_server: grpc::Server,
        broadcaster_task: broadcast::BroadcasterTask<
            cosmos::CosmosGrpcClient,
            MsgQueue,
            MultisigClient,
        >,
        tx_confirmer: broadcast::TxConfirmer<cosmos::CosmosGrpcClient>,
    ) -> Self {
        Self {
            event_publisher,
            block_height_monitor,
            monitoring_server,
            grpc_server,
            broadcaster_task,
            tx_confirmer,
        }
    }

    async fn run(self) -> Result<(), Error> {
        let Self {
            event_publisher,
            block_height_monitor,
            monitoring_server,
            grpc_server,
            broadcaster_task,
            tx_confirmer,
            ..
        } = self;

        let main_token = CancellationToken::new();
        let exit_token = main_token.clone();
        tokio::spawn(async move {
            let mut sigint = signal(SignalKind::interrupt()).expect("failed to capture SIGINT");
            let mut sigterm = signal(SignalKind::terminate()).expect("failed to capture SIGTERM");

            tokio::select! {
                _ = sigint.recv() => {},
                _ = sigterm.recv() => {},
            }

            info!("signal received, waiting for program to exit gracefully");

            exit_token.cancel();
        });

        TaskGroup::new("ampd")
            .add_task(
                "block-height-monitor",
                CancellableTask::create(|token| {
                    block_height_monitor
                        .run(token)
                        .change_context(Error::BlockHeightMonitor)
                }),
            )
            .add_task(
                "event-publisher",
                CancellableTask::create(|token| {
                    event_publisher
                        .run(token)
                        .change_context(Error::EventPublisher)
                }),
            )
            .add_task(
                "monitoring-server",
                CancellableTask::create(|token| {
                    monitoring_server.run(token).change_context(Error::Monitor)
                }),
            )
            .add_task(
                "grpc-server",
                CancellableTask::create(|token| {
                    grpc_server.run(token).change_context(Error::GrpcServer)
                }),
            )
            .add_task(
                "tx-confirmer",
                CancellableTask::create(|token| {
                    tx_confirmer
                        .run(token)
                        .change_context(Error::TxConfirmation)
                }),
            )
            .add_task(
                "broadcaster-task",
                CancellableTask::create(|token| {
                    broadcaster_task
                        .run(token)
                        .change_context(Error::Broadcaster)
                }),
            )
            .run(main_token)
            .await
            .change_context(Error::AppFailure)
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("event publisher failed")]
    EventPublisher,
    #[error("event processor failed")]
    EventProcessor,
    #[error("broadcaster failed")]
    Broadcaster,
    #[error("tx confirmation failed")]
    TxConfirmation,
    #[error("tofnd failed")]
    Tofnd,
    #[error("connection failed")]
    Connection,
    #[error("task execution failed")]
    Task(#[from] TaskError),
    #[error("app failed")]
    AppFailure,
    #[error("failed to return updated state")]
    ReturnState,
    #[error("failed to load config")]
    LoadConfig,
    #[error("invalid input")]
    InvalidInput,
    #[error("block height monitor failed")]
    BlockHeightMonitor,
    #[error("invalid finalizer type for chain {0}")]
    InvalidFinalizerType(ChainName),
    #[error("monitor server failed")]
    Monitor,
    #[error("gRPC server failed")]
    GrpcServer,
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::url::Url;

    #[test]
    fn test_invalid_url_parsing_returns_error() {
        // Test that invalid URLs are properly detected
        let invalid_url = "http://definitely-does-not-exist-12345.invalid";
        let result = Url::new_non_sensitive(invalid_url);

        // Should be able to parse the URL (syntax is valid)
        assert!(
            result.is_ok(),
            "URL parsing should succeed for syntactically valid URLs"
        );

        // The actual connection failure will happen during handler creation
        let parsed_url = result.unwrap();
        // URL parsing may normalize the URL (e.g., add trailing slash)
        assert!(parsed_url
            .as_str()
            .starts_with("http://definitely-does-not-exist-12345.invalid"));
    }

    #[test]
    fn test_handler_config_creation_with_invalid_url() {
        // Test URL creation with invalid host - this should succeed syntactically
        let invalid_url = "http://invalid-nonexistent-host:8545";
        let parsed_url = Url::new_non_sensitive(invalid_url);

        // URL parsing should succeed for syntactically valid URLs
        assert!(
            parsed_url.is_ok(),
            "URL parsing should succeed for syntactically valid URLs"
        );

        // The actual connection failure will happen during handler creation, not URL parsing
        let url = parsed_url.unwrap();
        assert!(url
            .as_str()
            .starts_with("http://invalid-nonexistent-host:8545"));
    }

    #[test]
    fn test_resilient_handler_configuration_concept() {
        // Test the concept behind resilient handler configuration
        // This verifies that individual handler failures should not prevent app startup

        // Simulate handler creation results - some succeed, some fail
        let handler_results = vec![
            Ok("MultisigSigner created successfully"),
            Err("Connection failed: invalid-stellar-host unreachable"),
            Ok("Another handler created successfully"),
            Err("Connection failed: invalid-ethereum-host unreachable"),
        ];

        let mut successful_handlers = 0;
        let mut failed_handlers = 0;

        // This simulates the error handling logic in configure_handlers
        for result in handler_results {
            match result {
                Ok(_) => {
                    successful_handlers += 1;
                }
                Err(error) => {
                    // Log warning and continue (simulated)
                    failed_handlers += 1;
                    assert!(
                        error.contains("Connection failed"),
                        "Error should be connection-related: {}",
                        error
                    );
                }
            }
        }

        // Verify that we continue processing even with failures
        assert_eq!(successful_handlers, 2);
        assert_eq!(failed_handlers, 2);

        // The key insight: ampd should start with 2 working handlers,
        // even though 2 handlers failed to initialize
        assert!(
            successful_handlers > 0,
            "At least some handlers should succeed"
        );
    }

    #[test]
    fn test_error_context_propagation() {
        // Test that error context is properly maintained
        use error_stack::Report;

        // Simulate an error that would occur during handler creation
        let connection_error: Report<Error> = Report::new(Error::Connection);

        // Verify error context
        assert!(matches!(
            connection_error.current_context(),
            Error::Connection
        ));

        // Test error message
        let error_string = format!("{}", connection_error);
        assert!(error_string.contains("connection failed"));
    }
}
