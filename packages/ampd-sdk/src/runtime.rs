use std::fmt::Debug;
use std::time::Duration;

use ampd::monitoring;
use ampd::url::Url;
use cosmrs::AccountId;
use error_stack::{Context, Report, Result, ResultExt};
use events::Event;
use tokio::signal::unix::{signal, SignalKind};
use tokio_util::sync::CancellationToken;
use tracing::{info, Level};

use crate::config::Config;
use crate::event::event_handler::{EventHandler, HandlerTask};
use crate::future::RetryPolicy;
use crate::grpc::client::types::ContractsAddresses;
use crate::grpc::client::{EventHandlerClient, GrpcClient, HandlerTaskClient};
use crate::grpc::connection_pool::ConnectionPool;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to start handler runtime")]
    RuntimeStart,
    #[error("failed to run handler")]
    HandlerRun,
}

pub struct HandlerRuntime {
    pub monitoring_client: monitoring::Client,
    pub grpc_client: GrpcClient,
    pub contracts: ContractsAddresses,
    pub verifier: AccountId,
}

impl HandlerRuntime {
    pub async fn start(config: Config, token: CancellationToken) -> Result<Self, Error> {
        init_tracing(Level::INFO);

        info!("Starting runtime");

        start_shutdown_signal_monitor(token.clone());
        let monitoring_client = start_monitoring_server(config.monitoring_server, token.clone());
        let mut grpc_client = start_connection_pool(config.ampd_url, token.clone());
        let contracts = grpc_client
            .contracts(config.chain_name.clone())
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

    pub async fn run_handler<H, C>(
        mut self,
        handler: H,
        config: Config,
        token: CancellationToken,
    ) -> Result<(), Error>
    where
        H: EventHandler + Debug,
        H::Event: TryFrom<Event, Error = Report<C>>,
        C: Context,
        H::Event: Debug + Clone,
    {
        let task = HandlerTask::builder()
            .handler(handler)
            .config(config.event_handler)
            .handler_retry_policy(RetryPolicy::RepeatConstant {
                // TODO: make this configurable
                sleep: Duration::from_secs(1),
                max_attempts: 3,
            })
            .build();

        task.run(&mut self.grpc_client, token)
            .await
            .change_context(Error::HandlerRun)?;

        Ok(())
    }
}

fn init_tracing(max_level: Level) {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(max_level)
            .finish(),
    )
    .expect("failed to set global default tracing subscriber");
}

fn start_connection_pool(ampd_url: Url, token: CancellationToken) -> GrpcClient {
    let (pool, handle) = ConnectionPool::new(ampd_url);

    tokio::spawn(async move {
        let _ = pool.run(token).await;
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
        let _ = server.run(token).await;
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
