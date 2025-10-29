use std::fmt::Debug;

use ampd::monitoring;
use ampd::url::Url;
use cosmrs::AccountId;
use error_stack::{Context, Report, Result, ResultExt};
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
#[derive(Debug)]
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
            .build();

        task.run(&mut self.grpc_client, token)
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
