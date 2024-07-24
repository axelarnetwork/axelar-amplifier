use std::time::Duration;

use asyncutil::task::{CancellableTask, TaskError, TaskGroup};
use block_height_monitor::BlockHeightMonitor;
use broadcaster::Broadcaster;
use cosmrs::proto::cosmos::auth::v1beta1::query_client::QueryClient as AuthQueryClient;
use cosmrs::proto::cosmos::bank::v1beta1::query_client::QueryClient as BankQueryClient;
use cosmrs::proto::cosmos::tx::v1beta1::service_client::ServiceClient;
use error_stack::{FutureExt, Result, ResultExt};
use event_processor::EventHandler;
use event_sub::EventSub;
use evm::finalizer::{pick, Finalization};
use evm::json_rpc::EthereumClient;
use queue::queued_broadcaster::QueuedBroadcaster;
use router_api::ChainName;
use thiserror::Error;
use tofnd::grpc::{Multisig, MultisigClient};
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::interval;
use tokio_util::sync::CancellationToken;
use tracing::info;
use types::TMAddress;

use crate::config::Config;

mod asyncutil;
mod block_height_monitor;
mod broadcaster;
pub mod commands;
pub mod config;
pub mod error;
mod event_processor;
mod event_sub;
mod evm;
mod grpc;
mod handlers;
mod health_check;
mod json_rpc;
mod queue;
mod sui;
mod tm_client;
mod tofnd;
mod types;
mod url;

pub use grpc::{client, proto};

const PREFIX: &str = "axelar";
const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(3);

pub async fn run(cfg: Config) -> Result<(), Error> {
    prepare_app(cfg).await?.run().await
}

async fn prepare_app(cfg: Config) -> Result<App<impl Broadcaster>, Error> {
    let Config {
        tm_jsonrpc,
        tm_grpc,
        broadcast,
        handlers,
        tofnd_config,
        event_processor,
        service_registry: _service_registry,
        health_check_bind_addr,
    } = cfg;

    let tm_client = tendermint_rpc::HttpClient::new(tm_jsonrpc.to_string().as_str())
        .change_context(Error::Connection)?;
    let service_client = ServiceClient::connect(tm_grpc.to_string())
        .await
        .change_context(Error::Connection)?;
    let auth_query_client = AuthQueryClient::connect(tm_grpc.to_string())
        .await
        .change_context(Error::Connection)?;
    let bank_query_client = BankQueryClient::connect(tm_grpc.to_string())
        .await
        .change_context(Error::Connection)?;
    let multisig_client = MultisigClient::new(tofnd_config.party_uid, tofnd_config.url)
        .await
        .change_context(Error::Connection)?;

    let block_height_monitor = BlockHeightMonitor::connect(tm_client.clone())
        .await
        .change_context(Error::Connection)?;

    let pub_key = multisig_client
        .keygen(&tofnd_config.key_uid, tofnd::Algorithm::Ecdsa)
        .await
        .change_context(Error::Tofnd)?;

    let broadcaster = broadcaster::UnvalidatedBasicBroadcaster::builder()
        .auth_query_client(auth_query_client)
        .bank_query_client(bank_query_client)
        .address_prefix(PREFIX.to_string())
        .client(service_client)
        .signer(multisig_client.clone())
        .pub_key((tofnd_config.key_uid, pub_key))
        .config(broadcast.clone())
        .build()
        .validate_fee_denomination()
        .await
        .change_context(Error::Broadcaster)?;

    let health_check_server = health_check::Server::new(health_check_bind_addr);

    let verifier: TMAddress = pub_key
        .account_id(PREFIX)
        .expect("failed to convert to account identifier")
        .into();

    App::new(
        tm_client,
        broadcaster,
        multisig_client,
        broadcast,
        event_processor.stream_buffer_size,
        block_height_monitor,
        health_check_server,
    )
    .configure_handlers(verifier, handlers, event_processor)
    .await
}

async fn check_finalizer<'a, C>(
    chain_name: &ChainName,
    finalization: &Finalization,
    rpc_client: &'a C,
) -> Result<(), Error>
where
    C: EthereumClient + Send + Sync,
{
    let _ = pick(finalization, rpc_client, 0)
        .latest_finalized_block_height()
        .await
        .change_context_lazy(|| Error::InvalidFinalizerType(chain_name.to_owned()))?;

    Ok(())
}

struct App<T>
where
    T: Broadcaster,
{
    event_publisher: event_sub::EventPublisher<tendermint_rpc::HttpClient>,
    event_subscriber: event_sub::EventSubscriber,
    event_processor: TaskGroup<event_processor::Error>,
    broadcaster: QueuedBroadcaster<T>,
    multisig_client: MultisigClient,
    block_height_monitor: BlockHeightMonitor<tendermint_rpc::HttpClient>,
    health_check_server: health_check::Server,
    token: CancellationToken,
}

impl<T> App<T>
where
    T: Broadcaster + Send + Sync + 'static,
{
    #[allow(clippy::too_many_arguments)]
    fn new(
        tm_client: tendermint_rpc::HttpClient,
        broadcaster: T,
        multisig_client: MultisigClient,
        broadcast_cfg: broadcaster::Config,
        event_buffer_cap: usize,
        block_height_monitor: BlockHeightMonitor<tendermint_rpc::HttpClient>,
        health_check_server: health_check::Server,
    ) -> Self {
        let token = CancellationToken::new();

        let (event_publisher, event_subscriber) =
            event_sub::EventPublisher::new(tm_client, event_buffer_cap);

        let event_processor = TaskGroup::new();
        let broadcaster = QueuedBroadcaster::new(
            broadcaster,
            broadcast_cfg.batch_gas_limit,
            broadcast_cfg.queue_cap,
            interval(broadcast_cfg.broadcast_interval),
        );

        Self {
            event_publisher,
            event_subscriber,
            event_processor,
            broadcaster,
            multisig_client,
            block_height_monitor,
            health_check_server,
            token,
        }
    }

    async fn configure_handlers(
        mut self,
        verifier: TMAddress,
        handler_configs: Vec<handlers::config::Config>,
        event_processor_config: event_processor::Config,
    ) -> Result<App<T>, Error> {
        for config in handler_configs {
            let task = match config {
                handlers::config::Config::EvmMsgVerifier {
                    chain,
                    cosmwasm_contract,
                    rpc_timeout,
                } => {
                    let rpc_client = json_rpc::Client::new_http(
                        &chain.rpc_url,
                        reqwest::ClientBuilder::new()
                            .connect_timeout(rpc_timeout.unwrap_or(DEFAULT_RPC_TIMEOUT))
                            .timeout(rpc_timeout.unwrap_or(DEFAULT_RPC_TIMEOUT))
                            .build()
                            .change_context(Error::Connection)?,
                    );

                    check_finalizer(&chain.name, &chain.finalization, &rpc_client).await?;

                    self.create_handler_task(
                        format!("{}-msg-verifier", chain.name),
                        handlers::evm_verify_msg::Handler::new(
                            verifier.clone(),
                            cosmwasm_contract,
                            chain.name,
                            chain.finalization,
                            rpc_client,
                            self.block_height_monitor.latest_block_height(),
                        ),
                        event_processor_config.clone(),
                    )
                }
                handlers::config::Config::EvmVerifierSetVerifier {
                    chain,
                    cosmwasm_contract,
                    rpc_timeout,
                } => {
                    let rpc_client = json_rpc::Client::new_http(
                        &chain.rpc_url,
                        reqwest::ClientBuilder::new()
                            .connect_timeout(rpc_timeout.unwrap_or(DEFAULT_RPC_TIMEOUT))
                            .timeout(rpc_timeout.unwrap_or(DEFAULT_RPC_TIMEOUT))
                            .build()
                            .change_context(Error::Connection)?,
                    );

                    check_finalizer(&chain.name, &chain.finalization, &rpc_client).await?;

                    self.create_handler_task(
                        format!("{}-verifier-set-verifier", chain.name),
                        handlers::evm_verify_verifier_set::Handler::new(
                            verifier.clone(),
                            cosmwasm_contract,
                            chain.name,
                            chain.finalization,
                            rpc_client,
                            self.block_height_monitor.latest_block_height(),
                        ),
                        event_processor_config.clone(),
                    )
                }
                handlers::config::Config::MultisigSigner { cosmwasm_contract } => self
                    .create_handler_task(
                        "multisig-signer",
                        handlers::multisig::Handler::new(
                            verifier.clone(),
                            cosmwasm_contract,
                            self.multisig_client.clone(),
                            self.block_height_monitor.latest_block_height(),
                        ),
                        event_processor_config.clone(),
                    ),
                handlers::config::Config::SuiMsgVerifier {
                    cosmwasm_contract,
                    rpc_url,
                    rpc_timeout,
                } => self.create_handler_task(
                    "sui-msg-verifier",
                    handlers::sui_verify_msg::Handler::new(
                        verifier.clone(),
                        cosmwasm_contract,
                        json_rpc::Client::new_http(
                            &rpc_url,
                            reqwest::ClientBuilder::new()
                                .connect_timeout(rpc_timeout.unwrap_or(DEFAULT_RPC_TIMEOUT))
                                .timeout(rpc_timeout.unwrap_or(DEFAULT_RPC_TIMEOUT))
                                .build()
                                .change_context(Error::Connection)?,
                        ),
                        self.block_height_monitor.latest_block_height(),
                    ),
                    event_processor_config.clone(),
                ),
                handlers::config::Config::SuiVerifierSetVerifier {
                    cosmwasm_contract,
                    rpc_url,
                    rpc_timeout,
                } => self.create_handler_task(
                    "sui-verifier-set-verifier",
                    handlers::sui_verify_verifier_set::Handler::new(
                        verifier.clone(),
                        cosmwasm_contract,
                        json_rpc::Client::new_http(
                            &rpc_url,
                            reqwest::ClientBuilder::new()
                                .connect_timeout(rpc_timeout.unwrap_or(DEFAULT_RPC_TIMEOUT))
                                .timeout(rpc_timeout.unwrap_or(DEFAULT_RPC_TIMEOUT))
                                .build()
                                .change_context(Error::Connection)?,
                        ),
                        self.block_height_monitor.latest_block_height(),
                    ),
                    event_processor_config.clone(),
                ),
            };
            self.event_processor = self.event_processor.add_task(task);
        }

        Ok(self)
    }

    fn create_handler_task<L, H>(
        &mut self,
        label: L,
        handler: H,
        event_processor_config: event_processor::Config,
    ) -> CancellableTask<Result<(), event_processor::Error>>
    where
        L: AsRef<str>,
        H: EventHandler + Send + Sync + 'static,
    {
        let label = label.as_ref().to_string();
        let broadcaster = self.broadcaster.client();
        let sub = self.event_subscriber.subscribe();

        CancellableTask::create(move |token| {
            event_processor::consume_events(
                label,
                handler,
                broadcaster,
                sub,
                event_processor_config,
                token,
            )
        })
    }

    async fn run(self) -> Result<(), Error> {
        let Self {
            event_publisher,
            event_processor,
            broadcaster,
            block_height_monitor,
            health_check_server,
            token,
            ..
        } = self;

        let exit_token = token.clone();
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

        TaskGroup::new()
            .add_task(CancellableTask::create(|token| {
                block_height_monitor
                    .run(token)
                    .change_context(Error::BlockHeightMonitor)
            }))
            .add_task(CancellableTask::create(|token| {
                event_publisher
                    .run(token)
                    .change_context(Error::EventPublisher)
            }))
            .add_task(CancellableTask::create(|token| {
                health_check_server
                    .run(token)
                    .change_context(Error::HealthCheck)
            }))
            .add_task(CancellableTask::create(|token| {
                event_processor
                    .run(token)
                    .change_context(Error::EventProcessor)
            }))
            .add_task(CancellableTask::create(|_| {
                broadcaster.run().change_context(Error::Broadcaster)
            }))
            .run(token)
            .await
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
    #[error("tofnd failed")]
    Tofnd,
    #[error("connection failed")]
    Connection,
    #[error("task execution failed")]
    Task(#[from] TaskError),
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
    #[error("health check is not working")]
    HealthCheck,
}
