use std::pin::Pin;
use std::time::Duration;

use block_height_monitor::BlockHeightMonitor;
use broadcaster::accounts::account;
use broadcaster::Broadcaster;
use connection_router_api::ChainName;
use cosmos_sdk_proto::cosmos::auth::v1beta1::query_client::QueryClient;
use cosmos_sdk_proto::cosmos::tx::v1beta1::service_client::ServiceClient;
use error_stack::{report, FutureExt, Result, ResultExt};
use event_processor::EventHandler;
use events::Event;
use evm::finalizer::{pick, Finalization};
use evm::json_rpc::EthereumClient;
use queue::queued_broadcaster::{QueuedBroadcaster, QueuedBroadcasterDriver};
use state::StateUpdater;
use thiserror::Error;
use tofnd::grpc::{MultisigClient, SharableEcdsaClient};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::oneshot;
use tokio_stream::Stream;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use types::TMAddress;

use crate::asyncutil::task::{CancellableTask, TaskError, TaskGroup};
use crate::config::Config;
use crate::state::State;

mod asyncutil;
mod block_height_monitor;
mod broadcaster;
pub mod commands;
pub mod config;
pub mod error;
mod event_processor;
mod event_sub;
mod evm;
mod handlers;
mod health_check;
mod json_rpc;
mod queue;
mod starknet;
pub mod state;
mod sui;
mod tm_client;
mod tofnd;
mod types;
mod url;

const PREFIX: &str = "axelar";
const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(3);

type HandlerStream<E> = Pin<Box<dyn Stream<Item = Result<Event, E>> + Send>>;

pub async fn run(cfg: Config, state: State) -> (State, Result<(), Error>) {
    let app = prepare_app(cfg, state.clone()).await;

    match app {
        Ok(app) => app.run().await,
        Err(err) => (state, Err(err)),
    }
}

async fn prepare_app(cfg: Config, state: State) -> Result<App<impl Broadcaster>, Error> {
    let Config {
        tm_jsonrpc,
        tm_grpc,
        broadcast,
        handlers,
        tofnd_config,
        event_buffer_cap,
        event_stream_timeout,
        service_registry: _service_registry,
        health_check_bind_addr,
    } = cfg;

    let tm_client = tendermint_rpc::HttpClient::new(tm_jsonrpc.to_string().as_str())
        .change_context(Error::Connection)?;
    let service_client = ServiceClient::connect(tm_grpc.to_string())
        .await
        .change_context(Error::Connection)?;
    let query_client = QueryClient::connect(tm_grpc.to_string())
        .await
        .change_context(Error::Connection)?;
    let multisig_client = MultisigClient::connect(tofnd_config.party_uid, tofnd_config.url)
        .await
        .change_context(Error::Connection)?;
    let ecdsa_client = SharableEcdsaClient::new(multisig_client);

    let block_height_monitor = BlockHeightMonitor::connect(tm_client.clone())
        .await
        .change_context(Error::Connection)?;

    let mut state_updater = StateUpdater::new(state);
    let pub_key = match state_updater.state().pub_key {
        Some(pub_key) => pub_key,
        None => {
            let pub_key = ecdsa_client
                .keygen(&tofnd_config.key_uid)
                .await
                .change_context(Error::Tofnd)?;
            state_updater.as_mut().pub_key = Some(pub_key);

            pub_key
        }
    };

    let worker = pub_key
        .account_id(PREFIX)
        .expect("failed to convert to account identifier")
        .into();
    let account = account(query_client, &worker)
        .await
        .change_context(Error::Broadcaster)?;

    let broadcaster = broadcaster::BroadcastClientBuilder::default()
        .client(service_client)
        .signer(ecdsa_client.clone())
        .acc_number(account.account_number)
        .acc_sequence(account.sequence)
        .pub_key((tofnd_config.key_uid, pub_key))
        .config(broadcast.clone())
        .build()
        .change_context(Error::Broadcaster)?;

    let health_check_server = health_check::Server::new(health_check_bind_addr);

    App::new(
        tm_client,
        broadcaster,
        state_updater,
        ecdsa_client,
        broadcast,
        event_buffer_cap,
        block_height_monitor,
        health_check_server,
    )
    .configure_handlers(worker, handlers, event_stream_timeout)
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
    event_processor: TaskGroup<event_processor::Error>,
    broadcaster: QueuedBroadcaster<T>,
    #[allow(dead_code)]
    broadcaster_driver: QueuedBroadcasterDriver,
    state_updater: StateUpdater,
    ecdsa_client: SharableEcdsaClient,
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
        state_updater: StateUpdater,
        ecdsa_client: SharableEcdsaClient,
        broadcast_cfg: broadcaster::Config,
        event_buffer_cap: usize,
        block_height_monitor: BlockHeightMonitor<tendermint_rpc::HttpClient>,
        health_check_server: health_check::Server,
    ) -> Self {
        let token = CancellationToken::new();

        let event_publisher = event_sub::EventPublisher::new(tm_client, event_buffer_cap);
        let event_publisher = match state_updater.state().min_handler_block_height() {
            Some(min_height) => event_publisher.start_from(min_height.increment()),
            None => event_publisher,
        };

        let event_processor = TaskGroup::new();
        let (broadcaster, broadcaster_driver) = QueuedBroadcaster::new(
            broadcaster,
            broadcast_cfg.batch_gas_limit,
            broadcast_cfg.queue_cap,
            broadcast_cfg.broadcast_interval,
        );

        Self {
            event_publisher,
            event_processor,
            broadcaster,
            broadcaster_driver,
            state_updater,
            ecdsa_client,
            block_height_monitor,
            health_check_server,
            token,
        }
    }

    async fn configure_handlers(
        mut self,
        worker: TMAddress,
        handler_configs: Vec<handlers::config::Config>,
        stream_timeout: Duration,
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
                            worker.clone(),
                            cosmwasm_contract,
                            chain.name,
                            chain.finalization,
                            rpc_client,
                            self.broadcaster.client(),
                            self.block_height_monitor.latest_block_height(),
                        ),
                        stream_timeout,
                    )
                }
                handlers::config::Config::EvmWorkerSetVerifier {
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
                        format!("{}-worker-set-verifier", chain.name),
                        handlers::evm_verify_worker_set::Handler::new(
                            worker.clone(),
                            cosmwasm_contract,
                            chain.name,
                            chain.finalization,
                            rpc_client,
                            self.broadcaster.client(),
                            self.block_height_monitor.latest_block_height(),
                        ),
                        stream_timeout,
                    )
                }
                handlers::config::Config::MultisigSigner { cosmwasm_contract } => self
                    .create_handler_task(
                        "multisig-signer",
                        handlers::multisig::Handler::new(
                            worker.clone(),
                            cosmwasm_contract,
                            self.broadcaster.client(),
                            self.ecdsa_client.clone(),
                            self.block_height_monitor.latest_block_height(),
                        ),
                        stream_timeout,
                    ),
                handlers::config::Config::SuiMsgVerifier {
                    cosmwasm_contract,
                    rpc_url,
                    rpc_timeout,
                } => self.create_handler_task(
                    "sui-msg-verifier",
                    handlers::sui_verify_msg::Handler::new(
                        worker.clone(),
                        cosmwasm_contract,
                        json_rpc::Client::new_http(
                            &rpc_url,
                            reqwest::ClientBuilder::new()
                                .connect_timeout(rpc_timeout.unwrap_or(DEFAULT_RPC_TIMEOUT))
                                .timeout(rpc_timeout.unwrap_or(DEFAULT_RPC_TIMEOUT))
                                .build()
                                .change_context(Error::Connection)?,
                        ),
                        self.broadcaster.client(),
                        self.block_height_monitor.latest_block_height(),
                    ),
                    stream_timeout,
                ),
                handlers::config::Config::SuiWorkerSetVerifier {
                    cosmwasm_contract,
                    rpc_url,
                    rpc_timeout,
                } => self.create_handler_task(
                    "sui-worker-set-verifier",
                    handlers::sui_verify_worker_set::Handler::new(
                        worker.clone(),
                        cosmwasm_contract,
                        json_rpc::Client::new_http(
                            &rpc_url,
                            reqwest::ClientBuilder::new()
                                .connect_timeout(rpc_timeout.unwrap_or(DEFAULT_RPC_TIMEOUT))
                                .timeout(rpc_timeout.unwrap_or(DEFAULT_RPC_TIMEOUT))
                                .build()
                                .change_context(Error::Connection)?,
                        ),
                        self.broadcaster.client(),
                        self.block_height_monitor.latest_block_height(),
                    ),
                    stream_timeout,
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
        stream_timeout: Duration,
    ) -> CancellableTask<Result<(), event_processor::Error>>
    where
        L: AsRef<str>,
        H: EventHandler + Send + Sync + 'static,
    {
        let (handler, rx) = handlers::end_block::with_block_height_notifier(handler);
        self.state_updater.register_event(label.as_ref(), rx);

        let sub: HandlerStream<_> = match self
            .state_updater
            .state()
            .handler_block_height(label.as_ref())
        {
            None => Box::pin(self.event_publisher.subscribe()),
            Some(&completed_height) => Box::pin(event_sub::skip_to_block(
                self.event_publisher.subscribe(),
                completed_height.increment(),
            )),
        };

        CancellableTask::create(move |token| {
            event_processor::consume_events(handler, sub, stream_timeout, token)
        })
    }

    async fn run(self) -> (State, Result<(), Error>) {
        let Self {
            event_publisher,
            event_processor,
            broadcaster,
            state_updater,
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

        let (state_tx, mut state_rx) = oneshot::channel::<State>();

        let execution_result = TaskGroup::new()
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
            .add_task(CancellableTask::create(|_| async move {
                // assert: the state updater only stops when all handlers that are updating
                // their states have stopped
                state_tx
                    .send(state_updater.run().await)
                    .map_err(|_| report!(Error::ReturnState))
            }))
            .run(token)
            .await;

        // assert: all tasks have exited, it is safe to receive the state
        let state = state_rx
            .try_recv()
            .expect("the state sender should have been able to send the state");

        (state, execution_result)
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
