use std::pin::Pin;
use std::time::Duration;

use asyncutil::task::{CancellableTask, TaskError, TaskGroup};
use block_height_monitor::BlockHeightMonitor;
use broadcaster::Broadcaster;
use broadcaster_v2::MsgQueue;
use cosmos::CosmosGrpcClient;
use error_stack::{FutureExt, Result, ResultExt};
use event_processor::EventHandler;
use event_sub::EventSub;
use evm::finalizer::{pick, Finalization};
use evm::json_rpc::EthereumClient;
use multiversx_sdk::gateway::GatewayProxy;
use queue::queued_broadcaster::QueuedBroadcaster;
use router_api::ChainName;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use starknet_providers::jsonrpc::HttpTransport;
use thiserror::Error;
use tofnd::grpc::{Multisig, MultisigClient};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;
use tracing::info;
use types::{CosmosPublicKey, TMAddress};

use crate::config::Config;

mod asyncutil;
mod block_height_monitor;
mod broadcaster;
#[allow(dead_code)]
mod broadcaster_v2;
pub mod commands;
pub mod config;
mod cosmos;
mod event_processor;
mod event_sub;
mod evm;
mod grpc;
mod handlers;
mod health_check;
mod json_rpc;
mod mvx;
mod queue;
mod solana;
mod starknet;
mod stellar;
mod sui;
mod tm_client;
mod tofnd;
mod types;
mod url;
mod xrpl;
pub mod metrics;

use crate::asyncutil::future::RetryPolicy;
use crate::broadcaster::confirm_tx::TxConfirmer;

const PREFIX: &str = "axelar";
const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(3);

pub async fn run(cfg: Config) -> Result<(), Error> {
    prepare_app(cfg).await?.run().await
}

async fn prepare_app(cfg: Config) -> Result<App<impl Broadcaster>, Error> {
    let Config {
        tm_jsonrpc,
        tm_grpc,
        tm_grpc_timeout,
        broadcast,
        handlers,
        tofnd_config,
        event_processor,
        service_registry: _service_registry,
        rewards: _rewards,
        health_check_bind_addr,
        grpc: grpc_config,
    } = cfg;

    let tm_client = tendermint_rpc::HttpClient::new(tm_jsonrpc.to_string().as_str())
        .change_context(Error::Connection)
        .attach_printable(tm_jsonrpc.clone())?;
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
    let (event_publisher, event_subscriber) =
        event_sub::EventPublisher::new(tm_client.clone(), event_processor.stream_buffer_size);
    let cosmos_client = cosmos::CosmosGrpcClient::new(tm_grpc.as_str(), tm_grpc_timeout)
        .await
        .change_context(Error::Connection)
        .attach_printable(tm_grpc.clone())?;
    let broadcaster = broadcaster_v2::Broadcaster::new(
        cosmos_client.clone(),
        broadcast.chain_id.clone(),
        pub_key,
    )
    .await
    .change_context(Error::Broadcaster)?;
    let (msg_queue, msg_queue_client) = broadcaster_v2::MsgQueue::new_msg_queue_and_client(
        broadcaster.clone(),
        broadcast.queue_cap,
        broadcast.batch_gas_limit,
        broadcast.broadcast_interval,
    );
    let grpc_server = grpc::Server::builder()
        .config(grpc_config)
        .event_sub(event_subscriber.clone())
        .msg_queue_client(msg_queue_client)
        .cosmos_grpc_client(cosmos_client.clone())
        .build();
    let broadcaster_task = broadcaster_v2::BroadcasterTask::builder()
        .broadcaster(broadcaster)
        .msg_queue(msg_queue)
        .signer(multisig_client.clone())
        .key_id(tofnd_config.key_uid.clone())
        .gas_adjustment(broadcast.gas_adjustment)
        .gas_price(broadcast.gas_price.clone())
        .build();
    let broadcaster = broadcaster::UnvalidatedBasicBroadcaster::builder()
        .address_prefix(PREFIX.to_string())
        .client(cosmos_client.clone())
        .signer(multisig_client.clone())
        .pub_key((tofnd_config.key_uid, pub_key))
        .config(broadcast.clone())
        .build()
        .validate_fee_denomination()
        .await
        .change_context(Error::Broadcaster)?;

    let broadcaster = QueuedBroadcaster::new(
        broadcaster,
        broadcast.batch_gas_limit,
        broadcast.queue_cap,
        interval(broadcast.broadcast_interval),
    );

    let tx_confirmer = TxConfirmer::new(
        cosmos_client,
        RetryPolicy::RepeatConstant {
            sleep: broadcast.tx_fetch_interval,
            max_attempts: broadcast.tx_fetch_max_retries.saturating_add(1).into(),
        },
    );

    let health_check_server = health_check::Server::new(health_check_bind_addr);

    let verifier: TMAddress = pub_key
        .account_id(PREFIX)
        .expect("failed to convert to account identifier")
        .into();

    App::new(
        event_publisher,
        event_subscriber,
        broadcaster,
        tx_confirmer,
        multisig_client,
        block_height_monitor,
        health_check_server,
        grpc_server,
        broadcaster_task,
    )
    .configure_handlers(verifier, handlers, event_processor)
    .await
}

async fn check_finalizer<C>(
    chain_name: &ChainName,
    finalization: &Finalization,
    rpc_client: &C,
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
    tx_confirmer: TxConfirmer<CosmosGrpcClient>,
    multisig_client: MultisigClient,
    block_height_monitor: BlockHeightMonitor<tendermint_rpc::HttpClient>,
    health_check_server: health_check::Server,
    grpc_server: grpc::Server,
    broadcaster_task: broadcaster_v2::BroadcasterTask<
        cosmos::CosmosGrpcClient,
        Pin<Box<MsgQueue>>,
        MultisigClient,
    >,
}

impl<T> App<T>
where
    T: Broadcaster + Send + Sync + 'static,
{
    #[allow(clippy::too_many_arguments)]
    fn new(
        event_publisher: event_sub::EventPublisher<tendermint_rpc::HttpClient>,
        event_subscriber: event_sub::EventSubscriber,
        broadcaster: QueuedBroadcaster<T>,
        tx_confirmer: TxConfirmer<CosmosGrpcClient>,
        multisig_client: MultisigClient,
        block_height_monitor: BlockHeightMonitor<tendermint_rpc::HttpClient>,
        health_check_server: health_check::Server,
        grpc_server: grpc::Server,
        broadcaster_task: broadcaster_v2::BroadcasterTask<
            cosmos::CosmosGrpcClient,
            Pin<Box<MsgQueue>>,
            MultisigClient,
        >,
    ) -> Self {
        let event_processor = TaskGroup::new("event handler");

        Self {
            event_publisher,
            event_subscriber,
            event_processor,
            broadcaster,
            tx_confirmer,
            multisig_client,
            block_height_monitor,
            health_check_server,
            grpc_server,
            broadcaster_task,
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
                handlers::config::Config::MultisigSigner {
                    cosmwasm_contract,
                    chain_name,
                } => self.create_handler_task(
                    "multisig-signer",
                    handlers::multisig::Handler::new(
                        verifier.clone(),
                        cosmwasm_contract,
                        chain_name,
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
                handlers::config::Config::XRPLMsgVerifier {
                    cosmwasm_contract,
                    chain_name,
                    chain_rpc_url,
                    rpc_timeout,
                } => {
                    let rpc_client = xrpl_http_client::Client::builder()
                        .base_url(chain_rpc_url.as_str())
                        .http_client(
                            reqwest::ClientBuilder::new()
                                .connect_timeout(rpc_timeout.unwrap_or(DEFAULT_RPC_TIMEOUT))
                                .timeout(rpc_timeout.unwrap_or(DEFAULT_RPC_TIMEOUT))
                                .build()
                                .change_context(Error::Connection)?,
                        )
                        .build();

                    self.create_handler_task(
                        format!("{}-msg-verifier", chain_name),
                        handlers::xrpl_verify_msg::Handler::new(
                            verifier.clone(),
                            cosmwasm_contract,
                            rpc_client,
                            self.block_height_monitor.latest_block_height(),
                        ),
                        event_processor_config.clone(),
                    )
                }
                handlers::config::Config::XRPLMultisigSigner {
                    cosmwasm_contract,
                    chain_name,
                } => self.create_handler_task(
                    "xrpl-multisig-signer",
                    handlers::xrpl_multisig::Handler::new(
                        verifier.clone(),
                        cosmwasm_contract,
                        chain_name,
                        self.multisig_client.clone(),
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
                handlers::config::Config::MvxMsgVerifier {
                    cosmwasm_contract,
                    proxy_url,
                } => self.create_handler_task(
                    "mvx-msg-verifier",
                    handlers::mvx_verify_msg::Handler::new(
                        verifier.clone(),
                        cosmwasm_contract,
                        GatewayProxy::new(proxy_url.to_string().trim_end_matches('/').into()),
                        self.block_height_monitor.latest_block_height(),
                    ),
                    event_processor_config.clone(),
                ),
                handlers::config::Config::MvxVerifierSetVerifier {
                    cosmwasm_contract,
                    proxy_url,
                } => self.create_handler_task(
                    "mvx-worker-set-verifier",
                    handlers::mvx_verify_verifier_set::Handler::new(
                        verifier.clone(),
                        cosmwasm_contract,
                        GatewayProxy::new(proxy_url.to_string().trim_end_matches('/').into()),
                        self.block_height_monitor.latest_block_height(),
                    ),
                    event_processor_config.clone(),
                ),
                handlers::config::Config::StellarMsgVerifier {
                    cosmwasm_contract,
                    rpc_url,
                } => self.create_handler_task(
                    "stellar-msg-verifier",
                    handlers::stellar_verify_msg::Handler::new(
                        verifier.clone(),
                        cosmwasm_contract,
                        stellar::rpc_client::Client::new(
                            rpc_url.to_string().trim_end_matches('/').into(),
                        )
                        .change_context(Error::Connection)?,
                        self.block_height_monitor.latest_block_height(),
                    ),
                    event_processor_config.clone(),
                ),
                handlers::config::Config::StellarVerifierSetVerifier {
                    cosmwasm_contract,
                    rpc_url,
                } => self.create_handler_task(
                    "stellar-verifier-set-verifier",
                    handlers::stellar_verify_verifier_set::Handler::new(
                        verifier.clone(),
                        cosmwasm_contract,
                        stellar::rpc_client::Client::new(
                            rpc_url.to_string().trim_end_matches('/').into(),
                        )
                        .change_context(Error::Connection)?,
                        self.block_height_monitor.latest_block_height(),
                    ),
                    event_processor_config.clone(),
                ),
                handlers::config::Config::StarknetMsgVerifier {
                    cosmwasm_contract,
                    rpc_url,
                } => self.create_handler_task(
                    "starknet-msg-verifier",
                    handlers::starknet_verify_msg::Handler::new(
                        verifier.clone(),
                        cosmwasm_contract,
                        starknet::json_rpc::Client::new_with_transport(HttpTransport::new(
                            &rpc_url,
                        ))
                        .change_context(Error::Connection)?,
                        self.block_height_monitor.latest_block_height(),
                    ),
                    event_processor_config.clone(),
                ),
                handlers::config::Config::StarknetVerifierSetVerifier {
                    cosmwasm_contract,
                    rpc_url,
                } => self.create_handler_task(
                    "starknet-verifier-set-verifier",
                    handlers::starknet_verify_verifier_set::Handler::new(
                        verifier.clone(),
                        cosmwasm_contract,
                        starknet::json_rpc::Client::new_with_transport(HttpTransport::new(
                            &rpc_url,
                        ))
                        .change_context(Error::Connection)?,
                        self.block_height_monitor.latest_block_height(),
                    ),
                    event_processor_config.clone(),
                ),
                handlers::config::Config::SolanaMsgVerifier {
                    chain_name,
                    cosmwasm_contract,
                    rpc_url,
                    rpc_timeout,
                } => self.create_handler_task(
                    "solana-msg-verifier",
                    handlers::solana_verify_msg::Handler::new(
                        chain_name,
                        verifier.clone(),
                        cosmwasm_contract,
                        RpcClient::new_with_timeout_and_commitment(
                            rpc_url.to_string(),
                            rpc_timeout.unwrap_or(DEFAULT_RPC_TIMEOUT),
                            CommitmentConfig::finalized(),
                        ),
                        self.block_height_monitor.latest_block_height(),
                    ),
                    event_processor_config.clone(),
                ),
                handlers::config::Config::SolanaVerifierSetVerifier {
                    chain_name,
                    cosmwasm_contract,
                    rpc_url,
                    rpc_timeout,
                } => self.create_handler_task(
                    "solana-verifier-set-verifier",
                    handlers::solana_verify_verifier_set::Handler::new(
                        chain_name,
                        verifier.clone(),
                        cosmwasm_contract,
                        RpcClient::new_with_timeout_and_commitment(
                            rpc_url.to_string(),
                            rpc_timeout.unwrap_or(DEFAULT_RPC_TIMEOUT),
                            CommitmentConfig::finalized(),
                        ),
                        self.block_height_monitor.latest_block_height(),
                    )
                    .await,
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

    fn create_broadcaster_task(
        broadcaster: QueuedBroadcaster<T>,
        confirmer: TxConfirmer<CosmosGrpcClient>,
    ) -> TaskGroup<Error> {
        let (tx_hash_sender, tx_hash_receiver) = mpsc::channel(1000);
        let (tx_response_sender, tx_response_receiver) = mpsc::channel(1000);

        TaskGroup::new("broadcaster")
            .add_task(CancellableTask::create(|_| {
                confirmer
                    .run(tx_hash_receiver, tx_response_sender)
                    .change_context(Error::TxConfirmation)
            }))
            .add_task(CancellableTask::create(|_| {
                broadcaster
                    .run(tx_hash_sender, tx_response_receiver)
                    .change_context(Error::Broadcaster)
            }))
    }

    async fn run(self) -> Result<(), Error> {
        let Self {
            event_publisher,
            event_processor,
            broadcaster,
            tx_confirmer,
            block_height_monitor,
            health_check_server,
            grpc_server,
            broadcaster_task,
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
            .add_task(CancellableTask::create(|token| {
                App::create_broadcaster_task(broadcaster, tx_confirmer).run(token)
            }))
            .add_task(CancellableTask::create(|token| {
                grpc_server.run(token).change_context(Error::GrpcServer)
            }))
            .add_task(CancellableTask::create(|_| {
                broadcaster_task.run().change_context(Error::Broadcaster)
            }))
            .run(main_token)
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
    #[error("tx confirmation failed")]
    TxConfirmation,
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
    #[error("gRPC server failed")]
    GrpcServer,
}
