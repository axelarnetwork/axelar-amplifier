use std::path::PathBuf;
use std::pin::Pin;

use cosmos_sdk_proto::cosmos::{
    auth::v1beta1::query_client::QueryClient, tx::v1beta1::service_client::ServiceClient,
};
use error_stack::{FutureExt, IntoReport, Result};
use tokio::signal::unix::{signal, SignalKind};
use tokio::task::JoinSet;
use tokio_stream::Stream;
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;
use tracing::info;

use crate::config::Config;
use broadcaster::Broadcaster;
use broadcaster::{accounts::account, key::ECDSASigningKey};
use event_processor::EventProcessor;
use event_sub::Event;
use evm::EvmChainConfig;
use queue::queued_broadcaster::{QueuedBroadcaster, QueuedBroadcasterDriver};
use report::Error;
use state::StateUpdater;
use tofnd::grpc::{MultisigClient, SharableEcdsaClient};
use types::TMAddress;

mod broadcaster;
pub mod config;
mod event_processor;
mod event_sub;
mod evm;
mod handlers;
mod queue;
pub mod report;
pub mod state;
mod tm_client;
mod tofnd;
mod types;
mod url;

type HandlerStream<E> = Pin<Box<dyn Stream<Item = Result<Event, E>> + Send>>;

pub async fn run(cfg: Config, state_path: PathBuf) -> Result<(), Error> {
    let Config {
        tm_jsonrpc,
        tm_grpc,
        broadcast,
        evm_chains,
        tofnd_config,
        private_key,
        event_buffer_cap,
    } = cfg;

    let tm_client =
        tendermint_rpc::HttpClient::new(tm_jsonrpc.to_string().as_str()).map_err(Error::new)?;
    let service_client = ServiceClient::connect(tm_grpc.to_string())
        .await
        .map_err(Error::new)?;
    let query_client = QueryClient::connect(tm_grpc.to_string())
        .await
        .map_err(Error::new)?;
    let multisig_client = MultisigClient::connect(tofnd_config.party_uid, tofnd_config.url)
        .await
        .map_err(Error::new)?;

    let worker = private_key.address();
    let account = account(query_client, &worker).await.map_err(Error::new)?;
    let broadcaster =
        broadcaster::BroadcasterBuilder::new(service_client, private_key, broadcast.clone())
            .acc_number(account.account_number)
            .acc_sequence(account.sequence)
            .build();
    let state_updater = StateUpdater::new(state_path).map_err(Error::new)?;
    let ecdsa_client = SharableEcdsaClient::new(multisig_client);

    App::new(
        tm_client,
        broadcaster,
        state_updater,
        ecdsa_client,
        broadcast,
        event_buffer_cap,
    )
    .configure_evm_chains(worker, evm_chains)
    .await?
    .run()
    .await
}

struct App {
    event_sub: event_sub::EventSub<tendermint_rpc::HttpClient>,
    event_processor: EventProcessor,
    broadcaster: QueuedBroadcaster<ServiceClient<Channel>>,
    #[allow(dead_code)]
    broadcaster_driver: QueuedBroadcasterDriver,
    state_updater: StateUpdater,
    #[allow(dead_code)]
    ecdsa_client: SharableEcdsaClient,
    token: CancellationToken,
}

impl App {
    fn new(
        tm_client: tendermint_rpc::HttpClient,
        broadcaster: Broadcaster<ServiceClient<Channel>>,
        state_updater: StateUpdater,
        ecdsa_client: SharableEcdsaClient,
        broadcast_cfg: broadcaster::Config,
        event_buffer_cap: usize,
    ) -> Self {
        let token = CancellationToken::new();

        let event_sub = event_sub::EventSub::new(tm_client, event_buffer_cap, token.child_token());
        let event_sub = match state_updater.state().min_handler_block_height() {
            Some(min_height) => event_sub.start_from(min_height.increment()),
            None => event_sub,
        };

        let event_processor = EventProcessor::new(token.child_token());
        let (broadcaster, broadcaster_driver) = QueuedBroadcaster::new(
            broadcaster,
            broadcast_cfg.batch_gas_limit,
            broadcast_cfg.queue_cap,
            broadcast_cfg.broadcast_interval,
        );

        Self {
            event_sub,
            event_processor,
            broadcaster,
            broadcaster_driver,
            state_updater,
            ecdsa_client,
            token,
        }
    }

    async fn configure_evm_chains(
        mut self,
        worker: TMAddress,
        evm_chains: Vec<EvmChainConfig>,
    ) -> Result<App, Error> {
        for config in evm_chains {
            let label = format!("{}-confirm-gateway-tx-handler", config.name);
            let handler = handlers::evm_verify_msg::Handler::new(
                worker.clone(),
                config.voting_verifier,
                config.name,
                evm::json_rpc::Client::new_http(&config.rpc_url).map_err(Error::new)?,
                self.broadcaster.client(),
            );

            let (handler, rx) = handlers::end_block::with_block_height_notifier(handler);
            self.state_updater.register_event(&label, rx);

            let sub: HandlerStream<_> =
                match self.state_updater.state().handler_block_height(&label) {
                    None => Box::pin(self.event_sub.sub()),
                    Some(&completed_height) => Box::pin(event_sub::skip_to_block(
                        self.event_sub.sub(),
                        completed_height.increment(),
                    )),
                };
            self.event_processor.add_handler(handler, sub);
        }

        Ok(self)
    }

    async fn run(self) -> Result<(), Error> {
        let Self {
            event_sub,
            event_processor,
            broadcaster,
            state_updater,
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

        let mut set = JoinSet::new();
        set.spawn(event_sub.run().change_context(Error::EventSub));
        set.spawn(event_processor.run().change_context(Error::EventProcessor));
        set.spawn(broadcaster.run().change_context(Error::Broadcaster));
        set.spawn(state_updater.run().change_context(Error::StateUpdater));

        let res = match (set.join_next().await, token.is_cancelled()) {
            (Some(result), false) => {
                token.cancel();
                result
                    .map_err(Error::new)
                    .into_report()
                    .and_then(|result| result)
            }
            (Some(_), true) => Ok(()),
            (None, _) => panic!("all tasks exited unexpectedly"),
        };

        while (set.join_next().await).is_some() {}

        res
    }
}
