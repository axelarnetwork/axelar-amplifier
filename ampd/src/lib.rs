use std::path::PathBuf;
use std::pin::Pin;

use cosmos_sdk_proto::cosmos::{
    auth::v1beta1::query_client::QueryClient, tx::v1beta1::service_client::ServiceClient,
};
use error_stack::{FutureExt, Result, ResultExt};
use tokio::signal::unix::{signal, SignalKind};
use tokio::task::JoinSet;
use tokio_stream::Stream;
use tokio_util::sync::CancellationToken;
use tracing::info;

use broadcaster::{accounts::account, Broadcaster};
use event_processor::{EventHandler, EventProcessor};
use events::Event;
use queue::queued_broadcaster::{QueuedBroadcaster, QueuedBroadcasterDriver};
use state::StateUpdater;
use tofnd::grpc::{MultisigClient, SharableEcdsaClient};
use types::TMAddress;

use crate::config::Config;
use crate::error::Error;

mod broadcaster;
pub mod config;
pub mod error;
mod event_processor;
mod event_sub;
mod evm;
mod handlers;
mod queue;
pub mod state;
mod tm_client;
mod tofnd;
mod types;
mod url;

const PREFIX: &str = "axelar";

type HandlerStream<E> = Pin<Box<dyn Stream<Item = Result<Event, E>> + Send>>;

pub async fn run(cfg: Config, state_path: PathBuf) -> Result<(), Error> {
    let Config {
        tm_jsonrpc,
        tm_grpc,
        broadcast,
        handlers,
        tofnd_config,
        event_buffer_cap,
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

    let mut state_updater = StateUpdater::new(state_path).change_context(Error::StateUpdater)?;
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

    App::new(
        tm_client,
        broadcaster,
        state_updater,
        ecdsa_client,
        broadcast,
        event_buffer_cap,
    )
    .configure_handlers(worker, handlers)?
    .run()
    .await
}

struct App<T>
where
    T: Broadcaster,
{
    event_sub: event_sub::EventSub<tendermint_rpc::HttpClient>,
    event_processor: EventProcessor,
    broadcaster: QueuedBroadcaster<T>,
    #[allow(dead_code)]
    broadcaster_driver: QueuedBroadcasterDriver,
    state_updater: StateUpdater,
    ecdsa_client: SharableEcdsaClient,
    token: CancellationToken,
}

impl<T> App<T>
where
    T: Broadcaster + Send + Sync + 'static,
{
    fn new(
        tm_client: tendermint_rpc::HttpClient,
        broadcaster: T,
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

    fn configure_handlers(
        mut self,
        worker: TMAddress,
        handler_configs: Vec<handlers::config::Config>,
    ) -> Result<App<T>, Error> {
        for config in handler_configs {
            match config {
                handlers::config::Config::EvmMsgVerifier {
                    chain,
                    cosmwasm_contract,
                } => self.configure_handler(
                    format!("{}-msg-verifier", chain.name),
                    handlers::evm_verify_msg::Handler::new(
                        worker.clone(),
                        cosmwasm_contract,
                        chain.name,
                        evm::json_rpc::Client::new_http(&chain.rpc_url)
                            .change_context(Error::Connection)?,
                        self.broadcaster.client(),
                    ),
                ),
                handlers::config::Config::EvmWorkerSetVerifier {
                    chain,
                    cosmwasm_contract,
                } => self.configure_handler(
                    format!("{}-worker-set-verifier", chain.name),
                    handlers::evm_verify_worker_set::Handler::new(
                        worker.clone(),
                        cosmwasm_contract,
                        chain.name,
                        evm::json_rpc::Client::new_http(&chain.rpc_url)
                            .change_context(Error::Connection)?,
                        self.broadcaster.client(),
                    ),
                ),
                handlers::config::Config::MultisigSigner { cosmwasm_contract } => self
                    .configure_handler(
                        "multisig-signer",
                        handlers::multisig::Handler::new(
                            worker.clone(),
                            cosmwasm_contract,
                            self.broadcaster.client(),
                            self.ecdsa_client.clone(),
                        ),
                    ),
            }
        }

        Ok(self)
    }

    fn configure_handler<L, H>(&mut self, label: L, handler: H)
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
            None => Box::pin(self.event_sub.sub()),
            Some(&completed_height) => Box::pin(event_sub::skip_to_block(
                self.event_sub.sub(),
                completed_height.increment(),
            )),
        };
        self.event_processor.add_handler(handler, sub);
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
                result.change_context(Error::Task)?
            }
            (Some(_), true) => Ok(()),
            (None, _) => panic!("all tasks exited unexpectedly"),
        };

        while (set.join_next().await).is_some() {}

        res
    }
}
