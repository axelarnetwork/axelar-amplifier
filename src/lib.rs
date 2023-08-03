use std::pin::Pin;
use std::time::Duration;

use cosmos_sdk_proto::cosmos::{auth::v1beta1::query_client::QueryClient, tx::v1beta1::service_client::ServiceClient};
use error_stack::Result;
use evm::EvmChainConfig;
use tokio::signal::unix::{signal, SignalKind};
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::Stream;
use tonic::transport::Channel;
use tracing::info;

use broadcaster::Broadcaster;
use broadcaster::{accounts::account, key::ECDSASigningKey};
use event_processor::EventProcessor;
use event_sub::Event;
use queue::queued_broadcaster::{QueuedBroadcaster, QueuedBroadcasterDriver};
use report::Error;
use state::State;
use types::TMAddress;

use crate::config::Config;

mod broadcaster;
pub mod config;
mod deserializers;
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

type HandlerStream = Pin<Box<dyn Stream<Item = Result<Event, BroadcastStreamRecvError>> + Send>>;

pub async fn run(cfg: Config, state: State<'_>) -> Result<(), Error> {
    let Config {
        tm_url,
        broadcast,
        evm_chains,
        tofnd_config: _tofnd_config,
        private_key,
    } = cfg;

    let tm_client = tendermint_rpc::HttpClient::new(tm_url.to_string().as_str()).map_err(Error::new)?;
    let service_client = ServiceClient::connect(tm_url.to_string()).await.map_err(Error::new)?;
    let query_client = QueryClient::connect(tm_url.to_string()).await.map_err(Error::new)?;

    let worker = private_key.address();
    let account = account(query_client, &worker).await.map_err(Error::new)?;
    let broadcaster = broadcaster::BroadcasterBuilder::new(service_client, private_key, broadcast)
        .acc_number(account.account_number)
        .acc_sequence(account.sequence)
        .build();

    App::new(tm_client, broadcaster, state)
        .configure_evm_chains(worker, evm_chains)
        .await?
        .run()
        .await
}

struct App<'a> {
    event_sub_client: event_sub::EventSubClient<tendermint_rpc::HttpClient>,
    event_sub_driver: event_sub::EventSubClientDriver,
    event_processor: EventProcessor,
    broadcaster: QueuedBroadcaster<ServiceClient<Channel>>,
    #[allow(dead_code)]
    broadcaster_driver: QueuedBroadcasterDriver,
    state_updater: state::Updater,
    state: State<'a>,
}

impl<'a> App<'a> {
    fn new(
        tm_client: tendermint_rpc::HttpClient,
        broadcaster: Broadcaster<ServiceClient<Channel>>,
        state: State<'a>,
    ) -> Self {
        let (event_sub_client, event_sub_driver) = event_sub::EventSubClient::new(tm_client, 100000);
        let event_sub_client = match state.min() {
            Some(min_height) => event_sub_client.start_from(min_height.increment()),
            None => event_sub_client,
        };

        let event_processor = EventProcessor::new();
        // TODO: make these parameters configurable
        let (broadcaster, broadcaster_driver) =
            QueuedBroadcaster::new(broadcaster, 1000000, 1000, Duration::from_secs(5));

        Self {
            event_sub_client,
            event_sub_driver,
            event_processor,
            broadcaster,
            broadcaster_driver,
            state_updater: state::Updater::default(),
            state,
        }
    }

    async fn configure_evm_chains(
        mut self,
        worker: TMAddress,
        evm_chains: Vec<EvmChainConfig>,
    ) -> Result<App<'a>, Error> {
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

            let sub: HandlerStream = match self.state.get(&label) {
                None => Box::pin(self.event_sub_client.sub()),
                Some(&completed_height) => Box::pin(event_sub::skip_to_block(
                    self.event_sub_client.sub(),
                    completed_height.increment(),
                )),
            };
            self.event_processor.add_handler(handler, sub);
        }

        Ok(self)
    }

    async fn run(self) -> Result<(), Error> {
        let Self {
            event_sub_client,
            event_processor,
            broadcaster,
            event_sub_driver,
            state_updater,
            state,
            ..
        } = self;

        let event_sub_handle = tokio::spawn(event_sub_client.run());
        let event_processor_handle = tokio::spawn(event_processor.run());
        let broadcaster_handler = tokio::spawn(broadcaster.run());

        tokio::spawn(async {
            let mut sigint = signal(SignalKind::interrupt()).expect("failed to capture SIGINT");
            let mut sigterm = signal(SignalKind::terminate()).expect("failed to capture SIGTERM");

            tokio::select! {
                _ = sigint.recv() => {},
                _ = sigterm.recv() => {},
            }

            info!("signal received, waiting for program to exit gracefully");

            event_sub_driver.close()
        });

        state_updater.run(state).await.map_err(Error::new)?;

        event_sub_handle.await.map_err(Error::new)?.map_err(Error::new)?;
        event_processor_handle.await.map_err(Error::new)?.map_err(Error::new)?;
        broadcaster_handler.await.map_err(Error::new)?.map_err(Error::new)?;

        Ok(())
    }
}
