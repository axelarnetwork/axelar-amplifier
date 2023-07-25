use std::pin::Pin;
use std::time::Duration;

use broadcaster::key::ECDSASigningKey;
use broadcaster::Broadcaster;
use cosmos_sdk_proto::cosmos::tx::v1beta1::service_client::ServiceClient;
use error_stack::Result;
use queue::queued_broadcaster::{QueuedBroadcaster, QueuedBroadcasterDriver};
use tokio::signal::unix::{signal, SignalKind};
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::Stream;
use tonic::transport::Channel;
use tracing::info;

use crate::config::Config;
use event_processor::EventProcessor;
use event_sub::Event;
use report::Error;
use state::State;

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
    let tm_client = tendermint_rpc::HttpClient::new(cfg.tm_url.to_string().as_str()).map_err(Error::new)?;
    let broadcaster = broadcaster::BroadcasterBuilder::new(
        ServiceClient::connect(cfg.tm_url.to_string())
            .await
            .map_err(Error::new)?,
        // TODO: load the private key properly
        ECDSASigningKey::random(),
        cfg.broadcast.clone(),
    )
    .build();

    App::new(tm_client, broadcaster, state)
        .configure(cfg)
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

    async fn configure(mut self, cfg: Config) -> Result<App<'a>, Error> {
        for config in cfg.evm_chain_configs {
            let label = format!("{}-confirm-gateway-tx-handler", config.name);
            let handler = handlers::evm_verify_msg::Handler::new(
                config.name,
                evm::new_finalizer(&config).await.map_err(Error::new)?,
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
        let client = self.event_sub_client;
        let processor = self.event_processor;
        let broadcaster = self.broadcaster;
        let event_sub_driver = self.event_sub_driver;

        let event_sub_handle = tokio::spawn(async move { client.run().await });
        let event_processor_handle = tokio::spawn(async move { processor.run().await });
        let broadcaster_handler = tokio::spawn(async move { broadcaster.run().await });

        tokio::spawn(async move {
            let mut sigint = signal(SignalKind::interrupt()).expect("failed to capture SIGINT");
            let mut sigterm = signal(SignalKind::terminate()).expect("failed to capture SIGTERM");

            tokio::select! {
                _ = sigint.recv() => {},
                _ = sigterm.recv() => {},
            }

            info!("signal received, waiting for program to exit gracefully");

            event_sub_driver.close()
        });

        self.state_updater.run(self.state).await.map_err(Error::new)?;

        event_sub_handle.await.map_err(Error::new)?.map_err(Error::new)?;
        event_processor_handle.await.map_err(Error::new)?.map_err(Error::new)?;
        broadcaster_handler.await.map_err(Error::new)?.map_err(Error::new)?;

        Ok(())
    }
}
