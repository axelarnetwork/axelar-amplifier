use std::pin::Pin;

use error_stack::Result;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::Stream;

use event_processor::EventProcessor;
use event_sub::Event;
use report::Error;
use state::State;

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
mod types;
mod url;

type HandlerStream = Pin<Box<dyn Stream<Item = Result<Event, BroadcastStreamRecvError>> + Send>>;

pub async fn run(cfg: Config, state: State<'_>) -> Result<(), Error> {
    let tm_client = tendermint_rpc::HttpClient::new(cfg.tm_url.as_str()).map_err(Error::new)?;
    let mut app = App::new(tm_client, state);

    app = app.configure(cfg).await?;
    app.run().await
}

pub struct App<'a> {
    event_sub_client: event_sub::EventSubClient<tendermint_rpc::HttpClient>,
    event_sub_driver: event_sub::EventSubClientDriver,
    event_processor: EventProcessor,
    event_processor_driver: event_processor::EventProcessorDriver,
    state_updater: state::Updater,
    state: State<'a>,
}

impl<'a> App<'a> {
    pub fn new(tm_client: tendermint_rpc::HttpClient, state: State<'a>) -> Self {
        let (event_sub_client, event_sub_driver) = event_sub::EventSubClient::new(tm_client, 100000);
        let event_sub_client = match state.min() {
            Some(min_height) => event_sub_client.start_from(min_height.increment()),
            None => event_sub_client,
        };

        let (event_processor, event_processor_driver) = EventProcessor::new();

        Self {
            event_sub_client,
            event_sub_driver,
            event_processor,
            event_processor_driver,
            state_updater: state::Updater::default(),
            state,
        }
    }

    pub async fn configure(mut self, cfg: Config) -> Result<App<'a>, Error> {
        for config in cfg.evm_chain_configs {
            let label = format!("{}-confirm-gateway-tx-handler", config.name);
            let handler = evm::confirm_gateway_tx_handler(&config).await.map_err(Error::new)?;

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

    pub async fn run(self) -> Result<(), Error> {
        let client = self.event_sub_client;
        let processor = self.event_processor;
        let mut state = self.state;

        tokio::spawn(async move { client.run().await });
        tokio::spawn(async move { processor.run().await });
        self.state_updater.run(&mut state).await;

        // TODO: Make the teardown process more robust so that it is done however the program is terminated
        self.event_sub_driver.close().map_err(Error::new)?;
        self.event_processor_driver.close().map_err(Error::new)?;
        state.flush().map_err(Error::new)?;

        Ok(())
    }
}
