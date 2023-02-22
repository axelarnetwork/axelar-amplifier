use crate::event_processor::EventHandler;
use crate::report::Error;
use error_stack::Result;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{StreamExt, StreamMap};

mod broadcaster;
pub mod config;
mod deserializers;
pub mod event_processor;
pub mod event_sub;
pub mod evm;
mod handlers;
pub mod report;
mod tm_client;
mod types;
mod url;

pub async fn run(cfg: config::Config) -> Result<(), Error> {
    let tm_client = tendermint_rpc::HttpClient::new(cfg.tm_url.as_str()).map_err(Error::new)?;
    let (mut event_sub_client, _event_sub_driver) = event_sub::EventSubClient::new(tm_client, 100000);
    let (mut event_processor, _event_processor_driver) = event_processor::EventProcessor::new();
    let mut evm_client_repo = evm::json_rpc::EVMClientRepo::default();
    let mut end_block_streams = StreamMap::new();

    for config in cfg.evm_chain_configs {
        let label = format!("{}-confirm-gateway-tx-handler", config.name);
        let confirm_gateway_tx_handler = evm::confirm_gateway_tx_handler(&mut evm_client_repo, &config)
            .await
            .map_err(Error::new)?;
        let (end_block_handler, rx) = handlers::end_block::Handler::new();
        end_block_streams.insert(label, ReceiverStream::new(rx));
        event_processor.add_handler(
            confirm_gateway_tx_handler.chain(end_block_handler),
            event_sub_client.sub(),
        );
    }

    tokio::spawn(async move { event_sub_client.run().await.unwrap() });
    tokio::spawn(async move { event_processor.run().await.unwrap() });

    while let Some(end_block) = end_block_streams.next().await {
        println!("end_block {:?}", end_block);
    }

    Ok(())
}
