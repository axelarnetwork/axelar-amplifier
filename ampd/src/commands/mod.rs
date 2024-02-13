use std::path::Path;

use clap::Subcommand;
use cosmos_sdk_proto::cosmos::auth::v1beta1::BaseAccount;
use cosmos_sdk_proto::cosmos::base::abci::v1beta1::TxResponse;
use cosmos_sdk_proto::cosmos::{
    auth::v1beta1::query_client::QueryClient, tx::v1beta1::service_client::ServiceClient,
};
use cosmos_sdk_proto::Any;
use cosmrs::AccountId;
use error_stack::Result;
use error_stack::ResultExt;
use serde::{Deserialize, Serialize};
use valuable::Valuable;

use crate::broadcaster::{accounts::account, Broadcaster};
use crate::config::Config as AmpdConfig;
use crate::state;
use crate::tofnd::grpc::{MultisigClient, SharableEcdsaClient};
use crate::types::{PublicKey, TMAddress};
use crate::{broadcaster, Error};
use crate::{tofnd, PREFIX};

pub mod bond_worker;
pub mod daemon;
pub mod deregister_chain_support;
pub mod register_chain_support;
pub mod register_public_key;
pub mod worker_address;

#[derive(Debug, Subcommand, Valuable)]
pub enum SubCommand {
    /// Run the ampd daemon process (default)
    Daemon,
    /// Bond the worker to the service registry contract
    BondWorker(bond_worker::Args),
    /// Register chain support to the service registry contract
    RegisterChainSupport(register_chain_support::Args),
    /// Deregister chain support to the service registry contract
    DeregisterChainSupport(deregister_chain_support::Args),
    /// Register public key to the multisig contract
    RegisterPublicKey,
    /// Query the worker address
    WorkerAddress,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct ServiceRegistryConfig {
    pub cosmwasm_contract: TMAddress,
}

impl Default for ServiceRegistryConfig {
    fn default() -> Self {
        Self {
            cosmwasm_contract: AccountId::new(PREFIX, &[0; 32]).unwrap().into(),
        }
    }
}

async fn worker_pub_key(state_path: &Path, config: tofnd::Config) -> Result<PublicKey, Error> {
    let state = state::load(state_path).change_context(Error::LoadConfig)?;

    match state.pub_key {
        Some(pub_key) => Ok(pub_key),
        None => SharableEcdsaClient::new(
            MultisigClient::connect(config.party_uid, config.url)
                .await
                .change_context(Error::Connection)?,
        )
        .keygen(&config.key_uid)
        .await
        .change_context(Error::Tofnd),
    }
}

async fn broadcast_tx(
    config: AmpdConfig,
    tx: Any,
    pub_key: PublicKey,
) -> Result<TxResponse, Error> {
    let AmpdConfig {
        tm_grpc,
        broadcast,
        tofnd_config,
        ..
    } = config;

    let account = account_info(tm_grpc.to_string(), &pub_key)
        .await
        .change_context(Error::Broadcaster)?;

    let service_client = ServiceClient::connect(tm_grpc.to_string())
        .await
        .change_context(Error::Connection)?;

    let ecdsa_client = SharableEcdsaClient::new(
        MultisigClient::connect(tofnd_config.party_uid, tofnd_config.url)
            .await
            .change_context(Error::Connection)?,
    );

    broadcaster::BroadcastClientBuilder::default()
        .client(service_client)
        .signer(ecdsa_client)
        .acc_number(account.account_number)
        .acc_sequence(account.sequence)
        .pub_key((tofnd_config.key_uid, pub_key))
        .config(broadcast)
        .build()
        .change_context(Error::Broadcaster)?
        .broadcast(vec![tx])
        .await
        .change_context(Error::Broadcaster)
}

async fn account_info(tm_grpc: String, pub_key: &PublicKey) -> Result<BaseAccount, Error> {
    let query_client = QueryClient::connect(tm_grpc.to_string())
        .await
        .change_context(Error::Connection)?;

    account(
        query_client,
        &pub_key
            .account_id(PREFIX)
            .expect("failed to convert to account identifier")
            .into(),
    )
    .await
    .change_context(Error::Broadcaster)
}
