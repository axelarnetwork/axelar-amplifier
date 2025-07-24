use std::net::SocketAddr;
use std::pin::Pin;

use clap::Subcommand;
use cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse;
use cosmrs::proto::Any;
use cosmrs::AccountId;
use error_stack::{Result, ResultExt};
use futures::TryFutureExt;
use serde::{Deserialize, Serialize};
use valuable::Valuable;

use crate::asyncutil::future::RetryPolicy;
use crate::config::Config;
use crate::tofnd::{Multisig, MultisigClient};
use crate::types::{CosmosPublicKey, TMAddress};
use crate::{broadcaster_v2, cosmos, monitoring, tofnd, Error, PREFIX};

pub mod bond_verifier;
pub mod claim_stake;
pub mod daemon;
pub mod deregister_chain_support;
pub mod register_chain_support;
pub mod register_public_key;
pub mod send_tokens;
pub mod set_rewards_proxy;
pub mod unbond_verifier;
pub mod verifier_address;

#[derive(clap::Args, Debug, Valuable)]
pub struct BroadcastArgs {
    /// Skip transaction confirmation
    #[arg(long, short)]
    skip_confirmation: bool,
}

#[derive(Debug, Subcommand, Valuable)]
pub enum SubCommand {
    /// Run the ampd daemon process (default)
    Daemon,
    /// Bond the verifier to the service registry contract
    BondVerifier(bond_verifier::Args),
    /// Unbond the verifier from the service registry contract
    UnbondVerifier(unbond_verifier::Args),
    /// Claim unbonded stake from the service registry contract
    ClaimStake(claim_stake::Args),
    /// Register chain support to the service registry contract
    RegisterChainSupport(register_chain_support::Args),
    /// Deregister chain support to the service registry contract
    DeregisterChainSupport(deregister_chain_support::Args),
    /// Register public key to the multisig contract
    RegisterPublicKey(register_public_key::Args),
    /// Query the verifier address
    VerifierAddress,
    /// Send tokens from the verifier account to a specified address
    SendTokens(send_tokens::Args),
    /// Set a proxy address to receive rewards, instead of receiving rewards at the verifier address
    SetRewardsProxy(set_rewards_proxy::Args),
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

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct RewardsConfig {
    pub cosmwasm_contract: TMAddress,
}

impl Default for RewardsConfig {
    fn default() -> Self {
        Self {
            cosmwasm_contract: AccountId::new(PREFIX, &[0; 32]).unwrap().into(),
        }
    }
}

async fn verifier_pub_key(config: tofnd::Config) -> Result<CosmosPublicKey, Error> {
    let pub_key = MultisigClient::new(config.party_uid, config.url.as_str(), config.timeout)
        .await
        .change_context(Error::Connection)
        .attach_printable(config.url.clone())?
        .keygen(&config.key_uid, tofnd::Algorithm::Ecdsa)
        .await
        .change_context(Error::Tofnd)?;

    CosmosPublicKey::try_from(pub_key).change_context(Error::Tofnd)
}

async fn broadcast_tx(
    config: Config,
    tx: Any,
    pub_key: CosmosPublicKey,
    skip_confirmation: bool,
) -> Result<String, Error> {
    let Config {
        tm_grpc,
        tm_grpc_timeout,
        broadcast,
        tofnd_config,
        ..
    } = config;
    let cosmos_client = cosmos::CosmosGrpcClient::new(tm_grpc.as_str(), tm_grpc_timeout)
        .await
        .change_context(Error::Connection)
        .attach_printable(tm_grpc.clone())?;

    let mut broadcaster = instantiate_broadcaster(
        broadcast.clone(),
        tofnd_config,
        cosmos_client.clone(),
        pub_key,
    )
    .await?;

    broadcaster
        .broadcast(vec![tx].try_into().expect("must be non-empty"))
        .map_err(|err| err.change_context(Error::Broadcaster))
        .and_then(|res| handle_tx_result(broadcast, cosmos_client, res, skip_confirmation))
        .await
}

async fn instantiate_broadcaster(
    broadcaster_config: broadcaster_v2::Config,
    tofnd_config: tofnd::Config,
    cosmos_client: cosmos::CosmosGrpcClient,
    pub_key: CosmosPublicKey,
) -> Result<
    broadcaster_v2::BroadcasterTask<
        cosmos::CosmosGrpcClient,
        Pin<Box<broadcaster_v2::MsgQueue>>,
        MultisigClient,
    >,
    Error,
> {
    let multisig_client = MultisigClient::new(
        tofnd_config.party_uid,
        tofnd_config.url.as_str(),
        tofnd_config.timeout,
    )
    .await
    .change_context(Error::Connection)
    .attach_printable(tofnd_config.url)?;

    let broadcaster = broadcaster_v2::Broadcaster::new(
        cosmos_client.clone(),
        broadcaster_config.chain_id,
        pub_key,
    )
    .await
    .change_context(Error::Broadcaster)?;
    let (msg_queue, _) = broadcaster_v2::MsgQueue::new_msg_queue_and_client(
        broadcaster.clone(),
        broadcaster_config.queue_cap,
        broadcaster_config.batch_gas_limit,
        broadcaster_config.broadcast_interval,
    );
    let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();
    let broadcaster_task = broadcaster_v2::BroadcasterTask::builder()
        .broadcaster(broadcaster)
        .msg_queue(msg_queue)
        .signer(multisig_client.clone())
        .key_id(tofnd_config.key_uid.clone())
        .gas_adjustment(broadcaster_config.gas_adjustment)
        .gas_price(broadcaster_config.gas_price)
        .monitoring_client(monitoring_client)
        .build()
        .await
        .change_context(Error::Broadcaster)?;

    Ok(broadcaster_task)
}

async fn handle_tx_result(
    broadcaster_config: broadcaster_v2::Config,
    cosmos_client: cosmos::CosmosGrpcClient,
    res: TxResponse,
    skip_confirmation: bool,
) -> Result<String, Error> {
    if skip_confirmation {
        return Ok(res.txhash);
    }

    confirm_tx(broadcaster_config, cosmos_client, res.txhash).await
}

async fn confirm_tx(
    broadcaster_config: broadcaster_v2::Config,
    cosmos_client: cosmos::CosmosGrpcClient,
    tx_hash: String,
) -> Result<String, Error> {
    let retry_policy = RetryPolicy::repeat_constant(
        broadcaster_config.tx_fetch_interval,
        broadcaster_config
            .tx_fetch_max_retries
            .saturating_add(1)
            .into(),
    );
    let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();

    broadcaster_v2::confirm_tx(&cosmos_client, tx_hash, retry_policy, &monitoring_client)
        .await
        .map(|res| res.txhash)
        .change_context(Error::TxConfirmation)
}
