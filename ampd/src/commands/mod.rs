use clap::Subcommand;
use cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse;
use cosmrs::proto::Any;
use cosmrs::AccountId;
use error_stack::{report, FutureExt, Result, ResultExt};
use futures::TryFutureExt;
use serde::{Deserialize, Serialize};
use valuable::Valuable;

use crate::asyncutil::future::RetryPolicy;
use crate::broadcaster::confirm_tx::TxConfirmer;
use crate::broadcaster::Broadcaster;
use crate::config::{Config as AmpdConfig, Config};
use crate::tofnd::grpc::{Multisig, MultisigClient};
use crate::types::{CosmosPublicKey, TMAddress};
use crate::{broadcaster, cosmos, tofnd, Error, PREFIX};

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
    config: AmpdConfig,
    tx: Any,
    pub_key: CosmosPublicKey,
) -> Result<TxResponse, Error> {
    let (confirmation_sender, mut confirmation_receiver) = tokio::sync::mpsc::channel(1);
    let (hash_to_confirm_sender, hash_to_confirm_receiver) = tokio::sync::mpsc::channel(1);

    let (mut broadcaster, confirmer) = instantiate_broadcaster(config, pub_key).await?;

    broadcaster
        .broadcast(vec![tx])
        .change_context(Error::Broadcaster)
        .and_then(|response| {
            hash_to_confirm_sender
                .send(response.txhash)
                .change_context(Error::Broadcaster)
        })
        .await?;

    // drop the sender so the confirmer doesn't wait for more txs
    drop(hash_to_confirm_sender);

    confirmer
        .run(hash_to_confirm_receiver, confirmation_sender)
        .change_context(Error::TxConfirmation)
        .await?;

    confirmation_receiver
        .recv()
        .await
        .ok_or(report!(Error::TxConfirmation))
        .map(|tx| tx.response)
}

async fn instantiate_broadcaster(
    config: Config,
    pub_key: CosmosPublicKey,
) -> Result<(impl Broadcaster, TxConfirmer<cosmos::CosmosGrpcClient>), Error> {
    let AmpdConfig {
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
    let multisig_client = MultisigClient::new(
        tofnd_config.party_uid,
        tofnd_config.url.as_str(),
        tofnd_config.timeout,
    )
    .await
    .change_context(Error::Connection)
    .attach_printable(tofnd_config.url)?;

    let confirmer = TxConfirmer::new(
        cosmos_client.clone(),
        RetryPolicy::RepeatConstant {
            sleep: broadcast.tx_fetch_interval,
            max_attempts: broadcast.tx_fetch_max_retries.saturating_add(1).into(),
        },
    );

    let basic_broadcaster = broadcaster::UnvalidatedBasicBroadcaster::builder()
        .client(cosmos_client)
        .signer(multisig_client)
        .pub_key((tofnd_config.key_uid, pub_key))
        .config(broadcast)
        .address_prefix(PREFIX.to_string())
        .build()
        .validate_fee_denomination()
        .await
        .change_context(Error::Broadcaster)?;
    Ok((basic_broadcaster, confirmer))
}
