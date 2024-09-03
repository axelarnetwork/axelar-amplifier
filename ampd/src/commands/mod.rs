use clap::Subcommand;
use cosmrs::proto::cosmos::auth::v1beta1::query_client::QueryClient as AuthQueryClient;
use cosmrs::proto::cosmos::bank::v1beta1::query_client::QueryClient as BankQueryClient;
use cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse;
use cosmrs::proto::cosmos::tx::v1beta1::service_client::ServiceClient;
use cosmrs::proto::Any;
use cosmrs::AccountId;
use error_stack::{report, FutureExt, Result, ResultExt};
use futures::TryFutureExt;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{Receiver, Sender};
use valuable::Valuable;

use crate::asyncutil::future::RetryPolicy;
use crate::broadcaster::Broadcaster;
use crate::config::{Config as AmpdConfig, Config};
use crate::tofnd::grpc::{Multisig, MultisigClient};
use crate::types::{PublicKey, TMAddress};
use crate::{broadcaster, tofnd, Error, PREFIX};

pub mod bond_verifier;
pub mod claim_stake;
pub mod daemon;
pub mod deregister_chain_support;
pub mod register_chain_support;
pub mod register_public_key;
pub mod send_tokens;
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

async fn verifier_pub_key(config: tofnd::Config) -> Result<PublicKey, Error> {
    MultisigClient::new(config.party_uid, config.url.clone())
        .await
        .change_context(Error::Connection)
        .attach_printable(config.url.clone())?
        .keygen(&config.key_uid, tofnd::Algorithm::Ecdsa)
        .await
        .change_context(Error::Tofnd)
}

async fn broadcast_tx(
    config: AmpdConfig,
    tx: Any,
    pub_key: PublicKey,
) -> Result<TxResponse, Error> {
    let (confirmation_sender, mut confirmation_receiver) = tokio::sync::mpsc::channel(1);
    let (hash_to_confirm_sender, hash_to_confirm_receiver) = tokio::sync::mpsc::channel(1);

    let mut broadcaster = instantiate_broadcaster(
        config,
        pub_key,
        hash_to_confirm_receiver,
        confirmation_sender,
    )
    .await?;

    broadcaster
        .broadcast(vec![tx])
        .change_context(Error::Broadcaster)
        .and_then(|response| {
            hash_to_confirm_sender
                .send(response.txhash)
                .change_context(Error::Broadcaster)
        })
        .await?;

    confirmation_receiver
        .recv()
        .await
        .ok_or(report!(Error::TxConfirmation))
        .map(|tx| tx.response)
}

async fn instantiate_broadcaster(
    config: Config,
    pub_key: PublicKey,
    tx_hashes_to_confirm: Receiver<String>,
    confirmed_txs: Sender<broadcaster::confirm_tx::TxResponse>,
) -> Result<impl Broadcaster, Error> {
    let AmpdConfig {
        tm_grpc,
        broadcast,
        tofnd_config,
        ..
    } = config;
    let service_client = ServiceClient::connect(tm_grpc.to_string())
        .await
        .change_context(Error::Connection)
        .attach_printable(tm_grpc.clone())?;
    let auth_query_client = AuthQueryClient::connect(tm_grpc.to_string())
        .await
        .change_context(Error::Connection)
        .attach_printable(tm_grpc.clone())?;
    let bank_query_client = BankQueryClient::connect(tm_grpc.to_string())
        .await
        .change_context(Error::Connection)
        .attach_printable(tm_grpc)?;
    let multisig_client = MultisigClient::new(tofnd_config.party_uid, tofnd_config.url.clone())
        .await
        .change_context(Error::Connection)
        .attach_printable(tofnd_config.url)?;

    broadcaster::confirm_tx::TxConfirmer::new(
        service_client.clone(),
        RetryPolicy::RepeatConstant {
            sleep: broadcast.tx_fetch_interval,
            max_attempts: broadcast.tx_fetch_max_retries.saturating_add(1).into(),
        },
        tx_hashes_to_confirm,
        confirmed_txs,
    )
    .run()
    .await
    .change_context(Error::TxConfirmation)?;

    let basic_broadcaster = broadcaster::UnvalidatedBasicBroadcaster::builder()
        .client(service_client)
        .signer(multisig_client)
        .auth_query_client(auth_query_client)
        .bank_query_client(bank_query_client)
        .pub_key((tofnd_config.key_uid, pub_key))
        .config(broadcast)
        .address_prefix(PREFIX.to_string())
        .build()
        .validate_fee_denomination()
        .await
        .change_context(Error::Broadcaster)?;
    Ok(basic_broadcaster)
}
