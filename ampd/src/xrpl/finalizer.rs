use async_trait::async_trait;
use error_stack::{self, Report, ResultExt};
use mockall::automock;
use serde::{Deserialize, Serialize};

use super::error::Error;
use crate::xrpl::json_rpc::XRPLClient;

type Result<T> = error_stack::Result<T, Error>;

#[automock]
#[async_trait]
pub trait Finalizer: Send + Sync {
    async fn latest_validated_ledger_index(&self) -> Result<u32>;
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Default)]
pub enum Finalization {
    #[default]
    ValidatedLedger,
    ConfirmationHeight,
}

pub fn pick<'a, C, H>(
    finalizer_type: &'a Finalization,
    rpc_client: &'a C,
    confirmation_height: H,
) -> Box<dyn Finalizer + 'a>
where
    C: XRPLClient + Send + Sync,
    H: Into<u32>,
{
    match finalizer_type {
        Finalization::ValidatedLedger => Box::new(ValidatedLedgerFinalizer::new(rpc_client)),
        Finalization::ConfirmationHeight => Box::new(ConfirmationHeightFinalizer::new(
            rpc_client,
            confirmation_height,
        )),
    }
}

pub struct ValidatedLedgerFinalizer<'a, C>
where
    C: XRPLClient,
{
    rpc_client: &'a C,
}

impl<'a, C> ValidatedLedgerFinalizer<'a, C>
where
    C: XRPLClient,
{
    pub fn new(rpc_client: &'a C) -> Self {
        ValidatedLedgerFinalizer { rpc_client }
    }
}

#[async_trait]
impl<'a, C> Finalizer for ValidatedLedgerFinalizer<'a, C>
where
    C: XRPLClient + Send + Sync,
{
    async fn latest_validated_ledger_index(&self) -> Result<u32> {
        self.rpc_client
            .validated_ledger()
            .await
            .change_context(Error::JsonRPC)?
            .ledger_spec
            .ledger_index
            .ok_or_else(|| Report::new(Error::MissLedgerIndex))
    }
}

pub struct ConfirmationHeightFinalizer<'a, C>
where
    C: XRPLClient,
{
    rpc_client: &'a C,
    confirmation_height: u32,
}

impl<'a, C> ConfirmationHeightFinalizer<'a, C>
where
    C: XRPLClient,
{
    pub fn new<H>(rpc_client: &'a C, confirmation_height: H) -> Self
    where
        H: Into<u32>,
    {
        ConfirmationHeightFinalizer {
            rpc_client,
            confirmation_height: confirmation_height.into(),
        }
    }
}

#[async_trait]
impl<'a, C> Finalizer for ConfirmationHeightFinalizer<'a, C>
where
    C: XRPLClient + Send + Sync,
{
    async fn latest_validated_ledger_index(&self) -> Result<u32> {
        let ledger_index = self.rpc_client
            .validated_ledger()
            .await
            .change_context(Error::JsonRPC)?
            .ledger_spec
            .ledger_index
            .ok_or_else(|| Report::new(Error::MissLedgerIndex))?;

        // order of operations is important here when saturating, otherwise the finalization window could be cut short
        // if we add 1 afterwards
        Ok(ledger_index
            .saturating_add(1u32)
            .saturating_sub(self.confirmation_height))
    }
}
