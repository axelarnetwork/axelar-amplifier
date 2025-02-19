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
}

pub fn pick<'a, C>(finalizer_type: &'a Finalization, rpc_client: &'a C) -> Box<dyn Finalizer + 'a>
where
    C: XRPLClient + Send + Sync,
{
    match finalizer_type {
        Finalization::ValidatedLedger => Box::new(ValidatedLedgerFinalizer::new(rpc_client)),
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
