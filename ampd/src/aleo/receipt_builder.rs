use std::str::FromStr;

use aleo_gateway_types::{ContractCall, SignersRotated};
use aleo_string_encoder::StringEncoder;
use error_stack::{ensure, Report, Result, ResultExt};
use snarkvm::prelude::{Network, ProgramID, ToBytes, Value};

use crate::aleo::error::Error;
use crate::aleo::http_client::ClientTrait;
use crate::aleo::utils::*;

mod call_contract;
mod receipt;

pub use call_contract::CallContractReceipt;
pub use receipt::Receipt;

// State types for the type state pattern
/// Initial state of the builder
#[derive(Debug)]
pub struct Initial;

/// State after finding the transaction ID from a transition ID
#[derive(Debug)]
pub struct StateTransactionId<N: Network> {
    transaction_id: N::TransactionID,
}

/// State after retrieving the transaction
#[derive(Debug)]
pub struct StateTransactionFound {
    transaction: aleo_utils::block_processor::OwnedTransaction,
}

/// State after finding the transition in the transaction
#[derive(Debug)]
pub struct StateTransitionFound {
    transaction: aleo_utils::block_processor::OwnedTransaction,
    transition: aleo_utils::block_processor::OwnedTransition,
}

/// Builder for verifying Aleo receipts using a type-state pattern
///
/// The builder progresses through multiple states to verify a receipt:
/// 1. Initial → Find transaction ID from transition ID
/// 2. StateTransactionId → Retrieve transaction
/// 3. StateTransactionFound → Find target transition
/// 4. StateTransitionFound → Verify receipt (CallContract or SignerRotation)
pub struct ReceiptBuilder<'a, N: Network, C: ClientTrait<N>, S> {
    client: &'a C,
    target_contract: &'a ProgramID<N>,
    state: S,
}

impl<'a, N, C> ReceiptBuilder<'a, N, C, Initial>
where
    N: Network,
    C: ClientTrait<N> + Send + Sync + 'static,
{
    pub fn new(client: &'a C, target_contract: &'a ProgramID<N>) -> Result<Self, Error> {
        Ok(Self {
            client,
            target_contract,
            state: Initial,
        })
    }

    pub async fn get_transaction_id(
        self,
        transition_id: &N::TransitionID,
    ) -> Result<ReceiptBuilder<'a, N, C, StateTransactionId<N>>, Error> {
        let transaction_id = self
            .client
            .find_transaction(transition_id)
            .await
            .change_context(Error::TransitionNotFound(transition_id.to_string()))?;

        let transaction = transaction_id.trim_matches('"');

        Ok(ReceiptBuilder {
            client: self.client,
            target_contract: self.target_contract,
            state: StateTransactionId {
                transaction_id: N::TransactionID::from_str(transaction)
                    .map_err(|_| Report::new(Error::TransitionNotFound(transaction.to_string())))?,
            },
        })
    }
}

impl<'a, N, C> ReceiptBuilder<'a, N, C, StateTransactionId<N>>
where
    N: Network,
    C: ClientTrait<N> + Send + Sync + 'static,
{
    /// Retrieve the transaction from the transaction ID and transition to the next state
    pub async fn get_transaction(
        self,
    ) -> Result<ReceiptBuilder<'a, N, C, StateTransactionFound>, Error> {
        let transaction = self
            .client
            .get_transaction(&self.state.transaction_id)
            .await
            .change_context(Error::TransactionNotFound(
                self.state.transaction_id.to_string(),
            ))?;

        Ok(ReceiptBuilder {
            client: self.client,
            target_contract: self.target_contract,
            state: StateTransactionFound { transaction },
        })
    }
}

impl<'a, N, C> ReceiptBuilder<'a, N, C, StateTransactionFound>
where
    N: Network,
    C: ClientTrait<N> + Send + Sync + 'static,
{
    pub fn get_transition(self) -> Result<ReceiptBuilder<'a, N, C, StateTransitionFound>, Error> {
        let execution = self.state.transaction.execution.as_ref().ok_or(
            Error::TransitionNotFoundInTransaction(self.target_contract.to_string()),
        )?;

        let transition = execution
            .transitions
            .iter()
            .find(|t| t.program == self.target_contract.to_string())
            .ok_or(Error::TransitionNotFoundInTransaction(
                self.target_contract.to_string(),
            ))?
            .clone();

        Ok(ReceiptBuilder {
            client: self.client,
            target_contract: self.target_contract,
            state: StateTransitionFound {
                transaction: self.state.transaction,
                transition: transition.into_owned(),
            },
        })
    }
}

impl<C, N> ReceiptBuilder<'_, N, C, StateTransitionFound>
where
    N: Network,
    C: ClientTrait<N> + Send + Sync + 'static,
{
    pub fn check_call_contract(self) -> Result<Receipt<N, CallContractReceipt<N>>, Error> {
        let outputs = self.state.transition.outputs;
        ensure!(outputs.len() == 1, Error::CallContractNotFound);

        // The call contract from call contract call
        let call_contract: ContractCall<N> = outputs
            .first()
            .map(read_call_contract)
            .ok_or(Error::CallContractNotFound)??;

        let payload = self
            .state
            .transaction
            .execution
            .as_ref()
            .ok_or(Error::CallContractNotFound)?
            .transitions
            .iter()
            .find_map(|t| {
                if t.id != self.state.transition.id && t.program != self.target_contract.to_string()
                {
                    find_call_contract_in_outputs::<N>(&t.outputs, call_contract.payload_hash)
                } else {
                    None
                }
            })
            .ok_or(Error::CallContractNotFound)?;

        let payload_plaintext_bytes = Value::<N>::from_str(&payload)
            .and_then(|p| p.to_bytes_le())
            .map_err(|_| Report::new(Error::PayloadHash(payload.to_string())))?;

        let chain_name = StringEncoder::from_slice(&call_contract.destination_chain)
            .decode()
            .change_context(Error::InvalidChainName)?;

        Ok(Receipt::Found(CallContractReceipt {
            transition: N::TransitionID::from_str(&self.state.transition.id).map_err(|_| {
                Report::new(Error::TransitionNotFound(
                    self.state.transition.id.to_string(),
                ))
            })?,
            destination_address: StringEncoder::from_slice(&call_contract.destination_address)
                .decode()
                .change_context(Error::InvalidDestinationAddress)?,
            destination_chain: chain_name
                .try_into()
                .map_err(|_| Report::new(Error::InvalidChainName))?,
            source_address: call_contract.caller,
            payload: payload_plaintext_bytes,
        }))
    }

    pub fn check_signer_rotation(self) -> Result<Receipt<N, SignersRotated<N>>, Error> {
        let outputs = self.state.transition.outputs;
        let signer_rotation =
            find_signers_rotated_in_outputs(&outputs).ok_or(Error::SignerRotationNotFound)?;
        let scm = self.state.transition.scm;

        let signers_rotation_calls = self
            .state
            .transaction
            .execution
            .as_ref()
            .ok_or(Error::SignerRotationNotFound)?
            .transitions
            .iter()
            .filter(|t| {
                t.scm == scm
                    && t.program == self.target_contract.to_string()
                    && t.id != self.state.transition.id
            })
            .count();

        ensure!(signers_rotation_calls == 1, Error::SignerRotationNotFound);

        Ok(Receipt::Found(signer_rotation))
    }
}
