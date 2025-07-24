use std::marker::PhantomData;
use std::ops::Deref;

use cosmwasm_std::{
    to_json_binary, Addr, Coin, CosmosMsg, CustomQuery, QuerierWrapper, QueryRequest, StdError,
    WasmMsg, WasmQuery,
};
use error_stack::Report;
use serde::de::DeserializeOwned;
use serde::Serialize;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    QueryFailed(#[from] StdError),
}

/// A client for interacting with Cosmos SDK-based blockchain modules.
///
/// This client provides low-level access to query and execute operations on a Cosmos SDK blockchain.
/// For more convenient interaction with smart contracts, use the [`ContractClient`] struct.
///
/// # Generic Parameters
///
/// * `M` - The execute message type for the blockchain module
/// * `Q` - The query message type for the blockchain module
///
/// These types are defined at the client level, so calls to [`CosmosClient::execute`] and [`CosmosClient::query`]
/// can enforce that the messages are of the correct type.
pub struct CosmosClient<'a, M, Q> {
    querier: QuerierWrapper<'a>,
    execute_msg_type: PhantomData<M>,
    query_msg_type: PhantomData<Q>,
}

impl<'a, M, Q> CosmosClient<'a, M, Q> {
    /// Creates a new `CosmosClient` instance.
    ///
    /// # Arguments
    ///
    /// * `querier` - A wrapper around the querier interface for blockchain queries
    pub fn new(querier: QuerierWrapper<'a>) -> Self {
        Self {
            querier,
            execute_msg_type: PhantomData,
            query_msg_type: PhantomData,
        }
    }

    /// Converts a message into a `CosmosMsg` for execution.
    ///
    /// # Arguments
    ///
    /// * `msg` - The message to convert into a `CosmosMsg`
    ///
    /// # Returns
    ///
    /// A `CosmosMsg` ready for execution
    pub fn execute<T>(&self, msg: M) -> CosmosMsg<T>
    where
        M: Into<CosmosMsg<T>>,
    {
        msg.into()
    }

    /// Executes a query against the blockchain.
    ///
    /// # Arguments
    ///
    /// * `msg` - The query message to execute
    ///
    /// # Returns
    ///
    /// A result containing the deserialized response or an error
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails or if deserialization fails
    pub fn query<R, C>(&self, msg: Q) -> error_stack::Result<R, Error>
    where
        R: DeserializeOwned,
        Q: Into<QueryRequest<C>>,
        C: CustomQuery,
    {
        QuerierWrapper::new(self.querier.deref())
            .query(&msg.into())
            .map_err(Into::into)
            .map_err(Report::new)
    }
}

/// A client for interacting with cosmwasm smart contracts.
///
/// This client provides a higher-level interface for executing and querying smart contracts
/// compared to the raw [`CosmosClient`]. It handles message serialization and contract address management.
///
/// # Generic Parameters
///
/// * `M` - The execute message type for the contract
/// * `Q` - The query message type for the contract
///
/// These types are defined at the client level, so calls to [`ContractClient::execute`] and [`ContractClient::query`]
/// can enforce that the messages are of the correct type.
pub struct ContractClient<'a, M, Q> {
    inner: CosmosClient<'a, WasmMsg, QueryRequest>,
    pub address: &'a Addr,
    execute_msg_type: PhantomData<M>,
    query_msg_type: PhantomData<Q>,
}

impl<'a, M, Q> ContractClient<'a, M, Q> {
    /// Creates a new `ContractClient` instance.
    ///
    /// # Arguments
    ///
    /// * `querier` - A wrapper around the querier interface for blockchain queries
    /// * `address` - The address of the smart contract to interact with
    pub fn new(querier: QuerierWrapper<'a>, address: &'a Addr) -> Self {
        Self {
            inner: CosmosClient::new(querier),
            address,
            execute_msg_type: PhantomData,
            query_msg_type: PhantomData,
        }
    }

    /// Creates an execute message for the contract without any funds.
    ///
    /// # Arguments
    ///
    /// * `msg` - The execute message to send to the contract
    ///
    /// # Returns
    ///
    /// A `CosmosMsg` ready for execution
    pub fn execute(&self, msg: &M) -> CosmosMsg
    where
        M: Serialize,
    {
        self.execute_wrapped(msg, None)
    }

    /// Creates an execute message for the contract with attached funds.
    ///
    /// # Arguments
    ///
    /// * `msg` - The execute message to send to the contract
    /// * `coin` - The funds to attach to the message
    ///
    /// # Returns
    ///
    /// A `CosmosMsg` ready for execution with attached funds
    pub fn execute_with_funds(&self, msg: &M, coin: Coin) -> CosmosMsg
    where
        M: Serialize,
    {
        self.execute_wrapped(msg, Some(coin))
    }

    /// Executes a message on behalf of an original sender using proxy semantics.
    ///
    /// # Arguments
    ///
    /// * `original_sender` - The address of the original sender to proxy for
    /// * `msg` - The execute message to send to the contract
    ///
    /// # Returns
    ///
    /// A `CosmosMsg` ready for execution with proxy information attached
    pub fn execute_as_proxy(&self, original_sender: Addr, msg: M) -> CosmosMsg
    where
        M: MsgFromProxy,
    {
        self.execute_wrapped(&msg.via_proxy(original_sender), None)
    }

    fn execute_wrapped(&self, msg: &impl Serialize, coin: Option<Coin>) -> CosmosMsg {
        self.inner.execute(WasmMsg::Execute {
            contract_addr: self.address.to_string(),
            msg: to_json_binary(msg).expect("msg should always be serializable"),
            funds: coin.into_iter().collect(),
        })
    }

    /// Executes a query against the contract.
    ///
    /// # Arguments
    ///
    /// * `msg` - The query message to send to the contract
    ///
    /// # Returns
    ///
    /// A result containing the deserialized response or an error
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails or if deserialization fails
    pub fn query<R>(&self, msg: &Q) -> error_stack::Result<R, Error>
    where
        Q: Serialize,
        R: DeserializeOwned,
    {
        self.inner.query(QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: self.address.to_string(),
            msg: to_json_binary(msg).expect("msg should always be serializable"),
        }))
    }
}

/// A trait for messages that can be executed via proxy.
///
/// This trait allows messages to be wrapped with proxy information,
/// enabling contracts to execute messages on behalf of other addresses.
pub trait MsgFromProxy {
    /// The type of the message after proxy information is added.
    type MsgWithOriginalSender: Serialize;
    /// Wraps the message with proxy information.
    ///
    /// # Arguments
    ///
    /// * `original_sender` - The address of the original sender
    ///
    /// # Returns
    ///
    /// A message wrapped with proxy information
    fn via_proxy(self, original_sender: Addr) -> Self::MsgWithOriginalSender;
}
