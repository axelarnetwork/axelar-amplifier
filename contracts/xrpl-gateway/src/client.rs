use axelar_wasm_std::nonempty;
use axelar_wasm_std::vec::VecExt;
use cosmwasm_std::{Addr, CosmosMsg};
use error_stack::ResultExt;
use interchain_token_service::TokenId;
use router_api::{ChainNameRaw, CrossChainId, Message};
use xrpl_types::msg::{XRPLMessage, XRPLInterchainTransferMessage};
use xrpl_types::types::XRPLToken;

use crate::msg::{ExecuteMsg, InterchainTransfer, QueryMsg};

type Result<T> = error_stack::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    #[error("failed to query interchain transfer for message {message:?} with payload {payload:?}")]
    InterchainTransfer {
        message: XRPLInterchainTransferMessage,
        payload: Option<nonempty::HexBinary>,
    },

    #[error("failed to query linked token id. salt: {salt:?}, deployer: {deployer}")]
    LinkedTokenId { salt: [u8; 32], deployer: Addr },

    #[error("failed to query gateway for outgoing messages. message ids: {0:?}")]
    OutgoingMessages(Vec<CrossChainId>),

    #[error(
        "failed to query token instance decimals. chain name: {chain_name}, token id: {token_id}"
    )]
    TokenInstanceDecimals {
        chain_name: ChainNameRaw,
        token_id: TokenId,
    },

    #[error("failed to query xrpl token for token id: {0}")]
    XrplToken(TokenId),

    #[error("failed to query xrp token id")]
    XrpTokenId,
}

impl From<QueryMsg> for Error {
    fn from(value: QueryMsg) -> Self {
        match value {
            QueryMsg::InterchainTransfer {
                message,
                payload,
            } => Error::InterchainTransfer {
                message,
                payload,
            },
            QueryMsg::LinkedTokenId { salt, deployer } => Error::LinkedTokenId { salt, deployer },
            QueryMsg::OutgoingMessages(message_ids) => Error::OutgoingMessages(message_ids),
            QueryMsg::TokenInstanceDecimals {
                chain_name,
                token_id,
            } => Error::TokenInstanceDecimals {
                chain_name,
                token_id,
            },
            QueryMsg::XrplToken(token_id) => Error::XrplToken(token_id),
            QueryMsg::XrpTokenId => Error::XrpTokenId,
        }
    }
}

impl<'a> From<client::ContractClient<'a, ExecuteMsg, QueryMsg>> for Client<'a> {
    fn from(client: client::ContractClient<'a, ExecuteMsg, QueryMsg>) -> Self {
        Client { client }
    }
}

pub struct Client<'a> {
    client: client::ContractClient<'a, ExecuteMsg, QueryMsg>,
}

impl Client<'_> {
    pub fn interchain_transfer(
        &self,
        message: XRPLInterchainTransferMessage,
        payload: Option<nonempty::HexBinary>,
    ) -> Result<InterchainTransfer> {
        let msg = QueryMsg::InterchainTransfer {
            message,
            payload,
        };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }

    pub fn linked_token_id(&self, salt: [u8; 32], deployer: Addr) -> Result<TokenId> {
        let msg = QueryMsg::LinkedTokenId { salt, deployer };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }

    pub fn outgoing_messages(&self, message_ids: Vec<CrossChainId>) -> Result<Vec<Message>> {
        let msg = QueryMsg::OutgoingMessages(message_ids);
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }

    pub fn token_instance_decimals(
        &self,
        chain_name: ChainNameRaw,
        token_id: TokenId,
    ) -> Result<u8> {
        let msg = QueryMsg::TokenInstanceDecimals {
            chain_name,
            token_id,
        };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }

    pub fn xrpl_token(&self, token_id: TokenId) -> Result<XRPLToken> {
        let msg = QueryMsg::XrplToken(token_id);
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }

    pub fn xrp_token_id(&self) -> Result<TokenId> {
        let msg = QueryMsg::XrpTokenId;
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }

    pub fn route_messages(&self, messages: Vec<Message>) -> Option<CosmosMsg> {
        messages
            .to_none_if_empty()
            .map(|messages| self.client.execute(&ExecuteMsg::RouteMessages(messages)))
    }

    pub fn verify_messages(&self, messages: Vec<XRPLMessage>) -> Option<CosmosMsg> {
        messages
            .to_none_if_empty()
            .map(|messages| self.client.execute(&ExecuteMsg::VerifyMessages(messages)))
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{MockApi, MockQuerier};
    use cosmwasm_std::{from_json, to_json_binary, Addr, QuerierWrapper, SystemError, WasmQuery};
    use router_api::{CrossChainId, Message};

    use crate::client::Client;
    use crate::msg::QueryMsg;

    #[test]
    fn query_outgoing_messages_should_return_error_when_query_errors() {
        let (querier, addr) = setup_queries_to_fail();

        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let cc_id = CrossChainId {
            source_chain: "xrpl".parse().unwrap(),
            message_id: "0x13548ac28fe95805ad2b8b824472d08e3b45cbc023a5a45a912f11ea98f81e97"
                .parse()
                .unwrap(),
        };
        let res = client.outgoing_messages(vec![cc_id.clone()]);
        assert!(res.is_err());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_outgoing_messages_should_return_outgoing_messages() {
        let (querier, addr) = setup_queries_to_succeed();

        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let cc_id = CrossChainId {
            source_chain: "xrpl".parse().unwrap(),
            message_id: "0x13548ac28fe95805ad2b8b824472d08e3b45cbc023a5a45a912f11ea98f81e97"
                .parse()
                .unwrap(),
        };
        let res = client.outgoing_messages(vec![cc_id.clone()]);
        assert!(res.is_ok());
        goldie::assert_json!(res.unwrap());
    }

    fn setup_queries_to_fail() -> (MockQuerier, Addr) {
        let addr = "xrpl-gateway";

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart {
                contract_addr,
                msg: _,
            } if contract_addr == MockApi::default().addr_make(addr).as_str() => {
                Err(SystemError::Unknown {}).into() // simulate cryptic error seen in production
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, MockApi::default().addr_make(addr))
    }

    fn setup_queries_to_succeed() -> (MockQuerier, Addr) {
        let addr = "xrpl_gateway";

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart { contract_addr, msg }
                if contract_addr == MockApi::default().addr_make(addr).as_str() =>
            {
                let msg = from_json::<QueryMsg>(msg).unwrap();
                match msg {
                    QueryMsg::OutgoingMessages(cc_ids) => Ok(to_json_binary(
                        &cc_ids
                            .into_iter()
                            .map(|cc_id| Message {
                                cc_id,
                                source_address: "foobar".parse().unwrap(),
                                destination_chain: "xrpl".parse().unwrap(),
                                destination_address: "foobar".parse().unwrap(),
                                payload_hash: [0u8; 32],
                            })
                            .collect::<Vec<Message>>(),
                    )
                    .into())
                    .into(),
                    _ => panic!("unexpected query: {:?}", msg),
                }
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, MockApi::default().addr_make(addr))
    }
}
