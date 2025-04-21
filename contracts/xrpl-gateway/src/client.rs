use axelar_wasm_std::nonempty;
use axelar_wasm_std::vec::VecExt;
use cosmwasm_std::CosmosMsg;
use error_stack::ResultExt;
use interchain_token_service::TokenId;
use router_api::{ChainNameRaw, CrossChainId, Message};
use xrpl_types::msg::{XRPLCallContractMessage, XRPLInterchainTransferMessage, XRPLMessage};
use xrpl_types::types::XRPLToken;

use crate::msg::{ExecuteMsg, InterchainTransfer, QueryMsg};

type Result<T> = error_stack::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    #[error(
        "failed to query interchain transfer for message {message:?} with payload {payload:?}"
    )]
    InterchainTransfer {
        message: XRPLInterchainTransferMessage,
        payload: Option<nonempty::HexBinary>,
    },

    #[error("failed to query call contract for message {message:?} with payload {payload:?}")]
    CallContract {
        message: XRPLCallContractMessage,
        payload: nonempty::HexBinary,
    },

    #[error("failed to query linked token id for xrpl token: {0}")]
    LinkedTokenId(XRPLToken),

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

    #[error("failed to query token id for xrpl token: {0}")]
    XrplTokenId(XRPLToken),

    #[error("failed to query xrp token id")]
    XrpTokenId,
}

impl From<QueryMsg> for Error {
    fn from(value: QueryMsg) -> Self {
        match value {
            QueryMsg::InterchainTransfer { message, payload } => {
                Error::InterchainTransfer { message, payload }
            }
            QueryMsg::CallContract { message, payload } => Error::CallContract { message, payload },
            QueryMsg::LinkedTokenId(token_id) => Error::LinkedTokenId(token_id),
            QueryMsg::OutgoingMessages(message_ids) => Error::OutgoingMessages(message_ids),
            QueryMsg::TokenInstanceDecimals {
                chain_name,
                token_id,
            } => Error::TokenInstanceDecimals {
                chain_name,
                token_id,
            },
            QueryMsg::XrplToken(token_id) => Error::XrplToken(token_id),
            QueryMsg::XrplTokenId(token) => Error::XrplTokenId(token),
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
        let msg = QueryMsg::InterchainTransfer { message, payload };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }

    pub fn linked_token_id(&self, xrpl_token: XRPLToken) -> Result<TokenId> {
        let msg = QueryMsg::LinkedTokenId(xrpl_token);
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
    use axelar_wasm_std::msg_id::HexTxHash;
    use axelar_wasm_std::nonempty;
    use cosmwasm_std::testing::{MockApi, MockQuerier};
    use cosmwasm_std::{
        from_json, to_json_binary, Addr, HexBinary, QuerierWrapper, SystemError, WasmQuery,
    };
    use interchain_token_service::TokenId;
    use router_api::{CrossChainId, Message};
    use xrpl_types::msg::XRPLInterchainTransferMessage;
    use xrpl_types::types::{XRPLPaymentAmount, XRPLToken};

    use crate::client::Client;
    use crate::msg::{InterchainTransfer, MessageWithPayload, QueryMsg};

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

    #[test]
    fn query_xrp_token_id_should_return_error_when_query_errors() {
        let (querier, addr) = setup_queries_to_fail();

        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.xrp_token_id();
        assert!(res.is_err());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_xrp_token_id_should_return_xrp_token_id() {
        let (querier, addr) = setup_queries_to_succeed();

        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.xrp_token_id();
        assert!(res.is_ok());
        goldie::assert!(res.unwrap().to_string());
    }

    #[test]
    fn query_token_instance_decimals_should_return_error_when_query_errors() {
        let (querier, addr) = setup_queries_to_fail();

        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.token_instance_decimals("xrpl".parse().unwrap(), TokenId::new([0; 32]));
        assert!(res.is_err());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_token_instance_decimals_should_return_token_instance_decimals() {
        let (querier, addr) = setup_queries_to_succeed();

        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.token_instance_decimals("xrpl".parse().unwrap(), TokenId::new([0; 32]));
        assert!(res.is_ok());
        goldie::assert_json!(res.unwrap());
    }

    #[test]
    fn query_xrpl_token_should_return_error_when_query_errors() {
        let (querier, addr) = setup_queries_to_fail();

        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.xrpl_token(TokenId::new([2; 32]));
        assert!(res.is_err());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_xrpl_token_should_return_xrpl_token() {
        let (querier, addr) = setup_queries_to_succeed();

        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.xrpl_token(TokenId::new([2; 32]));
        assert!(res.is_ok());
        goldie::assert_json!(res.unwrap());
    }

    #[test]
    fn query_linked_token_id_should_return_error_when_query_errors() {
        let (querier, addr) = setup_queries_to_fail();

        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.linked_token_id(XRPLToken {
            issuer: "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh".parse().unwrap(),
            currency: "USD".to_string().try_into().unwrap(),
        });
        assert!(res.is_err());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_linked_token_id_should_return_linked_token_id() {
        let (querier, addr) = setup_queries_to_succeed();

        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.linked_token_id(XRPLToken {
            issuer: "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh".parse().unwrap(),
            currency: "USD".to_string().try_into().unwrap(),
        });
        assert!(res.is_ok());
        goldie::assert!(res.unwrap().to_string());
    }

    #[test]
    fn query_interchain_transfer_should_return_error_when_query_errors() {
        let (querier, addr) = setup_queries_to_fail();

        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.interchain_transfer(
            XRPLInterchainTransferMessage {
                tx_id: HexTxHash::new([0; 32]),
                source_address: "raNVNWvhUQzFkDDTdEw3roXRJfMJFVJuQo".parse().unwrap(),
                destination_chain: "Avalanche".parse().unwrap(),
                destination_address: nonempty::String::try_from(
                    "95181d16cfb23Bc493668C17d973F061e30F2EAF",
                )
                .unwrap(),
                payload_hash: None,
                transfer_amount: XRPLPaymentAmount::Drops(100000),
                gas_fee_amount: XRPLPaymentAmount::Drops(10),
            },
            None,
        );
        assert!(res.is_err());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_interchain_transfer_should_return_interchain_transfer() {
        let (querier, addr) = setup_queries_to_succeed();

        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();
        let res = client.interchain_transfer(
            XRPLInterchainTransferMessage {
                tx_id: HexTxHash::new([0; 32]),
                source_address: "raNVNWvhUQzFkDDTdEw3roXRJfMJFVJuQo".parse().unwrap(),
                destination_chain: "Avalanche".parse().unwrap(),
                destination_address: nonempty::String::try_from(
                    "95181d16cfb23Bc493668C17d973F061e30F2EAF",
                )
                .unwrap(),
                payload_hash: None,
                transfer_amount: XRPLPaymentAmount::Drops(100000),
                gas_fee_amount: XRPLPaymentAmount::Drops(10),
            },
            None,
        );
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
                    QueryMsg::XrpTokenId => {
                        Ok(to_json_binary(&TokenId::new([0; 32])).into()).into()
                    },
                    QueryMsg::TokenInstanceDecimals { .. } => {
                        Ok(to_json_binary(&18u8).into()).into()
                    },
                    QueryMsg::XrplToken(_) => {
                        Ok(to_json_binary(&XRPLToken {
                            issuer: "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh".parse().unwrap(),
                            currency: "USD".to_string().try_into().unwrap(),
                        }).into()).into()
                    },
                    QueryMsg::LinkedTokenId(_) => {
                        Ok(to_json_binary(&TokenId::new([2; 32])).into()).into()
                    },
                    QueryMsg::InterchainTransfer { .. } => {
                        Ok(to_json_binary(&InterchainTransfer {
                            message_with_payload: Some(MessageWithPayload {
                                message: Message {
                                    cc_id: CrossChainId {
                                        source_chain: "xrpl".parse().unwrap(),
                                        message_id: "0x13548ac28fe95805ad2b8b824472d08e3b45cbc023a5a45a912f11ea98f81e97"
                                            .parse()
                                            .unwrap(),
                                    },
                                    source_address: "foobar".parse().unwrap(),
                                    destination_chain: "xrpl".parse().unwrap(),
                                    destination_address: "foobar".parse().unwrap(),
                                    payload_hash: [0u8; 32],
                                },
                                payload: nonempty::HexBinary::try_from(HexBinary::from_hex("abcd1234").unwrap()).unwrap(),
                            }),
                            token_id: TokenId::new([0; 32]),
                        })
                        .into()).into()
                    },
                    _ => panic!("unexpected query: {:?}", msg),
                }
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, MockApi::default().addr_make(addr))
    }
}
