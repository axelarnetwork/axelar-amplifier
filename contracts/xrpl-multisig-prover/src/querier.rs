use axelar_wasm_std::VerificationStatus;
use cosmwasm_schema::serde::de::DeserializeOwned;
use cosmwasm_schema::serde::Serialize;
use cosmwasm_std::{to_json_binary, QuerierWrapper, QueryRequest, Uint64, WasmQuery};
use interchain_token_service::TokenId;
use multisig::key::PublicKey;
use multisig::multisig::Multisig;
use router_api::{ChainNameRaw, CrossChainId, Message};
use service_registry::{Service, WeightedVerifier};
use xrpl_types::msg::XRPLMessage;
use xrpl_types::types::XRPLToken;
use xrpl_voting_verifier::msg::MessageStatus;

use crate::error::ContractError;
use crate::state::Config;

fn query<U, T>(
    querier: QuerierWrapper,
    contract_addr: String,
    query_msg: &T,
) -> Result<U, ContractError>
where
    U: DeserializeOwned,
    T: Serialize + ?Sized,
{
    querier
        .query(&QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr,
            msg: to_json_binary(&query_msg)?,
        }))
        .map_err(ContractError::from)
}

pub struct Querier<'a> {
    querier: QuerierWrapper<'a>,
    config: Config,
}

impl<'a> Querier<'a> {
    pub fn new(querier: QuerierWrapper<'a>, config: Config) -> Self {
        Self { querier, config }
    }

    pub fn service(&self) -> Result<Service, ContractError> {
        query(
            self.querier,
            self.config.service_registry.to_string(),
            &service_registry::msg::QueryMsg::Service {
                service_name: self.config.service_name.clone(),
            },
        )
    }

    pub fn active_verifiers(&self) -> Result<Vec<WeightedVerifier>, ContractError> {
        query(
            self.querier,
            self.config.service_registry.to_string(),
            &service_registry::msg::QueryMsg::ActiveVerifiers {
                service_name: self.config.service_name.clone(),
                chain_name: self.config.chain_name.clone(),
            },
        )
    }

    pub fn public_key(&self, verifier_address: String) -> Result<PublicKey, ContractError> {
        query(
            self.querier,
            self.config.multisig.to_string(),
            &multisig::msg::QueryMsg::PublicKey {
                verifier_address,
                key_type: multisig::key::KeyType::Ecdsa,
            },
        )
    }

    pub fn outgoing_message(&self, cc_id: &CrossChainId) -> Result<Message, ContractError> {
        let messages: Vec<Message> = query(
            self.querier,
            self.config.gateway.to_string(),
            &xrpl_gateway::msg::QueryMsg::OutgoingMessages(vec![cc_id.clone()]),
        )?;
        messages
            .first()
            .cloned()
            .ok_or(ContractError::InvalidMessageId(
                cc_id.message_id.to_string(),
            ))
    }

    pub fn token_instance_decimals(
        &self,
        chain_name: ChainNameRaw,
        token_id: TokenId,
    ) -> Result<u8, ContractError> {
        let decimals: u8 = query(
            self.querier,
            self.config.gateway.to_string(),
            &xrpl_gateway::msg::QueryMsg::TokenInstanceDecimals {
                chain_name,
                token_id,
            },
        )?;
        Ok(decimals)
    }

    pub fn xrpl_token(&self, token_id: TokenId) -> Result<XRPLToken, ContractError> {
        let token_info: XRPLToken = query(
            self.querier,
            self.config.gateway.to_string(),
            &xrpl_gateway::msg::QueryMsg::XrplToken(token_id),
        )?;
        Ok(token_info)
    }

    pub fn xrp_token_id(&self) -> Result<TokenId, ContractError> {
        query(
            self.querier,
            self.config.gateway.to_string(),
            &xrpl_gateway::msg::QueryMsg::XrpTokenId,
        )
    }

    pub fn message_status(
        &self,
        message: XRPLMessage,
    ) -> Result<VerificationStatus, ContractError> {
        let messages_status: Vec<MessageStatus> = query(
            self.querier,
            self.config.voting_verifier.to_string(),
            &xrpl_voting_verifier::msg::QueryMsg::MessagesStatus(vec![message]),
        )?;
        let message_status = messages_status
            .first()
            .ok_or(ContractError::MessageStatusNotFound)?;
        Ok(message_status.status)
    }

    pub fn multisig(&self, multisig_session_id: &Uint64) -> Result<Multisig, ContractError> {
        let query_msg = multisig::msg::QueryMsg::Multisig {
            session_id: *multisig_session_id,
        };
        query(self.querier, self.config.multisig.to_string(), &query_msg)
    }
}
