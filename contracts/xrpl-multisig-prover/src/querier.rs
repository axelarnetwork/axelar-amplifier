use std::str::FromStr;

use connection_router_api::{ChainName, CrossChainId, Message};
#[cfg(not(feature = "library"))]
use cosmwasm_schema::serde::{de::DeserializeOwned, Serialize};
use cosmwasm_std::{
    to_json_binary, QueryRequest, WasmQuery, QuerierWrapper, Uint64,
};
use multisig::{key::PublicKey, msg::Multisig};
use axelar_wasm_std::VerificationStatus;

use crate::{
    error::ContractError,
    state::Config,
};

use service_registry::state::WeightedWorker;

pub const XRPL_CHAIN_NAME: &str = "XRPL";

fn query<U, T>(querier: QuerierWrapper, contract_addr: String, query_msg: &T) -> Result<U, ContractError>
where U: DeserializeOwned, T: Serialize + ?Sized {
    querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr,
        msg: to_json_binary(&query_msg)?,
    })).map_err(ContractError::from)
}

pub struct Querier<'a> {
    querier: QuerierWrapper<'a>,
    config: Config,
}

impl<'a> Querier<'a> {
    pub fn new(querier: QuerierWrapper<'a>, config: Config) -> Self {
        Self {
            querier,
            config,
        }
    }

    pub fn get_active_workers(&self) -> Result<Vec<WeightedWorker>, ContractError> {
        query(self.querier, self.config.service_registry.to_string(),
            &service_registry::msg::QueryMsg::GetActiveWorkers {
                service_name: self.config.service_name.clone(),
                chain_name: ChainName::from_str(XRPL_CHAIN_NAME).unwrap(),
            },
        )
    }

    pub fn get_public_key(&self, worker_address: String) -> Result<PublicKey, ContractError> {
        query(self.querier, self.config.axelar_multisig.to_string(),
            &multisig::msg::QueryMsg::GetPublicKey {
                worker_address,
                key_type: self.config.key_type,
            },
        )
    }

    pub fn get_message(&self, message_id: &CrossChainId) -> Result<Message, ContractError> {
        let messages: Vec<Message> = query(self.querier, self.config.gateway.to_string(),
            &gateway_api::msg::QueryMsg::GetOutgoingMessages {
                message_ids: vec![message_id.clone()],
            }
        )?;
        messages.first().cloned().ok_or(ContractError::InvalidMessageID(message_id.id.to_string()))
    }

    pub fn get_message_status(&self, message: Message) -> Result<VerificationStatus, ContractError> {
        let statuses: Vec<(CrossChainId, VerificationStatus)> = query(self.querier, self.config.voting_verifier.to_string(),
            &voting_verifier::msg::QueryMsg::GetMessagesStatus {
                messages: vec![message],
            }
        )?;
        let status = statuses.first().ok_or(ContractError::GenericError("failed fetching message status".to_owned()))?;
        Ok(status.1)
    }

    pub fn get_multisig_session(&self, multisig_session_id: &Uint64) -> Result<Multisig, ContractError> {
        let query_msg = multisig::msg::QueryMsg::GetMultisig {
            session_id: *multisig_session_id,
        };
        query(self.querier, self.config.axelar_multisig.to_string(), &query_msg)
    }
}
