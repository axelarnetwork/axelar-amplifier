use std::collections::HashMap;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{CosmosMsg, HexBinary, Uint64};
use error_stack::{Result, ResultExt};
use router_api::ChainName;

use crate::key::{KeyType, PublicKey};
use crate::msg::{ExecuteMsg, QueryMsg};
use crate::multisig::Multisig;
use crate::verifier_set::VerifierSet;

#[derive(thiserror::Error)]
#[cw_serde]
pub enum Error {
    #[error("failed to query multisig contract for multisig session. session_id: {0}")]
    MultisigSession(Uint64),

    #[error("failed to query multisig contract for verifier set: verifier_set_id: {0}")]
    VerifierSet(String),

    #[error("failed to query multisig contract for verifier public key. verifier_address: {verifier_address}, key_type: {key_type}")]
    PublicKey {
        verifier_address: String,
        key_type: KeyType,
    },

    #[error("failed to query multisig contract for caller authorization. contract_address: {contract_address}, chain_name: {chain_name}")]
    IsCallerAuthorized {
        contract_address: String,
        chain_name: ChainName,
    },
}

impl<'a> From<client::ContractClient<'a, ExecuteMsg, QueryMsg>> for Client<'a> {
    fn from(client: client::ContractClient<'a, ExecuteMsg, QueryMsg>) -> Self {
        Client { client }
    }
}

impl From<QueryMsg> for Error {
    fn from(value: QueryMsg) -> Self {
        match value {
            QueryMsg::Multisig { session_id } => Error::MultisigSession(session_id),
            QueryMsg::VerifierSet { verifier_set_id } => Error::VerifierSet(verifier_set_id),
            QueryMsg::PublicKey {
                verifier_address,
                key_type,
            } => Error::PublicKey {
                verifier_address,
                key_type,
            },
            QueryMsg::IsCallerAuthorized {
                contract_address,
                chain_name,
            } => Error::IsCallerAuthorized {
                contract_address,
                chain_name,
            },
        }
    }
}

pub struct Client<'a> {
    client: client::ContractClient<'a, ExecuteMsg, QueryMsg>,
}

impl<'a> Client<'a> {
    pub fn start_signing_session(
        &self,
        verifier_set_id: String,
        msg: HexBinary,
        chain_name: ChainName,
        sig_verifier: Option<String>,
    ) -> CosmosMsg {
        self.client.execute(&ExecuteMsg::StartSigningSession {
            verifier_set_id,
            msg,
            chain_name,
            sig_verifier,
        })
    }

    pub fn submit_signature(&self, session_id: Uint64, signature: HexBinary) -> CosmosMsg {
        self.client.execute(&ExecuteMsg::SubmitSignature {
            session_id,
            signature,
        })
    }

    pub fn register_verifier_set(&self, verifier_set: VerifierSet) -> CosmosMsg {
        self.client
            .execute(&ExecuteMsg::RegisterVerifierSet { verifier_set })
    }

    pub fn register_public_key(
        &self,
        public_key: PublicKey,
        signed_sender_address: HexBinary,
    ) -> CosmosMsg {
        self.client.execute(&ExecuteMsg::RegisterPublicKey {
            public_key,
            signed_sender_address,
        })
    }

    pub fn authorize_callers(&self, contracts: HashMap<String, ChainName>) -> CosmosMsg {
        self.client
            .execute(&ExecuteMsg::AuthorizeCallers { contracts })
    }

    pub fn unauthorize_callers(&self, contracts: HashMap<String, ChainName>) -> CosmosMsg {
        self.client
            .execute(&ExecuteMsg::UnauthorizeCallers { contracts })
    }

    pub fn disable_signing(&self) -> CosmosMsg {
        self.client.execute(&ExecuteMsg::DisableSigning)
    }

    pub fn enable_signing(&self) -> CosmosMsg {
        self.client.execute(&ExecuteMsg::EnableSigning)
    }

    pub fn multisig(&self, session_id: Uint64) -> Result<Multisig, Error> {
        let msg = QueryMsg::Multisig { session_id };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }

    pub fn verifier_set(&self, verifier_set_id: String) -> Result<VerifierSet, Error> {
        let msg = QueryMsg::VerifierSet { verifier_set_id };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }

    pub fn public_key(
        &self,
        verifier_address: String,
        key_type: KeyType,
    ) -> Result<PublicKey, Error> {
        let msg = QueryMsg::PublicKey {
            verifier_address,
            key_type,
        };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }

    pub fn is_caller_authorized(
        &self,
        contract_address: String,
        chain_name: ChainName,
    ) -> Result<bool, Error> {
        let msg = QueryMsg::IsCallerAuthorized {
            contract_address,
            chain_name,
        };
        self.client.query(&msg).change_context_lazy(|| msg.into())
    }
}

#[cfg(test)]
mod test {

    use cosmwasm_std::testing::MockQuerier;
    use cosmwasm_std::{
        from_json, to_json_binary, Addr, QuerierWrapper, SystemError, Uint64, WasmQuery,
    };

    use crate::client::Client;
    use crate::key::{KeyType, PublicKey, Signature};
    use crate::msg::QueryMsg;
    use crate::multisig::Multisig;
    use crate::test::common::{build_verifier_set, ecdsa_test_data};
    use crate::types::MultisigState;

    #[test]
    fn query_multisig_session_returns_error_when_query_errors() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        let session_id: Uint64 = 1u64.into();
        let res = client.multisig(session_id);
        assert!(res.is_err());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_multisig_session_returns_session() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        let session_id: Uint64 = 1u64.into();
        let res = client.multisig(session_id);
        assert!(res.is_ok());
        goldie::assert_json!(res.unwrap());
    }

    #[test]
    fn query_verifier_set_returns_error_when_query_errors() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        let verifier_set_id = "my_set".to_string();
        let res = client.verifier_set(verifier_set_id.clone());
        assert!(res.is_err());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_verifier_set_returns_verifier_set() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        let verifier_set_id = "my_set".to_string();
        let res = client.verifier_set(verifier_set_id.clone());
        assert!(res.is_ok());
        goldie::assert_json!(res.unwrap());
    }

    #[test]
    fn query_public_key_returns_error_when_query_errors() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        let verifier_address = Addr::unchecked("verifier").to_string();
        let key_type = crate::key::KeyType::Ecdsa;
        let res = client.public_key(verifier_address.clone(), key_type);
        assert!(res.is_err());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_public_key_returns_public_key() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        let verifier_address = Addr::unchecked("verifier").to_string();
        let key_type = crate::key::KeyType::Ecdsa;
        let res = client.public_key(verifier_address.clone(), key_type);
        println!("{:?}", res);
        assert!(res.is_ok());
        goldie::assert_json!(res.unwrap());
    }

    #[test]
    fn query_is_caller_authorized_returns_error_when_query_errors() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        let contract_address = Addr::unchecked("prover").to_string();
        let chain_name = "ethereum".parse().unwrap();
        let res = client.is_caller_authorized(contract_address, chain_name);
        assert!(res.is_err());
        goldie::assert!(res.unwrap_err().to_string());
    }

    #[test]
    fn query_is_caller_authorized_returns_caller_authorization() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        let contract_address = Addr::unchecked("prover").to_string();
        let chain_name = "ethereum".parse().unwrap();
        let res = client.is_caller_authorized(contract_address, chain_name);
        assert!(res.is_ok());
        goldie::assert_json!(res.unwrap());
    }

    fn setup_queries_to_fail() -> (MockQuerier, Addr) {
        let addr = "multisig";

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart {
                contract_addr,
                msg: _,
            } if contract_addr == addr => {
                Err(SystemError::Unknown {}).into() // simulate cryptic error seen in production
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, Addr::unchecked(addr))
    }

    fn setup_queries_to_succeed() -> (MockQuerier, Addr) {
        let addr = "multisig";

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart { contract_addr, msg } if contract_addr == addr => {
                let msg = from_json::<QueryMsg>(msg).unwrap();
                match msg {
                    QueryMsg::Multisig { session_id: _ } => Ok(to_json_binary(&Multisig {
                        state: MultisigState::Completed { completed_at: 1 },
                        verifier_set: build_verifier_set(
                            crate::key::KeyType::Ecdsa,
                            &ecdsa_test_data::signers(),
                        ),

                        signatures: ecdsa_test_data::signers()
                            .into_iter()
                            .map(|signer| {
                                (
                                    signer.address.to_string(),
                                    Signature::try_from((KeyType::Ecdsa, signer.signature))
                                        .unwrap(),
                                )
                            })
                            .collect(),
                    })
                    .into())
                    .into(),
                    QueryMsg::VerifierSet { verifier_set_id: _ } => Ok(to_json_binary(
                        &build_verifier_set(KeyType::Ecdsa, &ecdsa_test_data::signers()),
                    )
                    .into())
                    .into(),
                    QueryMsg::PublicKey {
                        verifier_address: _,
                        key_type: _,
                    } => Ok(to_json_binary(
                        &PublicKey::try_from((KeyType::Ecdsa, ecdsa_test_data::pub_key())).unwrap(),
                    )
                    .into())
                    .into(),
                    QueryMsg::IsCallerAuthorized {
                        contract_address: _,
                        chain_name: _,
                    } => Ok(to_json_binary(&true).into()).into(),
                }
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, Addr::unchecked(addr))
    }
}
