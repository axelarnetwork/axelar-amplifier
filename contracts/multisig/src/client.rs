use std::collections::HashMap;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, CosmosMsg, HexBinary, Uint64};
use error_stack::{Result, ResultExt};
use router_api::ChainName;

use crate::key::{KeyType, PublicKey};
use crate::msg::{ExecuteMsg, ExecuteMsgFromProxy, QueryMsg};
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

impl<'a> From<client::ContractClient<'a, ExecuteMsgFromProxy, QueryMsg>> for Client<'a> {
    fn from(client: client::ContractClient<'a, ExecuteMsgFromProxy, QueryMsg>) -> Self {
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
    client: client::ContractClient<'a, ExecuteMsgFromProxy, QueryMsg>,
}

impl Client<'_> {
    pub fn start_signing_session(
        &self,
        verifier_set_id: String,
        msg: HexBinary,
        chain_name: ChainName,
        sig_verifier: Option<String>,
    ) -> CosmosMsg {
        self.client.execute(
            &ExecuteMsg::StartSigningSession {
                verifier_set_id,
                msg,
                chain_name,
                sig_verifier,
            }
            .into(),
        )
    }

    pub fn submit_signature(&self, session_id: Uint64, signature: HexBinary) -> CosmosMsg {
        self.client.execute(
            &ExecuteMsg::SubmitSignature {
                session_id,
                signature,
            }
            .into(),
        )
    }

    pub fn register_verifier_set(&self, verifier_set: VerifierSet) -> CosmosMsg {
        self.client
            .execute(&ExecuteMsg::RegisterVerifierSet { verifier_set }.into())
    }

    pub fn register_public_key(
        &self,
        public_key: PublicKey,
        signed_sender_address: HexBinary,
    ) -> CosmosMsg {
        self.client.execute(
            &ExecuteMsg::RegisterPublicKey {
                public_key,
                signed_sender_address,
            }
            .into(),
        )
    }

    pub fn authorize_callers(&self, contracts: HashMap<String, ChainName>) -> CosmosMsg {
        self.client
            .execute(&ExecuteMsg::AuthorizeCallers { contracts }.into())
    }

    pub fn authorize_callers_from_proxy(
        &self,
        original_sender: Addr,
        contracts: HashMap<String, ChainName>,
    ) -> CosmosMsg {
        self.client.execute(&ExecuteMsgFromProxy::Relay {
            original_sender,
            msg: ExecuteMsg::AuthorizeCallers { contracts },
        })
    }

    pub fn unauthorize_callers(&self, contracts: HashMap<String, ChainName>) -> CosmosMsg {
        self.client
            .execute(&ExecuteMsg::UnauthorizeCallers { contracts }.into())
    }

    pub fn disable_signing(&self) -> CosmosMsg {
        self.client.execute(&ExecuteMsg::DisableSigning.into())
    }

    pub fn enable_signing(&self) -> CosmosMsg {
        self.client.execute(&ExecuteMsg::EnableSigning.into())
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

    use std::collections::HashMap;

    use cosmwasm_std::testing::{MockApi, MockQuerier};
    use cosmwasm_std::{
        from_json, to_json_binary, Addr, CosmosMsg, QuerierWrapper, SystemError, Uint64, WasmMsg,
        WasmQuery,
    };
    use router_api::ChainName;

    use crate::client::Client;
    use crate::key::{KeyType, PublicKey, Signature};
    use crate::msg::{ExecuteMsg, QueryMsg};
    use crate::multisig::Multisig;
    use crate::test::common::{
        build_verifier_set, ecdsa_test_data, ed25519_test_data, signature_test_data, TestSigner,
    };
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

        let verifier_address = MockApi::default().addr_make("verifier").to_string();
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

        let verifier_address = MockApi::default().addr_make("verifier").to_string();
        let key_type = crate::key::KeyType::Ecdsa;
        let res = client.public_key(verifier_address.clone(), key_type);
        assert!(res.is_ok());
        goldie::assert_json!(res.unwrap());
    }

    #[test]
    fn query_is_caller_authorized_returns_error_when_query_errors() {
        let (querier, addr) = setup_queries_to_fail();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        let contract_address = MockApi::default().addr_make("prover").to_string();
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

        let contract_address = MockApi::default().addr_make("prover").to_string();
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
            } if contract_addr == MockApi::default().addr_make(addr).as_str() => {
                Err(SystemError::Unknown {}).into() // simulate cryptic error seen in production
            }
            _ => panic!("unexpected query: {:?}", msg),
        });

        (querier, MockApi::default().addr_make(addr))
    }

    fn setup_queries_to_succeed() -> (MockQuerier, Addr) {
        let addr = "multisig";

        let mut querier = MockQuerier::default();
        querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart { contract_addr, msg }
                if contract_addr == MockApi::default().addr_make(addr).as_str() =>
            {
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

        (querier, MockApi::default().addr_make(addr))
    }

    fn signing_keys() -> (String, String) {
        (
            build_verifier_set(KeyType::Ecdsa, &ecdsa_test_data::signers()).id(),
            build_verifier_set(KeyType::Ed25519, &ed25519_test_data::signers()).id(),
        )
    }

    fn validate_submit_signature_msgs_construction(
        client: &Client,
        contract_addr: Addr,
        session_id: Uint64,
        signers: Vec<TestSigner>,
    ) {
        for signer in signers {
            assert_eq!(
                client.submit_signature(session_id, signer.signature.clone()),
                CosmosMsg::Wasm(WasmMsg::Execute {
                    contract_addr: contract_addr.to_string().clone(),
                    msg: to_json_binary(&ExecuteMsg::SubmitSignature {
                        session_id,
                        signature: signer.signature
                    })
                    .unwrap(),
                    funds: vec![],
                })
            );
        }
    }

    fn validate_register_public_key_msgs_construction(
        client: &Client,
        contract_addr: Addr,
        key_type: KeyType,
        signers: Vec<TestSigner>,
    ) {
        for signer in signers {
            let pub_key = match key_type {
                KeyType::Ecdsa => PublicKey::Ecdsa(signer.pub_key.clone()),
                KeyType::Ed25519 => PublicKey::Ed25519(signer.pub_key.clone()),
            };

            assert_eq!(
                client.register_public_key(pub_key.clone(), signer.signed_address.clone()),
                CosmosMsg::Wasm(WasmMsg::Execute {
                    contract_addr: contract_addr.to_string().clone(),
                    msg: to_json_binary(&ExecuteMsg::RegisterPublicKey {
                        public_key: pub_key,
                        signed_sender_address: signer.signed_address
                    })
                    .unwrap(),
                    funds: vec![],
                })
            );
        }
    }

    #[test]
    fn construct_submit_signature_msg() {
        let (ecdsa_subkey, ed25519_subkey) = signing_keys();

        let (querier, addr) = setup_queries_to_succeed();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        for (_, _, signers, session_id) in signature_test_data(&ecdsa_subkey, &ed25519_subkey) {
            validate_submit_signature_msgs_construction(&client, addr.clone(), session_id, signers);
        }
    }

    #[test]
    fn construct_register_public_key_msg() {
        let (ecdsa_subkey, ed25519_subkey) = signing_keys();

        let (querier, addr) = setup_queries_to_succeed();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        for (key_type, _, signers, _) in signature_test_data(&ecdsa_subkey, &ed25519_subkey) {
            validate_register_public_key_msgs_construction(
                &client,
                addr.clone(),
                key_type,
                signers,
            );
        }
    }

    #[test]
    fn construct_authorize_callers_msg() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        let contracts: HashMap<String, ChainName> = HashMap::from([(
            MockApi::default().addr_make("prover").to_string(),
            ChainName::try_from("ethereum").unwrap(),
        )]);

        assert_eq!(
            client.authorize_callers(contracts.clone()),
            CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: addr.to_string().clone(),
                msg: to_json_binary(&ExecuteMsg::AuthorizeCallers { contracts }).unwrap(),
                funds: vec![],
            }),
        );
    }

    #[test]
    fn construct_unauthorize_callers_msg() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        let contracts: HashMap<String, ChainName> = HashMap::from([(
            MockApi::default().addr_make("prover").to_string(),
            ChainName::try_from("ethereum").unwrap(),
        )]);

        assert_eq!(
            client.unauthorize_callers(contracts.clone()),
            CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: addr.to_string().clone(),
                msg: to_json_binary(&ExecuteMsg::UnauthorizeCallers { contracts }).unwrap(),
                funds: vec![],
            }),
        );
    }

    #[test]
    fn construct_disable_signing_msg() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        assert_eq!(
            client.disable_signing(),
            CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: addr.to_string().clone(),
                msg: to_json_binary(&ExecuteMsg::DisableSigning {}).unwrap(),
                funds: vec![],
            }),
        );
    }

    #[test]
    fn construct_enable_signing_msg() {
        let (querier, addr) = setup_queries_to_succeed();
        let client: Client =
            client::ContractClient::new(QuerierWrapper::new(&querier), &addr).into();

        assert_eq!(
            client.enable_signing(),
            CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: addr.to_string().clone(),
                msg: to_json_binary(&ExecuteMsg::EnableSigning {}).unwrap(),
                funds: vec![],
            }),
        );
    }
}
