use axelar_wasm_std::VerificationStatus;
use cosmwasm_schema::serde::de::DeserializeOwned;
use cosmwasm_std::testing::MockApi;
use cosmwasm_std::{
    from_json, to_json_binary, Addr, Api, Binary, BlockInfo, CustomMsg, CustomQuery, Querier,
    QuerierResult, Record, Storage, Uint128, WasmMsg, WasmQuery,
};
use cw_multi_test::error::AnyResult;
use cw_multi_test::{
    AppResponse, Contract, ContractData, CosmosRouter, Wasm, WasmKeeper, WasmSudo,
};
use multisig::msg::Signer;
use multisig::multisig::Multisig;
use multisig::types::MultisigState;
use multisig::verifier_set::VerifierSet;
use service_registry::VERIFIER_WEIGHT;
use service_registry_api::{AuthorizationState, BondingState, Verifier, WeightedVerifier};

use super::test_data::{self, TestOperator};

pub const GATEWAY_ADDRESS: &str = "gateway";
pub const MULTISIG_ADDRESS: &str = "multisig";
pub const COORDINATOR_ADDRESS: &str = "coordinator";
pub const SERVICE_REGISTRY_ADDRESS: &str = "service_registry";
pub const VOTING_VERIFIER_ADDRESS: &str = "voting_verifier";
pub const ADMIN: &str = "admin";
pub const GOVERNANCE: &str = "governance";
pub const SERVICE_NAME: &str = "validators";
pub const REWARDS: &str = "rewards";
pub const SIGNATURE_BLOCK_EXPIRY: u64 = 100;

pub trait ApiAddrMaker {
    fn addr_make(&self, input: &str) -> Addr;
}

impl ApiAddrMaker for cosmwasm_std::testing::MockApi {
    fn addr_make(&self, input: &str) -> Addr {
        self.addr_make(input)
    }
}

impl ApiAddrMaker for cw_multi_test::MockApiBech32 {
    fn addr_make(&self, input: &str) -> Addr {
        self.addr_make(input)
    }
}

pub fn mock_querier_handler(
    operators: Vec<TestOperator>,
    verifier_set_status: VerificationStatus,
) -> impl Fn(&WasmQuery) -> QuerierResult {
    move |wq: &WasmQuery| match wq {
        WasmQuery::Smart { contract_addr, .. }
            if contract_addr == MockApi::default().addr_make(GATEWAY_ADDRESS).as_str() =>
        {
            gateway_mock_querier_handler()
        }
        WasmQuery::Smart { contract_addr, msg }
            if contract_addr == MockApi::default().addr_make(MULTISIG_ADDRESS).as_str() =>
        {
            multisig_mock_querier_handler(from_json(msg).unwrap(), operators.clone())
        }
        WasmQuery::Smart { contract_addr, msg }
            if contract_addr
                == MockApi::default()
                    .addr_make(SERVICE_REGISTRY_ADDRESS)
                    .as_str() =>
        {
            service_registry_mock_querier_handler(
                from_json(msg).unwrap(),
                operators.clone(),
                &MockApi::default(),
            )
        }
        WasmQuery::Smart { contract_addr, .. }
            if contract_addr
                == MockApi::default()
                    .addr_make(VOTING_VERIFIER_ADDRESS)
                    .as_str() =>
        {
            voting_verifier_mock_querier_handler(verifier_set_status)
        }
        _ => panic!("unexpected query: {:?}", wq),
    }
}

fn gateway_mock_querier_handler() -> QuerierResult {
    Ok(to_json_binary(&test_data::messages()).into()).into()
}

fn multisig_mock_querier_handler(
    msg: multisig::msg::QueryMsg,
    operators: Vec<TestOperator>,
) -> QuerierResult {
    let result = match msg {
        multisig::msg::QueryMsg::Multisig { session_id: _ } => {
            to_json_binary(&mock_multisig(operators))
        }
        multisig::msg::QueryMsg::PublicKey {
            verifier_address,
            key_type: _,
        } => to_json_binary(
            &operators
                .iter()
                .find(|op| op.address.as_str() == verifier_address)
                .unwrap()
                .pub_key,
        ),
        _ => panic!("unexpected query: {:?}", msg),
    };

    Ok(result.into()).into()
}

fn mock_multisig(operators: Vec<TestOperator>) -> Multisig {
    let quorum = test_data::quorum();

    let signers = operators
        .clone()
        .into_iter()
        .map(|op| {
            (
                op.address.as_str().into(),
                Signer {
                    address: op.address,
                    weight: op.weight,
                    pub_key: op.pub_key,
                },
            )
        })
        .collect();

    let signatures = operators
        .into_iter()
        .filter_map(|op| {
            if let Some(signature) = op.signature {
                Some((op.address.into_string(), signature))
            } else {
                None
            }
        })
        .collect();

    let verifier_set = VerifierSet {
        signers,
        threshold: quorum,
        created_at: 1,
    };

    Multisig {
        state: MultisigState::Completed {
            completed_at: 12345,
        },
        verifier_set,
        signatures,
    }
}

fn service_registry_mock_querier_handler<'a, TestApi: Api + ApiAddrMaker>(
    msg: service_registry_api::msg::QueryMsg,
    operators: Vec<TestOperator>,
    mock_api: &'a TestApi,
) -> QuerierResult {
    let result = match msg {
        service_registry_api::msg::QueryMsg::Service { service_name } => {
            to_json_binary(&service_registry_api::Service {
                name: service_name.to_string(),
                coordinator_contract: mock_api.addr_make(COORDINATOR_ADDRESS),
                min_num_verifiers: 1,
                max_num_verifiers: Some(100),
                min_verifier_bond: Uint128::new(1).try_into().unwrap(),
                bond_denom: "uaxl".to_string(),
                unbonding_period_days: 1,
                description: "verifiers".to_string(),
            })
        }
        service_registry_api::msg::QueryMsg::ActiveVerifiers {
            service_name: _,
            chain_name: _,
        } => to_json_binary(
            &operators
                .clone()
                .into_iter()
                .map(|op| WeightedVerifier {
                    verifier_info: Verifier {
                        address: op.address,
                        bonding_state: BondingState::Bonded {
                            amount: op.weight.try_into().unwrap(),
                        },
                        authorization_state: AuthorizationState::Authorized,
                        service_name: SERVICE_NAME.to_string(),
                    },
                    weight: VERIFIER_WEIGHT,
                })
                .collect::<Vec<WeightedVerifier>>(),
        ),

        _ => panic!("unexpected query: {:?}", msg),
    };
    Ok(result.into()).into()
}

fn voting_verifier_mock_querier_handler(status: VerificationStatus) -> QuerierResult {
    Ok(to_json_binary(&status).into()).into()
}

pub struct ProverWasm<ExecC, QueryC, TestApi: Api + ApiAddrMaker> {
    wasm: WasmKeeper<ExecC, QueryC>,
    operators: Vec<TestOperator>,
    verifier_set_status: VerificationStatus,
    multisig_addr: Addr,
    mock_api: TestApi,
}

impl<ExecC, QueryC, TestApi: Api + ApiAddrMaker> ProverWasm<ExecC, QueryC, TestApi> {
    pub fn new(
        operators: Vec<TestOperator>,
        verifier_set_status: VerificationStatus,
        multisig_addr: Addr,
        mock_api: TestApi,
    ) -> Self {
        ProverWasm {
            wasm: WasmKeeper::default(),
            operators,
            verifier_set_status,
            multisig_addr,
            mock_api,
        }
    }
}

impl<ExecC, QueryC, TestApi: Api + ApiAddrMaker> Wasm<ExecC, QueryC>
    for ProverWasm<ExecC, QueryC, TestApi>
where
    ExecC: CustomMsg + DeserializeOwned + 'static,
    QueryC: CustomQuery + DeserializeOwned + 'static,
{
    /// Handles all `WasmMsg` messages.
    fn execute(
        &self,
        api: &dyn Api,
        storage: &mut dyn Storage,
        router: &dyn CosmosRouter<ExecC = ExecC, QueryC = QueryC>,
        block: &BlockInfo,
        sender: Addr,
        msg: WasmMsg,
    ) -> AnyResult<AppResponse> {
        self.wasm.execute(api, storage, router, block, sender, msg)
    }

    fn query(
        &self,
        api: &dyn Api,
        storage: &dyn Storage,
        querier: &dyn Querier,
        block: &BlockInfo,
        request: WasmQuery,
    ) -> AnyResult<Binary> {
        match request {
            WasmQuery::Smart { contract_addr, .. }
                if contract_addr == self.mock_api.addr_make(GATEWAY_ADDRESS).as_str() =>
            {
                gateway_mock_querier_handler()
                    .into_result()?
                    .into_result()
                    .map_err(|err| anyhow::Error::msg(err))
            }
            WasmQuery::Smart { contract_addr, msg }
                if contract_addr == self.multisig_addr.as_str() =>
            {
                multisig_mock_querier_handler(from_json(msg).unwrap(), self.operators.clone())
                    .into_result()?
                    .into_result()
                    .map_err(|err| anyhow::Error::msg(err))
            }
            WasmQuery::Smart { contract_addr, msg }
                if contract_addr == self.mock_api.addr_make(SERVICE_REGISTRY_ADDRESS).as_str() =>
            {
                service_registry_mock_querier_handler(
                    from_json(msg).unwrap(),
                    self.operators.clone(),
                    &self.mock_api,
                )
                .into_result()?
                .into_result()
                .map_err(|err| anyhow::Error::msg(err))
            }
            WasmQuery::Smart { contract_addr, .. }
                if contract_addr == self.mock_api.addr_make(VOTING_VERIFIER_ADDRESS).as_str() =>
            {
                voting_verifier_mock_querier_handler(self.verifier_set_status)
                    .into_result()?
                    .into_result()
                    .map_err(|err| anyhow::Error::msg(err))
            }
            _ => self.wasm.query(api, storage, querier, block, request),
        }
    }

    /// Handles all sudo messages, this is an admin interface and can not be called via `CosmosMsg`.
    fn sudo(
        &self,
        api: &dyn Api,
        storage: &mut dyn Storage,
        router: &dyn CosmosRouter<ExecC = ExecC, QueryC = QueryC>,
        block: &BlockInfo,
        msg: WasmSudo,
    ) -> AnyResult<AppResponse> {
        self.wasm.sudo(api, storage, router, block, msg)
    }

    /// Stores the contract's code and returns an identifier of the stored contract's code.
    fn store_code(&mut self, creator: Addr, code: Box<dyn Contract<ExecC, QueryC>>) -> u64 {
        self.wasm.store_code(creator, code)
    }

    /// Stores the contract's code under specified identifier,
    /// returns the same code identifier when successful.
    fn store_code_with_id(
        &mut self,
        creator: Addr,
        code_id: u64,
        code: Box<dyn Contract<ExecC, QueryC>>,
    ) -> AnyResult<u64> {
        self.wasm.store_code_with_id(creator, code_id, code)
    }

    /// Duplicates the contract's code with specified identifier
    /// and returns an identifier of the copy of the contract's code.
    fn duplicate_code(&mut self, code_id: u64) -> AnyResult<u64> {
        self.wasm.duplicate_code(code_id)
    }

    /// Returns `ContractData` for the contract with specified address.
    fn contract_data(&self, storage: &dyn Storage, address: &Addr) -> AnyResult<ContractData> {
        self.wasm.contract_data(storage, address)
    }

    /// Returns a raw state dump of all key-values held by a contract with specified address.
    fn dump_wasm_raw(&self, storage: &dyn Storage, address: &Addr) -> Vec<Record> {
        self.wasm.dump_wasm_raw(storage, address)
    }
}
