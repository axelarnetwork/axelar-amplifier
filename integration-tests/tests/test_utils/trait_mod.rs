use axelar_wasm_std::MajorityThreshold;
use cosmwasm_std::{Addr, Binary, Deps, Env, StdResult, Uint256};
use cw_multi_test::{App, ContractWrapper, Executor};
use integration_tests::contract::Contract;
use multisig::key::KeyType;
use multisig_prover::encoding::Encoder;
use service_registry::contract::{execute, instantiate, query};

#[derive(Clone)]
pub struct ServiceRegistryContract {
    pub contract_addr: Addr,
}

impl ServiceRegistryContract {
    pub fn instantiate_contract(app: &mut App, governance: Addr) -> Self {
        let code = ContractWrapper::new(execute, instantiate, query);
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &service_registry::msg::InstantiateMsg {
                    governance_account: governance.clone().into(),
                },
                &[],
                "service_registry",
                None,
            )
            .unwrap();

        ServiceRegistryContract { contract_addr }
    }
}

impl Contract for ServiceRegistryContract {
    type QMsg = service_registry::msg::QueryMsg;
    type ExMsg = service_registry::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}

#[derive(Clone)]
pub struct ConnectionRouterContract {
    pub contract_addr: Addr,
}

impl ConnectionRouterContract {
    pub fn instantiate_contract(app: &mut App, admin: Addr, governance: Addr, nexus: Addr) -> Self {
        let code = ContractWrapper::new(
            connection_router::contract::execute,
            connection_router::contract::instantiate,
            connection_router::contract::query,
        );
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("router"),
                &connection_router::msg::InstantiateMsg {
                    admin_address: admin.to_string(),
                    governance_address: governance.to_string(),
                    nexus_gateway: nexus.to_string(),
                },
                &[],
                "connection_router",
                None,
            )
            .unwrap();

        ConnectionRouterContract { contract_addr }
    }
}

impl Contract for ConnectionRouterContract {
    type QMsg = connection_router_api::msg::QueryMsg;
    type ExMsg = connection_router_api::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}

#[derive(Clone)]
pub struct RewardsContract {
    pub contract_addr: Addr,
}

impl RewardsContract {
    pub fn instantiate_contract(
        app: &mut App,
        governance: Addr,
        rewards_denom: String,
        params: rewards::msg::Params,
    ) -> Self {
        let code = ContractWrapper::new(
            rewards::contract::execute,
            rewards::contract::instantiate,
            |_: Deps, _: Env, _: rewards::msg::QueryMsg| -> StdResult<Binary> { todo!() },
        );
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &rewards::msg::InstantiateMsg {
                    governance_address: governance.to_string(),
                    rewards_denom,
                    params,
                },
                &[],
                "rewards",
                None,
            )
            .unwrap();

        RewardsContract { contract_addr }
    }
}

impl Contract for RewardsContract {
    type QMsg = rewards::msg::QueryMsg;
    type ExMsg = rewards::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}

#[derive(Clone)]
pub struct MultisigContract {
    pub contract_addr: Addr,
}

impl MultisigContract {
    pub fn instantiate_contract(
        app: &mut App,
        governance: Addr,
        rewards_address: Addr,
        block_expiry: u64,
    ) -> Self {
        let code = ContractWrapper::new(
            multisig::contract::execute,
            multisig::contract::instantiate,
            multisig::contract::query,
        );
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &multisig::msg::InstantiateMsg {
                    rewards_address: rewards_address.to_string(),
                    governance_address: governance.to_string(),
                    block_expiry,
                },
                &[],
                "multisig",
                None,
            )
            .unwrap();

        MultisigContract { contract_addr }
    }
}

impl Contract for MultisigContract {
    type QMsg = multisig::msg::QueryMsg;
    type ExMsg = multisig::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}

#[derive(Clone)]
pub struct MultisigProverContract {
    pub contract_addr: Addr,
}

impl MultisigProverContract {
    pub fn instantiate_contract(
        app: &mut App,
        admin_address: Addr,
        gateway_address: Addr,
        multisig_address: Addr,
        service_registry_address: Addr,
        voting_verifier_address: Addr,
        destination_chain_id: Uint256,
        signing_threshold: MajorityThreshold,
        service_name: String,
        chain_name: String,
        worker_set_diff_threshold: u32,
    ) -> Self {
        let code = ContractWrapper::new(
            multisig_prover::contract::execute,
            multisig_prover::contract::instantiate,
            multisig_prover::contract::query,
        )
        .with_reply(multisig_prover::contract::reply);
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &multisig_prover::msg::InstantiateMsg {
                    admin_address: admin_address.to_string(),
                    gateway_address: gateway_address.to_string(),
                    multisig_address: multisig_address.to_string(),
                    service_registry_address: service_registry_address.to_string(),
                    voting_verifier_address: voting_verifier_address.to_string(),
                    destination_chain_id,
                    signing_threshold,
                    service_name: service_name.to_string(),
                    chain_name: chain_name.to_string(),
                    worker_set_diff_threshold,
                    encoder: Encoder::Abi,
                    key_type: KeyType::Ecdsa,
                },
                &[],
                "multisig_prover",
                None,
            )
            .unwrap();

        MultisigProverContract { contract_addr }
    }
}

impl Contract for MultisigProverContract {
    type QMsg = multisig_prover::msg::QueryMsg;
    type ExMsg = multisig_prover::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}

#[derive(Clone)]
pub struct GatewayContract {
    pub contract_addr: Addr,
}

impl GatewayContract {
    pub fn instantiate_contract(
        app: &mut App,
        router_address: Addr,
        verifier_address: Addr,
    ) -> Self {
        let code = ContractWrapper::new(
            gateway::contract::execute,
            gateway::contract::instantiate,
            gateway::contract::query,
        );
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &gateway::msg::InstantiateMsg {
                    router_address: router_address.to_string(),
                    verifier_address: verifier_address.to_string(),
                },
                &[],
                "gateway",
                None,
            )
            .unwrap();

        GatewayContract { contract_addr }
    }
}

impl Contract for GatewayContract {
    type QMsg = gateway_api::msg::QueryMsg;
    type ExMsg = gateway_api::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
