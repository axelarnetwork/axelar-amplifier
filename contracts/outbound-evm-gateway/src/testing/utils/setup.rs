use auth_multisig::AuthMultisig;
use cosmwasm_std::{Addr, Coin, Empty, Uint128, Uint256, Uint64};
use cw_multi_test::{next_block, App, AppBuilder, Contract, ContractWrapper, Executor};

use crate::{
    msg::{InstantiateMsg, RegistrationParameters},
    state::{OutboundSettings, ServiceInfo},
};

pub const OWNER: &str = "owner";
pub const GATEWAY: &str = "gateway";
pub const WORKERS: [&str; 6] = [
    "worker0", "worker1", "worker2", "worker3", "worker4", "worker5",
];
pub const ANY: &str = "any";

pub fn mock_app(init_funds: &[Coin]) -> App {
    AppBuilder::new().build(|router, _, storage| {
        for worker in WORKERS {
            router
                .bank
                .init_balance(storage, &Addr::unchecked(worker), init_funds.to_vec())
                .unwrap();
        }
    })
}

fn contract_registry() -> Box<dyn Contract<Empty>> {
    let contract = ContractWrapper::new(
        service_registry::contract::execute,
        service_registry::contract::instantiate,
        service_registry::contract::query,
    );
    Box::new(contract)
}

fn contract_mock_router() -> Box<dyn Contract<Empty>> {
    let contract = ContractWrapper::new(
        crate::testing::mocks::mock_connection_router::execute,
        crate::testing::mocks::mock_connection_router::instantiate,
        crate::testing::mocks::mock_connection_router::query,
    );
    Box::new(contract)
}

fn contract_service() -> Box<dyn Contract<Empty>> {
    let contract = ContractWrapper::new(
        crate::contract::execute,
        crate::contract::instantiate,
        crate::contract::query,
    );
    Box::new(contract)
}

fn instantiate_registry(app: &mut App) -> Addr {
    let registry_id = app.store_code(contract_registry());
    let msg = service_registry::msg::InstantiateMsg {};

    app.instantiate_contract(
        registry_id,
        Addr::unchecked(OWNER),
        &msg,
        &[],
        "registry",
        None,
    )
    .unwrap()
}

fn instantiate_mock_router(app: &mut App) -> Addr {
    let router_id = app.store_code(contract_mock_router());
    let msg = connection_router::msg::InstantiateMsg {};

    app.instantiate_contract(
        router_id,
        Addr::unchecked(OWNER),
        &msg,
        &[],
        "mock-router",
        None,
    )
    .unwrap()
}

fn instantiate_service(
    app: &mut App,
    service_info: ServiceInfo,
    registration_parameters: RegistrationParameters,
    outbound_settings: OutboundSettings,
    auth_module: AuthMultisig,
) -> Addr {
    let service_id = app.store_code(contract_service());
    let msg = InstantiateMsg {
        service_info,
        registration_parameters,
        outbound_settings,
        auth_module,
    };

    app.instantiate_contract(
        service_id,
        Addr::unchecked(OWNER),
        &msg,
        &[],
        "outbound-evm-gateway",
        None,
    )
    .unwrap()
}

fn register_workers(app: &mut App, service_name: &str, registry: Addr) {
    for worker in WORKERS {
        let msg = service_registry::msg::ExecuteMsg::RegisterWorker {
            service_name: service_name.to_owned(),
            commission_rate: Uint128::from(1u8),
        };

        app.execute_contract(
            Addr::unchecked(worker),
            registry.clone(),
            &msg,
            &vec![Coin {
                denom: "uaxl".to_string(),
                amount: Uint128::from(100u8),
            }],
        )
        .unwrap();
    }
}

pub fn default_instantiation_message() -> InstantiateMsg {
    InstantiateMsg {
        service_info: ServiceInfo {
            service_registry: Addr::unchecked("service_registry"),
            name: "EVM Connection Service".to_string(),
            reward_pool: Addr::unchecked("reward_pool"),
            router_contract: Addr::unchecked("router"),
        },
        registration_parameters: RegistrationParameters {
            description: "EVM Connection Service".to_string(),
            min_num_workers: Uint64::from(5u64),
            max_num_workers: None,
            min_worker_bond: Uint128::from(100u8),
            unbonding_period: Uint128::from(1u8),
        },
        outbound_settings: OutboundSettings {
            destination_chain_id: Uint256::from(43114u16),
            destination_chain_name: "Avalanche".to_string(),
            finalize_actions_limit: 10u32,
        },
        auth_module: AuthMultisig {
            signing_timeout: Uint64::from(1u8),
            signing_grace_period: Uint64::from(1u8),
        },
    }
}

pub fn setup_test_case(
    service_info: Option<ServiceInfo>,
    registration_parameters: Option<RegistrationParameters>,
    outbound_settings: Option<OutboundSettings>,
    auth_module: Option<AuthMultisig>,
) -> (App, Addr, Addr, Addr) {
    let mut app = mock_app(&[Coin {
        denom: "uaxl".to_string(),
        amount: Uint128::from(100u8),
    }]);

    let registry_addr = instantiate_registry(&mut app);
    let router_addr = instantiate_mock_router(&mut app);
    app.update_block(next_block);

    let default_msg = default_instantiation_message();

    let mut service_info = service_info.unwrap_or(default_msg.service_info);
    service_info.service_registry = registry_addr.clone();
    service_info.router_contract = router_addr.clone();

    let registration_parameters =
        registration_parameters.unwrap_or(default_msg.registration_parameters);
    let outbound_settings = outbound_settings.unwrap_or(default_msg.outbound_settings);
    let auth_module = auth_module.unwrap_or(default_msg.auth_module);

    let service_name = service_info.name.clone();

    let service_address = instantiate_service(
        &mut app,
        service_info,
        registration_parameters,
        outbound_settings,
        auth_module,
    );
    app.update_block(next_block);

    register_workers(&mut app, &service_name, registry_addr.clone());

    (app, service_address, registry_addr, router_addr)
}
