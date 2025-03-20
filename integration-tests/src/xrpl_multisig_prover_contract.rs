use axelar_core_std::query::AxelarQueryMsg;
use axelar_wasm_std::Threshold;
use cosmwasm_std::{Addr, DepsMut, Env};
use cw_multi_test::{ContractWrapper, Executor};
use router_api::ChainName;
use xrpl_multisig_prover::contract::{execute, instantiate, query};
use xrpl_types::types::XRPLAccountId;

use crate::contract::Contract;
use crate::protocol::{emptying_deps_mut, Protocol};

#[derive(Clone)]
pub struct XRPLMultisigProverContract {
    pub contract_addr: Addr,
    pub admin_addr: Addr,
}

impl XRPLMultisigProverContract {
    pub fn instantiate_contract(
        protocol: &mut Protocol,
        admin_address: Addr,
        gateway_address: Addr,
        voting_verifier_address: Addr,
        xrpl_chain_name: ChainName,
        xrpl_multisig_address: XRPLAccountId,
    ) -> Self {
        let code =
            ContractWrapper::new_with_empty(execute, instantiate, query).with_reply(custom_reply);
        let app = &mut protocol.app;
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &xrpl_multisig_prover::msg::InstantiateMsg {
                    admin_address: admin_address.to_string(),
                    governance_address: protocol.governance_address.to_string(),
                    gateway_address: gateway_address.to_string(),
                    multisig_address: protocol.multisig.contract_addr.to_string(),
                    coordinator_address: protocol.coordinator.contract_addr.to_string(),
                    service_registry_address: protocol.service_registry.contract_addr.to_string(),
                    voting_verifier_address: voting_verifier_address.to_string(),
                    signing_threshold: Threshold::try_from((2, 3)).unwrap().try_into().unwrap(),
                    service_name: protocol.service_name.to_string(),
                    chain_name: xrpl_chain_name,
                    xrpl_multisig_address,
                    verifier_set_diff_threshold: 0,
                    xrpl_transaction_fee: 10,
                    xrpl_base_reserve: 1000000,
                    xrpl_owner_reserve: 200000,
                    initial_fee_reserve: 60000000,
                    ticket_count_threshold: 1,
                    next_sequence_number: 44218446,
                    last_assigned_ticket_number: 44218195,
                    available_tickets: [vec![], (44218195..44218200).collect::<Vec<_>>()].concat(),
                },
                &[],
                "xrpl_multisig_prover",
                None,
            )
            .unwrap();

        XRPLMultisigProverContract {
            contract_addr,
            admin_addr: admin_address,
        }
    }
}

fn custom_reply(
    mut deps: DepsMut<AxelarQueryMsg>,
    env: Env,
    msg: cosmwasm_std::Reply,
) -> Result<cosmwasm_std::Response, axelar_wasm_std::error::ContractError> {
    xrpl_multisig_prover::contract::reply(emptying_deps_mut(&mut deps), env, msg)
}

impl Contract for XRPLMultisigProverContract {
    type QMsg = xrpl_multisig_prover::msg::QueryMsg;
    type ExMsg = xrpl_multisig_prover::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
