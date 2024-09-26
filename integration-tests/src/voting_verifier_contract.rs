use axelar_core_std::query::AxelarQueryMsg;
use axelar_wasm_std::MajorityThreshold;
use cosmwasm_std::{Addr, DepsMut, Env, MessageInfo, Response};
use cw_multi_test::{ContractWrapper, Executor};
use router_api::ChainName;

use crate::contract::Contract;
use crate::protocol::{emptying_deps, emptying_deps_mut, Protocol};

#[derive(Clone)]
pub struct VotingVerifierContract {
    pub contract_addr: Addr,
}

impl VotingVerifierContract {
    pub fn instantiate_contract(
        protocol: &mut Protocol,
        voting_threshold: MajorityThreshold,
        source_chain: ChainName,
    ) -> Self {
        let code = ContractWrapper::new(custom_execute, custom_instantiate, custom_query);
        let app = &mut protocol.app;
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &voting_verifier::msg::InstantiateMsg {
                    governance_address: protocol.governance_address.to_string().try_into().unwrap(),
                    service_registry_address: protocol
                        .service_registry
                        .contract_addr
                        .to_string()
                        .try_into()
                        .unwrap(),
                    service_name: protocol.service_name.clone(),
                    source_gateway_address: "0x4F4495243837681061C4743b74B3eEdf548D56A5"
                        .try_into()
                        .unwrap(),
                    voting_threshold,
                    block_expiry: 10.try_into().unwrap(),
                    confirmation_height: 5,
                    source_chain,
                    rewards_address: protocol
                        .rewards
                        .contract_addr
                        .to_string()
                        .try_into()
                        .unwrap(),
                    msg_id_format: axelar_wasm_std::msg_id::MessageIdFormat::HexTxHashAndEventIndex,
                    address_format: axelar_wasm_std::address::AddressFormat::Eip55,
                },
                &[],
                "voting_verifier",
                None,
            )
            .unwrap();

        VotingVerifierContract { contract_addr }
    }
}

fn custom_execute(
    mut deps: DepsMut<AxelarQueryMsg>,
    env: Env,
    info: MessageInfo,
    msg: voting_verifier::msg::ExecuteMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    voting_verifier::contract::execute(emptying_deps_mut(&mut deps), env, info, msg)
}

fn custom_instantiate(
    mut deps: DepsMut<AxelarQueryMsg>,
    env: Env,
    info: MessageInfo,
    msg: voting_verifier::msg::InstantiateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    voting_verifier::contract::instantiate(emptying_deps_mut(&mut deps), env, info, msg)
}

fn custom_query(
    deps: cosmwasm_std::Deps<AxelarQueryMsg>,
    env: Env,
    msg: voting_verifier::msg::QueryMsg,
) -> Result<cosmwasm_std::Binary, axelar_wasm_std::error::ContractError> {
    voting_verifier::contract::query(emptying_deps(&deps), env, msg)
}

impl Contract for VotingVerifierContract {
    type QMsg = voting_verifier::msg::QueryMsg;
    type ExMsg = voting_verifier::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
