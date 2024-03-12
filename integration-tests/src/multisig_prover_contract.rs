use crate::contract::Contract;
use axelar_wasm_std::Threshold;
use cosmwasm_std::{Addr, Uint256};
use cw_multi_test::{App, ContractWrapper, Executor};
use multisig::key::KeyType;
use multisig_prover::encoding::Encoder;

#[derive(Clone)]
pub struct MultisigProverContract {
    pub contract_addr: Addr,
}

impl MultisigProverContract {
    pub fn instantiate_contract(
        app: &mut App,
        gateway_address: Addr,
        multisig_address: Addr,
        service_registry_address: Addr,
        voting_verifier_address: Addr,
        service_name: String,
        chain_name: String,
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
                    admin_address: Addr::unchecked("doesn't matter").to_string(),
                    gateway_address: gateway_address.to_string(),
                    multisig_address: multisig_address.to_string(),
                    service_registry_address: service_registry_address.to_string(),
                    voting_verifier_address: voting_verifier_address.to_string(),
                    destination_chain_id: Uint256::zero(),
                    signing_threshold: Threshold::try_from((2, 3)).unwrap().try_into().unwrap(),
                    service_name: service_name.to_string(),
                    chain_name: chain_name.to_string(),
                    worker_set_diff_threshold: 0,
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
