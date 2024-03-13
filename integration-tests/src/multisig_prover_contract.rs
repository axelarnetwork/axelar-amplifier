use crate::{contract::Contract, protocol::Protocol};
use axelar_wasm_std::Threshold;
use cosmwasm_std::{Addr, Uint256};
use cw_multi_test::{ContractWrapper, Executor};
use multisig::key::KeyType;
use multisig_prover::encoding::Encoder;

#[derive(Clone)]
pub struct MultisigProverContract {
    pub contract_addr: Addr,
    pub admin_addr: Addr,
}

impl MultisigProverContract {
    pub fn instantiate_contract(
        protocol: &mut Protocol,
        admin_address: Addr,
        gateway_address: Addr,
        voting_verifier_address: Addr,
        chain_name: String,
    ) -> Self {
        let code = ContractWrapper::new(
            multisig_prover::contract::execute,
            multisig_prover::contract::instantiate,
            multisig_prover::contract::query,
        )
        .with_reply(multisig_prover::contract::reply);
        let app = &mut protocol.app;
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("anyone"),
                &multisig_prover::msg::InstantiateMsg {
                    admin_address: admin_address.to_string(),
                    gateway_address: gateway_address.to_string(),
                    multisig_address: protocol.multisig.contract_addr.to_string(),
                    service_registry_address: protocol.service_registry.contract_addr.to_string(),
                    voting_verifier_address: voting_verifier_address.to_string(),
                    destination_chain_id: Uint256::zero(),
                    signing_threshold: Threshold::try_from((2, 3)).unwrap().try_into().unwrap(),
                    service_name: protocol.service_name.to_string(),
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

        MultisigProverContract {
            contract_addr,
            admin_addr: admin_address,
        }
    }
}

impl Contract for MultisigProverContract {
    type QMsg = multisig_prover::msg::QueryMsg;
    type ExMsg = multisig_prover::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
