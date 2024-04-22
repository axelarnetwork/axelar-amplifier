use crate::{contract::Contract, protocol::Protocol};
use axelar_wasm_std::Threshold;
use cosmwasm_std::Addr;
use cw_multi_test::{ContractWrapper, Executor};

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
        xrpl_multisig_address: String,
    ) -> Self {
        let code = ContractWrapper::new(
            xrpl_multisig_prover::contract::execute,
            xrpl_multisig_prover::contract::instantiate,
            xrpl_multisig_prover::contract::query,
        )
        .with_reply(xrpl_multisig_prover::contract::reply);
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
                    axelar_multisig_address: protocol.multisig.contract_addr.to_string(),
                    monitoring_address: protocol.monitoring.contract_addr.to_string(),
                    service_registry_address: protocol.service_registry.contract_addr.to_string(),
                    voting_verifier_address: voting_verifier_address.to_string(),
                    signing_threshold: Threshold::try_from((2, 3)).unwrap().try_into().unwrap(),
                    service_name: protocol.service_name.to_string(),
                    worker_set_diff_threshold: 0,
                    xrpl_fee: 30,
                    xrpl_multisig_address: xrpl_multisig_address.clone(),
                    ticket_count_threshold: 1,
                    next_sequence_number: 44218446,
                    last_assigned_ticket_number: 44218195,
                    available_tickets: vec![
                        vec![],
                        (44218195..44218200).collect::<Vec<_>>()
                    ].concat(),
                    xrp_denom: "uxrp".to_string(),
                    relayer_address: Addr::unchecked("relayer").to_string(),
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

impl Contract for XRPLMultisigProverContract {
    type QMsg = xrpl_multisig_prover::msg::QueryMsg;
    type ExMsg = xrpl_multisig_prover::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
