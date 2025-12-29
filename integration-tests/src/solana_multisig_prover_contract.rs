use axelar_core_std::query::AxelarQueryMsg;
use axelar_wasm_std::hash::Hash;
use axelar_wasm_std::Threshold;
use cosmwasm_std::{Addr, DepsMut, Env};
use cw_multi_test::{ContractWrapper, Executor};
use multisig::key::KeyType;
use router_api::cosmos_addr;
use solana_multisig_prover::contract::{execute, instantiate, query};

use crate::contract::Contract;
use crate::protocol::{emptying_deps_mut, Protocol};

#[derive(Clone)]
pub struct SolanaMultisigProverContract {
    pub contract_addr: Addr,
    pub admin_addr: Addr,
    pub code_id: u64,
}

impl SolanaMultisigProverContract {
    #[allow(clippy::too_many_arguments)]
    pub fn instantiate_contract(
        protocol: &mut Protocol,
        admin_address: Addr,
        gateway_address: Addr,
        voting_verifier_address: Addr,
        chain_codec_address: Addr,
        chain_name: String,
        sig_verifier: Option<Addr>,
        domain_separator: Hash,
        notify_signing_session: bool,
        expect_full_message_payloads: bool,
    ) -> Self {
        let code =
            ContractWrapper::new_with_empty(execute, instantiate, query).with_reply(custom_reply);
        let app = &mut protocol.app;
        let code_id = app.store_code(Box::new(code));

        let contract_addr = app
            .instantiate_contract(
                code_id,
                cosmos_addr!("anyone"),
                &multisig_prover_api::msg::InstantiateMsg {
                    admin_address: admin_address.to_string(),
                    governance_address: protocol.governance_address.to_string(),
                    gateway_address: gateway_address.to_string(),
                    multisig_address: protocol.multisig.contract_addr.to_string(),
                    coordinator_address: protocol.coordinator.contract_addr.to_string(),
                    service_registry_address: protocol.service_registry.contract_addr.to_string(),
                    voting_verifier_address: voting_verifier_address.to_string(),
                    chain_codec_address: chain_codec_address.to_string(),
                    signing_threshold: Threshold::try_from((2u64, 3u64))
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    service_name: protocol.service_name.to_string(),
                    chain_name: chain_name.to_string(),
                    verifier_set_diff_threshold: 0,
                    key_type: KeyType::Ecdsa,
                    sig_verifier_address: sig_verifier.map(|addr| addr.to_string()),
                    domain_separator,
                    notify_signing_session,
                    expect_full_message_payloads,
                },
                &[],
                "multisig_prover",
                None,
            )
            .unwrap();

        SolanaMultisigProverContract {
            contract_addr,
            admin_addr: admin_address,
            code_id,
        }
    }
}

impl Default for SolanaMultisigProverContract {
    fn default() -> Self {
        SolanaMultisigProverContract {
            contract_addr: cosmos_addr!("prover"),
            admin_addr: cosmos_addr!("admin"),
            code_id: 0,
        }
    }
}

fn custom_reply(
    mut deps: DepsMut<AxelarQueryMsg>,
    env: Env,
    msg: cosmwasm_std::Reply,
) -> Result<cosmwasm_std::Response, axelar_wasm_std::error::ContractError> {
    solana_multisig_prover::contract::reply(emptying_deps_mut(&mut deps), env, msg)
}

impl Contract for SolanaMultisigProverContract {
    type QMsg = multisig_prover_api::msg::QueryMsg;
    type ExMsg = multisig_prover_api::msg::ExecuteMsg;

    fn contract_address(&self) -> Addr {
        self.contract_addr.clone()
    }
}
