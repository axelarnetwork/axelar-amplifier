#[cfg(test)]
mod test {

    use axelar_wasm_std::nonempty;
    use connection_router::state::ChainName;
    use cosmwasm_std::{coins, Addr, Binary, Deps, Env, HexBinary, StdResult, Uint128, Uint256};
    use cw_multi_test::{App, ContractWrapper, Executor};

    use multisig::key::PublicKey;

    const AXL_DENOMINATION: &str = "uaxl";
    #[test]
    fn test() {
        let mut protocol = setup_protocol("validators".to_string().try_into().unwrap());
        let chains = vec![
            "Ethereum".to_string().try_into().unwrap(),
            "Polygon".to_string().try_into().unwrap(),
        ];
        let workers = vec![
            (Addr::unchecked("worker1"), chains.clone()),
            (Addr::unchecked("worker2"), chains.clone()),
        ];
        register_workers(
            &mut protocol.app,
            protocol.service_registry_address.clone(),
            protocol.multisig_address.clone(),
            protocol.service_name.clone(),
            protocol.governance_address.clone(),
            workers.clone(),
            protocol.genesis.clone(),
        );
        let _chain1 = setup_chain(
            &mut protocol.app,
            protocol.router_address.clone(),
            protocol.service_registry_address.clone(),
            protocol.rewards_address.clone(),
            protocol.multisig_address.clone(),
            protocol.governance_address.clone(),
            protocol.genesis.clone(),
            protocol.service_name.clone(),
            chains.get(0).unwrap().clone(),
        );
        let _chain2 = setup_chain(
            &mut protocol.app,
            protocol.router_address.clone(),
            protocol.service_registry_address.clone(),
            protocol.rewards_address.clone(),
            protocol.multisig_address.clone(),
            protocol.governance_address.clone(),
            protocol.genesis.clone(),
            protocol.service_name.clone(),
            chains.get(1).unwrap().clone(),
        );
    }

    #[allow(dead_code)]
    struct Protocol {
        genesis: Addr, // holds u128::max coins, can use to send coins to other addresses
        governance_address: Addr,
        router_address: Addr,
        router_admin_address: Addr,
        multisig_address: Addr,
        service_registry_address: Addr,
        service_name: nonempty::String,
        rewards_address: Addr,
        app: App,
    }

    fn setup_protocol(service_name: nonempty::String) -> Protocol {
        let genesis = Addr::unchecked("genesis");
        let mut app = App::new(|router, _, storage| {
            router
                .bank
                .init_balance(storage, &genesis, coins(u128::MAX, AXL_DENOMINATION))
                .unwrap()
        });
        let router_admin_address = Addr::unchecked("admin");
        let governance_address = Addr::unchecked("governance");

        let router_address = instantiate_connection_router(
            &mut app,
            connection_router::msg::InstantiateMsg {
                admin_address: router_admin_address.to_string(),
                governance_address: governance_address.to_string(),
            },
        );
        let rewards_address = instantiate_rewards(
            &mut app,
            rewards::msg::InstantiateMsg {
                governance_address: governance_address.to_string(),
                rewards_denom: AXL_DENOMINATION.to_string(),
                params: rewards::msg::Params {
                    epoch_duration: nonempty::Uint64::try_from(10u64).unwrap(),
                    rewards_per_epoch: Uint128::from(100u128).try_into().unwrap(),
                    participation_threshold: (1, 2).try_into().unwrap(),
                },
            },
        );
        let multisig_address = instantiate_multisig(
            &mut app,
            multisig::msg::InstantiateMsg {
                rewards_address: rewards_address.to_string(),
                governance_address: governance_address.to_string(),
                grace_period: 2,
            },
        );
        let service_registry_address = instantiate_service_registry(
            &mut app,
            service_registry::msg::InstantiateMsg {
                governance_account: governance_address.to_string(),
            },
        );

        Protocol {
            genesis,
            governance_address,
            router_address,
            router_admin_address,
            multisig_address,
            service_registry_address,
            service_name,
            rewards_address,
            app,
        }
    }

    fn register_workers(
        app: &mut App,
        service_registry: Addr,
        multisig: Addr,
        service_name: nonempty::String,
        governance_addr: Addr,
        workers: Vec<(Addr, Vec<ChainName>)>,
        genesis: Addr,
    ) {
        let min_worker_bond = Uint128::new(100);
        app.execute_contract(
            governance_addr.clone(),
            service_registry.clone(),
            &service_registry::msg::ExecuteMsg::RegisterService {
                service_name: service_name.to_string(),
                service_contract: Addr::unchecked("nowhere"),
                min_num_workers: 0,
                max_num_workers: Some(100),
                min_worker_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
            &[],
        )
        .unwrap();

        app.execute_contract(
            governance_addr,
            service_registry.clone(),
            &service_registry::msg::ExecuteMsg::AuthorizeWorkers {
                workers: workers
                    .iter()
                    .map(|(worker, _)| worker.to_string())
                    .collect(),
                service_name: service_name.to_string(),
            },
            &[],
        )
        .unwrap();

        for (worker, chains) in workers {
            app.send_tokens(
                genesis.clone(),
                worker.clone(),
                &coins(min_worker_bond.u128(), AXL_DENOMINATION),
            )
            .unwrap();
            app.execute_contract(
                worker.clone(),
                service_registry.clone(),
                &service_registry::msg::ExecuteMsg::BondWorker {
                    service_name: service_name.to_string(),
                },
                &coins(min_worker_bond.u128(), AXL_DENOMINATION),
            )
            .unwrap();

            app.execute_contract(
                worker.clone(),
                service_registry.clone(),
                &service_registry::msg::ExecuteMsg::DeclareChainSupport {
                    service_name: service_name.to_string(),
                    chains: chains.clone(),
                },
                &[],
            )
            .unwrap();

            app.execute_contract(
                worker.clone(),
                multisig.clone(),
                &multisig::msg::ExecuteMsg::RegisterPublicKey {
                    // TODO: figure out key generation and signing
                    public_key: PublicKey::Ecdsa(
                        HexBinary::from_hex(
                            "03f57d1a813febaccbe6429603f9ec57969511b76cd680452dba91fa01f54e756d",
                        )
                        .unwrap(),
                    ),
                },
                &[],
            )
            .unwrap();
        }
    }

    #[allow(dead_code)]
    #[derive(Clone)]
    struct Chain {
        gateway_address: Addr,
        voting_verifier_address: Addr,
        multisig_prover_address: Addr,
        chain_name: ChainName,
    }

    fn setup_chain(
        mut app: &mut App,
        router_address: Addr,
        service_registry_address: Addr,
        rewards_address: Addr,
        multisig_address: Addr,
        governance_address: Addr,
        genesis_address: Addr,
        service_name: nonempty::String,
        chain_name: ChainName,
    ) -> Chain {
        let voting_verifier_address = instantiate_voting_verifier(
            &mut app,
            voting_verifier::msg::InstantiateMsg {
                service_registry_address: service_registry_address.to_string().try_into().unwrap(),
                service_name: service_name.clone(),
                source_gateway_address: "doesn't matter".to_string().try_into().unwrap(),
                voting_threshold: (9, 10).try_into().unwrap(),
                block_expiry: 10,
                confirmation_height: 5,
                source_chain: chain_name.clone(),
                rewards_address: rewards_address.to_string(),
            },
        );
        let gateway_address = instantiate_gateway(
            &mut app,
            gateway::msg::InstantiateMsg {
                router_address: router_address.to_string(),
                verifier_address: voting_verifier_address.to_string(),
            },
        );
        let multisig_prover_address = instantiate_multisig_prover(
            &mut app,
            multisig_prover::msg::InstantiateMsg {
                admin_address: Addr::unchecked("doesn't matter").to_string(),
                gateway_address: gateway_address.to_string(),
                multisig_address: multisig_address.to_string(),
                service_registry_address: service_registry_address.to_string(),
                voting_verifier_address: voting_verifier_address.to_string(),
                destination_chain_id: Uint256::zero(),
                signing_threshold: (2, 3).try_into().unwrap(),
                service_name: service_name.to_string(),
                chain_name: chain_name.to_string(),
                worker_set_diff_threshold: 1,
                encoder: multisig_prover::encoding::Encoder::Abi,
                key_type: multisig::key::KeyType::Ecdsa,
            },
        );
        app.execute_contract(
            Addr::unchecked("doesn't matter"),
            multisig_prover_address.clone(),
            &multisig_prover::msg::ExecuteMsg::UpdateWorkerSet,
            &[],
        )
        .unwrap();
        app.execute_contract(
            governance_address.clone(),
            multisig_address,
            &multisig::msg::ExecuteMsg::AuthorizeCaller {
                contract_address: multisig_prover_address.clone(),
            },
            &[],
        )
        .unwrap();

        app.execute_contract(
            governance_address,
            router_address,
            &connection_router::msg::ExecuteMsg::RegisterChain {
                chain: chain_name.clone(),
                gateway_address: gateway_address.to_string(),
            },
            &[],
        )
        .unwrap();

        app.execute_contract(
            genesis_address.clone(),
            rewards_address.clone(),
            &rewards::msg::ExecuteMsg::AddRewards {
                contract_address: voting_verifier_address.to_string(),
            },
            &coins(1000, AXL_DENOMINATION),
        )
        .unwrap();

        app.execute_contract(
            genesis_address,
            rewards_address.clone(),
            &rewards::msg::ExecuteMsg::AddRewards {
                contract_address: multisig_prover_address.to_string(),
            },
            &coins(1000, AXL_DENOMINATION),
        )
        .unwrap();

        Chain {
            gateway_address,
            voting_verifier_address,
            multisig_prover_address,
            chain_name,
        }
    }

    fn instantiate_connection_router(
        app: &mut App,
        instantiate_msg: connection_router::msg::InstantiateMsg,
    ) -> Addr {
        let code = ContractWrapper::new(
            connection_router::contract::execute,
            connection_router::contract::instantiate,
            connection_router::contract::query,
        );
        let code_id = app.store_code(Box::new(code));

        app.instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &instantiate_msg,
            &[],
            "connection_router",
            None,
        )
        .unwrap()
    }

    fn instantiate_multisig(app: &mut App, instantiate_msg: multisig::msg::InstantiateMsg) -> Addr {
        let code = ContractWrapper::new(
            multisig::contract::execute,
            multisig::contract::instantiate,
            multisig::contract::query,
        );
        let code_id = app.store_code(Box::new(code));

        app.instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &instantiate_msg,
            &[],
            "multisig",
            None,
        )
        .unwrap()
    }

    fn instantiate_rewards(app: &mut App, instantiate_msg: rewards::msg::InstantiateMsg) -> Addr {
        let code = ContractWrapper::new(
            rewards::contract::execute,
            rewards::contract::instantiate,
            |_: Deps, _: Env, _: rewards::msg::QueryMsg| -> StdResult<Binary> { todo!() },
        );
        let code_id = app.store_code(Box::new(code));

        app.instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &instantiate_msg,
            &[],
            "rewards",
            None,
        )
        .unwrap()
    }

    fn instantiate_voting_verifier(
        app: &mut App,
        instantiate_msg: voting_verifier::msg::InstantiateMsg,
    ) -> Addr {
        let code = ContractWrapper::new(
            voting_verifier::contract::execute,
            voting_verifier::contract::instantiate,
            voting_verifier::contract::query,
        );
        let code_id = app.store_code(Box::new(code));

        app.instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &instantiate_msg,
            &[],
            "voting_verifier",
            None,
        )
        .unwrap()
    }

    fn instantiate_gateway(app: &mut App, instantiate_msg: gateway::msg::InstantiateMsg) -> Addr {
        let code = ContractWrapper::new(
            gateway::contract::execute,
            gateway::contract::instantiate,
            gateway::contract::query,
        );
        let code_id = app.store_code(Box::new(code));

        app.instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &instantiate_msg,
            &[],
            "gateway",
            None,
        )
        .unwrap()
    }

    fn instantiate_service_registry(
        app: &mut App,
        instantiate_msg: service_registry::msg::InstantiateMsg,
    ) -> Addr {
        let code = ContractWrapper::new(
            service_registry::contract::execute,
            service_registry::contract::instantiate,
            service_registry::contract::query,
        );
        let code_id = app.store_code(Box::new(code));

        app.instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &instantiate_msg,
            &[],
            "service_registry",
            None,
        )
        .unwrap()
    }

    fn instantiate_multisig_prover(
        app: &mut App,
        instantiate_msg: multisig_prover::msg::InstantiateMsg,
    ) -> Addr {
        let code = ContractWrapper::new(
            multisig_prover::contract::execute,
            multisig_prover::contract::instantiate,
            multisig_prover::contract::query,
        )
        .with_reply(multisig_prover::contract::reply);
        let code_id = app.store_code(Box::new(code));

        app.instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &instantiate_msg,
            &[],
            "multisig_prover",
            None,
        )
        .unwrap()
    }
}
