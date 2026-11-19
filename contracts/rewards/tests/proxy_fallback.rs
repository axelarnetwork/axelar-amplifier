#![allow(clippy::unwrap_used)] // Test fixtures and assertions.

//! Tests reward distribution against a bank module that rejects transfers to chosen addresses,
//! the way the chain's bank module rejects transfers to blocked module accounts.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use cosmwasm_schema::serde::de::DeserializeOwned;
use cosmwasm_std::{
    coins, Addr, Api, BankMsg, BankQuery, Binary, BlockInfo, CustomMsg, CustomQuery, Querier,
    Storage, Uint128,
};
use cw_multi_test::error::{bail, AnyResult};
use cw_multi_test::{
    App, AppBuilder, AppResponse, Bank, BankKeeper, BankSudo, ContractWrapper, CosmosRouter,
    Executor, Module,
};
use rewards::msg::{ExecuteMsg, InstantiateMsg, Params, PoolId};
use router_api::{chain_name, cosmos_addr};

const DENOM: &str = "uaxl";

#[derive(Default)]
struct RejectingBank {
    bank: BankKeeper,
    rejected: Rc<RefCell<BTreeSet<String>>>,
    /// Recipients of all attempted transfers, in order
    attempts: Rc<RefCell<Vec<String>>>,
}

impl Bank for RejectingBank {}

impl Module for RejectingBank {
    type ExecT = BankMsg;
    type QueryT = BankQuery;
    type SudoT = BankSudo;

    fn execute<E, Q>(
        &self,
        api: &dyn Api,
        storage: &mut dyn Storage,
        router: &dyn CosmosRouter<ExecC = E, QueryC = Q>,
        block: &BlockInfo,
        sender: Addr,
        msg: BankMsg,
    ) -> AnyResult<AppResponse>
    where
        E: CustomMsg + DeserializeOwned + 'static,
        Q: CustomQuery + DeserializeOwned + 'static,
    {
        if let BankMsg::Send { to_address, .. } = &msg {
            self.attempts.borrow_mut().push(to_address.clone());
            if self.rejected.borrow().contains(to_address) {
                bail!("bank rejects recipient {to_address}");
            }
        }
        self.bank.execute(api, storage, router, block, sender, msg)
    }

    fn query(
        &self,
        api: &dyn Api,
        storage: &dyn Storage,
        querier: &dyn Querier,
        block: &BlockInfo,
        msg: BankQuery,
    ) -> AnyResult<Binary> {
        self.bank.query(api, storage, querier, block, msg)
    }

    fn sudo<E, Q>(
        &self,
        api: &dyn Api,
        storage: &mut dyn Storage,
        router: &dyn CosmosRouter<ExecC = E, QueryC = Q>,
        block: &BlockInfo,
        msg: BankSudo,
    ) -> AnyResult<AppResponse>
    where
        E: CustomMsg + DeserializeOwned + 'static,
        Q: CustomQuery + DeserializeOwned + 'static,
    {
        self.bank.sudo(api, storage, router, block, msg)
    }
}

fn instantiate_rewards(app: &mut App<RejectingBank>, sender: &Addr, governance: &Addr) -> Addr {
    let code = ContractWrapper::new(
        rewards::contract::execute,
        rewards::contract::instantiate,
        rewards::contract::query,
    )
    .with_reply(rewards::contract::reply);
    let code_id = app.store_code(Box::new(code));

    app.instantiate_contract(
        code_id,
        sender.clone(),
        &InstantiateMsg {
            governance_address: governance.to_string(),
            rewards_denom: DENOM.into(),
        },
        &[],
        "rewards",
        None,
    )
    .unwrap()
}

/// Creates a pool that pays 100 per epoch of 10 blocks
fn execute_create_pool(
    app: &mut App<RejectingBank>,
    rewards: &Addr,
    governance: &Addr,
    pool_id: &PoolId,
) {
    app.execute_contract(
        governance.clone(),
        rewards.clone(),
        &ExecuteMsg::CreatePool {
            params: Params {
                epoch_duration: 10u64.try_into().unwrap(),
                rewards_per_epoch: Uint128::new(100).try_into().unwrap(),
                participation_threshold: (1, 2).try_into().unwrap(),
            },
            pool_id: pool_id.clone(),
        },
        &[],
    )
    .unwrap();
}

fn execute_add_rewards(
    app: &mut App<RejectingBank>,
    rewards: &Addr,
    sender: &Addr,
    pool_id: &PoolId,
    amount: u128,
) {
    app.execute_contract(
        sender.clone(),
        rewards.clone(),
        &ExecuteMsg::AddRewards {
            pool_id: pool_id.clone(),
        },
        &coins(amount, DENOM),
    )
    .unwrap();
}

fn execute_record_participation(
    app: &mut App<RejectingBank>,
    rewards: &Addr,
    pool_contract: &Addr,
    pool_id: &PoolId,
    verifier: &Addr,
) {
    app.execute_contract(
        pool_contract.clone(),
        rewards.clone(),
        &ExecuteMsg::RecordParticipation {
            chain_name: pool_id.chain_name.clone(),
            event_id: "some event".try_into().unwrap(),
            verifier_address: verifier.to_string(),
        },
        &[],
    )
    .unwrap();
}

fn execute_set_verifier_proxy(
    app: &mut App<RejectingBank>,
    rewards: &Addr,
    verifier: &Addr,
    proxy: &Addr,
) {
    app.execute_contract(
        verifier.clone(),
        rewards.clone(),
        &ExecuteMsg::SetVerifierProxy {
            proxy_address: proxy.to_string().try_into().unwrap(),
        },
        &[],
    )
    .unwrap();
}

/// A pool holding 300, with one finished epoch in which two verifiers earned 50 each.
/// `verifier` has set `proxy` as its proxy, `other_verifier` has no proxy.
struct Fixture {
    app: App<RejectingBank>,
    rejected: Rc<RefCell<BTreeSet<String>>>,
    attempts: Rc<RefCell<Vec<String>>>,
    rewards: Addr,
    pool_id: PoolId,
    user: Addr,
    other_verifier: Addr,
    verifier: Addr,
    proxy: Addr,
}

impl Fixture {
    fn new() -> Self {
        let user = cosmos_addr!("user");
        let pool_contract = cosmos_addr!("pool_contract");
        let governance = cosmos_addr!("governance");
        // rewards are paid in address order, so the verifier without a proxy is paid first
        let mut verifiers = [cosmos_addr!("verifier_one"), cosmos_addr!("verifier_two")];
        verifiers.sort();
        let [other_verifier, verifier] = verifiers;
        let proxy = cosmos_addr!("proxy");

        let bank = RejectingBank::default();
        let rejected = Rc::clone(&bank.rejected);
        let attempts = Rc::clone(&bank.attempts);
        let mut app = AppBuilder::new()
            .with_bank(bank)
            .build(|router, _, storage| {
                router
                    .bank
                    .bank
                    .init_balance(storage, &user, coins(300, DENOM))
                    .unwrap();
            });

        let rewards = instantiate_rewards(&mut app, &user, &governance);
        let pool_id = PoolId {
            chain_name: chain_name!("mock-chain"),
            contract: pool_contract.to_string(),
        };
        execute_create_pool(&mut app, &rewards, &governance, &pool_id);
        execute_add_rewards(&mut app, &rewards, &user, &pool_id, 300);
        execute_record_participation(
            &mut app,
            &rewards,
            &pool_contract,
            &pool_id,
            &other_verifier,
        );
        execute_record_participation(&mut app, &rewards, &pool_contract, &pool_id, &verifier);
        execute_set_verifier_proxy(&mut app, &rewards, &verifier, &proxy);
        // move past the end of the epoch, so its rewards can be distributed
        app.update_block(|block| block.height = block.height.saturating_add(20));

        // only record the transfers made by distributions
        attempts.borrow_mut().clear();

        Self {
            app,
            rejected,
            attempts,
            rewards,
            pool_id,
            user,
            other_verifier,
            verifier,
            proxy,
        }
    }

    fn reject(&self, addr: &Addr) {
        self.rejected.borrow_mut().insert(addr.to_string());
    }

    fn distribute(&mut self) -> AnyResult<AppResponse> {
        self.app.execute_contract(
            self.user.clone(),
            self.rewards.clone(),
            &ExecuteMsg::DistributeRewards {
                pool_id: self.pool_id.clone(),
                epoch_count: None,
            },
            &[],
        )
    }

    /// Balances of the other verifier, the verifier, its proxy and the rewards contract
    fn balances(&self) -> [u128; 4] {
        [
            &self.other_verifier,
            &self.verifier,
            &self.proxy,
            &self.rewards,
        ]
        .map(|addr| {
            self.app
                .wrap()
                .query_balance(addr, DENOM)
                .unwrap()
                .amount
                .u128()
        })
    }
}

#[test]
fn rewards_go_to_proxy_when_it_accepts_them() {
    let mut fixture = Fixture::new();

    fixture.distribute().unwrap();

    assert_eq!(fixture.balances(), [50, 0, 50, 200]);
}

#[test]
fn rewards_go_to_verifier_when_proxy_rejects_them() {
    let mut fixture = Fixture::new();
    fixture.reject(&fixture.proxy);

    let res = fixture.distribute().unwrap();

    assert_eq!(fixture.balances(), [50, 50, 0, 200]);
    let event = res
        .events
        .iter()
        .find(|event| event.ty == "wasm-proxy_transfer_failed")
        .unwrap();
    assert!(event
        .attributes
        .iter()
        .any(|attr| attr.key == "verifier_address" && attr.value == fixture.verifier.as_str()));

    // the epoch is settled, there is nothing left to distribute
    assert!(fixture.distribute().is_err());
}

#[test]
fn distribution_reverts_when_proxy_and_verifier_reject_rewards() {
    let mut fixture = Fixture::new();
    fixture.reject(&fixture.proxy);
    fixture.reject(&fixture.verifier);
    let state_before = fixture.app.dump_wasm_raw(&fixture.rewards);

    assert!(fixture.distribute().is_err());

    // the other verifier was paid before the failure
    assert_eq!(
        *fixture.attempts.borrow(),
        [&fixture.other_verifier, &fixture.proxy, &fixture.verifier].map(Addr::to_string)
    );
    // nothing is paid or recorded, including that earlier transfer
    assert_eq!(fixture.balances(), [0, 0, 0, 300]);
    assert_eq!(fixture.app.dump_wasm_raw(&fixture.rewards), state_before);

    // once the verifier can receive funds again, the same epoch is paid in full
    fixture
        .rejected
        .borrow_mut()
        .remove(fixture.verifier.as_str());
    fixture.distribute().unwrap();
    assert_eq!(fixture.balances(), [50, 50, 0, 200]);
}
