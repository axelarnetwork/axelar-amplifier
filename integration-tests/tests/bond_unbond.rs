use cosmwasm_std::BlockInfo;

pub mod test_utils;

#[test]
fn workers_can_claim_stake() {
    let test_utils::TestCase {
        mut protocol,
        workers,
        min_worker_bond,
        unbonding_period_days,
        ..
    } = test_utils::setup_test_case();

    let before_balances = test_utils::query_balances(&protocol.app, &workers);

    test_utils::deregister_workers(&mut protocol, &workers);

    // balances don't change after deregistering
    assert_eq!(
        before_balances,
        test_utils::query_balances(&protocol.app, &workers)
    );

    let block = protocol.app.block_info();
    protocol.app.set_block(BlockInfo {
        height: block.height + 1,
        time: protocol
            .app
            .block_info()
            .time
            .plus_days(unbonding_period_days.into()),
        ..block
    });

    test_utils::claim_stakes(&mut protocol, &workers);
    let after_balances = test_utils::query_balances(&protocol.app, &workers);

    for (before_balance, after_balance) in before_balances.into_iter().zip(after_balances) {
        assert_eq!(after_balance, before_balance + min_worker_bond);
    }
}
