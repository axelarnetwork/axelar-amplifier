use cosmrs::tx::Fee;
use cosmrs::Coin;

pub fn zero_fee() -> Fee {
    Fee::from_amount_and_gas(
        Coin {
            denom: "".parse().unwrap(),
            amount: 0,
        },
        0u64,
    )
}
