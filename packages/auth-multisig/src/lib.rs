use cosmwasm_std::Uint64;

pub struct AuthMultisig {
    pub signing_timeout: Uint64,
    pub signing_grace_period: Uint64,
}
