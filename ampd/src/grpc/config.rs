pub struct Config {
    pub coordinator: TMAddress,
    pub chains: Vec<ChainConfig>,
}

pub struct ChainConfig {
    pub chain_name: ChainName,
    pub voting_verifier: TMAddress,
    pub multisig_prover: TMAddress,
    pub multisig: TMAddress,
}
