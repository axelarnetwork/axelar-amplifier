use interchain_token_service::TokenId;
use router_api::ChainName;
use sha3::{Digest, Keccak256};
use xrpl_types::types::{XRPLAccountId, XRPLCurrency};

const PREFIX_TOKEN_ID: &[u8] = b"its-interchain-token-id";
const PREFIX_CUSTOM_TOKEN_SALT: &[u8] = b"custom-token-salt";
const TOKEN_FACTORY_DEPLOYER: &[u8; 32] = &[0; 32];

fn token_id(salt: [u8; 32]) -> TokenId {
    let token_id: [u8; 32] = Keccak256::digest(
        [
            Keccak256::digest(PREFIX_TOKEN_ID).as_slice(),
            TOKEN_FACTORY_DEPLOYER,
            &salt,
        ]
        .concat(),
    )
    .into();
    TokenId::new(token_id)
}

fn linked_token_deploy_salt(
    chain_name_hash: [u8; 32],
    deployer: &XRPLAccountId,
    salt: [u8; 32],
) -> [u8; 32] {
    Keccak256::digest(
        [
            Keccak256::digest(PREFIX_CUSTOM_TOKEN_SALT).as_slice(),
            &chain_name_hash,
            &deployer.as_bytes(),
            &salt,
        ]
        .concat(),
    )
    .into()
}

pub fn linked_token_id(
    chain_name_hash: [u8; 32],
    deployer: &XRPLAccountId,
    salt: [u8; 32],
) -> TokenId {
    token_id(linked_token_deploy_salt(chain_name_hash, deployer, salt))
}

pub fn chain_name_hash(chain_name: ChainName) -> [u8; 32] {
    Keccak256::digest(chain_name.to_string()).into()
}

pub fn currency_hash(currency: &XRPLCurrency) -> [u8; 32] {
    Keccak256::digest(currency.as_bytes()).into()
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use cosmwasm_std::HexBinary;
    use router_api::ChainName;
    use xrpl_types::types::{XRPLAccountId, XRPLCurrency};

    #[test]
    pub fn token_id() {
        let salt = [0u8; 32];
        let token_id = super::token_id(salt);
        goldie::assert!(token_id.to_string());
    }

    #[test]
    pub fn linked_token_deploy_salt() {
        let chain_name_hash = [0u8; 32];
        let deployer = &XRPLAccountId::from([0u8; 20]);
        let salt = [0u8; 32];

        let deploy_salt = super::linked_token_deploy_salt(chain_name_hash, deployer, salt);
        goldie::assert!(HexBinary::from(deploy_salt).to_string());
    }

    #[test]
    pub fn linked_token_id() {
        let chain_name_hash = [0u8; 32];
        let deployer = &XRPLAccountId::from([0u8; 20]);
        let salt = [0u8; 32];

        let token_id = super::linked_token_id(chain_name_hash, deployer, salt);
        goldie::assert!(token_id.to_string());
    }

    #[test]
    pub fn chain_name_hash() {
        let chain_name = ChainName::from_str("xrpl").unwrap();
        let chain_name_hash = super::chain_name_hash(chain_name);
        goldie::assert!(HexBinary::from(chain_name_hash).to_string());
    }

    #[test]
    pub fn currency_hash() {
        let currency = XRPLCurrency::XRP;
        let currency_hash = super::currency_hash(&currency);
        goldie::assert!(HexBinary::from(currency_hash).to_string());
    }
}
