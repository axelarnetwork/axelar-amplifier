use cosmwasm_std::Addr;
use interchain_token_service::TokenId;
use router_api::ChainName;
use sha3::{Digest, Keccak256};
use xrpl_types::types::{XRPLAccountId, XRPLCurrency};

const PREFIX_TOKEN_ID: &[u8] = b"its-interchain-token-id";
const PREFIX_CUSTOM_TOKEN_SALT: &[u8] = b"custom-token-salt";
const TOKEN_FACTORY_DEPLOYER: &str = "";

fn token_id(salt: [u8; 32]) -> TokenId {
    let token_id: [u8; 32] = Keccak256::digest(
        [
            Keccak256::digest(PREFIX_TOKEN_ID).as_slice(),
            Addr::unchecked(TOKEN_FACTORY_DEPLOYER).as_bytes(),
            &salt,
        ]
        .concat(),
    )
    .into();
    TokenId::new(token_id)
}

fn linked_token_deploy_salt(chain_name_hash: [u8; 32], deployer: &XRPLAccountId, salt: [u8; 32]) -> [u8; 32] {
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

pub fn linked_token_id(chain_name_hash: [u8; 32], deployer: &XRPLAccountId, salt: [u8; 32]) -> TokenId {
    token_id(linked_token_deploy_salt(chain_name_hash, deployer, salt))
}

pub fn chain_name_hash(chain_name: ChainName) -> [u8; 32] {
    Keccak256::digest(chain_name.to_string()).into()
}

pub fn currency_hash(currency: &XRPLCurrency) -> [u8; 32] {
    Keccak256::digest(currency.as_bytes()).into()
}
