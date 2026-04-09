use axelar_wasm_std::migrate_from_version;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{DepsMut, Empty, Env, Response};
use interchain_token_service_std::TokenId;
use router_api::ChainNameRaw;

use crate::state;

pub type MigrateMsg = Empty;

#[cfg_attr(not(feature = "library"), entry_point)]
#[migrate_from_version("1.3")]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    _msg: MigrateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    remove_stellar_xrp_token_instance(deps.storage);
    Ok(Response::default())
}

/// Remove the erroneously linked XRP token instance on Stellar.
/// XRP (token_id ba5a21ca...) was linked to a third-party custom token on Stellar
/// via LinkToken. This must be removed because the lockUnlock/mintBurnFrom asymmetry
/// would allow the custom token owner to drain the XRPL multisig.
fn remove_stellar_xrp_token_instance(storage: &mut dyn cosmwasm_std::Storage) {
    let chain: ChainNameRaw = "stellar".parse().expect("invalid chain name");
    let token_id = TokenId::new(
        <[u8; 32]>::try_from(
            cosmwasm_std::HexBinary::from_hex(
                "ba5a21ca88ef6bba2bfff5088994f90e1077e2a1cc3dcc38bd261f00fce2824f",
            )
            .expect("invalid hex")
            .as_slice(),
        )
        .expect("invalid token id"),
    );

    state::remove_token_instance(storage, chain, token_id);
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::mock_dependencies;

    use super::*;
    use crate::state::{TokenInstance, TokenSupply};

    #[test]
    fn migration_removes_stellar_xrp_token_instance() {
        let mut deps = mock_dependencies();

        let chain: ChainNameRaw = "stellar".parse().unwrap();
        let token_id = TokenId::new(
            <[u8; 32]>::try_from(
                cosmwasm_std::HexBinary::from_hex(
                    "ba5a21ca88ef6bba2bfff5088994f90e1077e2a1cc3dcc38bd261f00fce2824f",
                )
                .unwrap()
                .as_slice(),
            )
            .unwrap(),
        );

        // set up the token instance that should be removed
        state::save_token_instance(
            deps.as_mut().storage,
            chain.clone(),
            token_id,
            &TokenInstance {
                supply: TokenSupply::Untracked,
                decimals: 6,
            },
        )
        .unwrap();

        assert!(state::may_load_token_instance(deps.as_ref().storage, chain.clone(), token_id)
            .unwrap()
            .is_some());

        remove_stellar_xrp_token_instance(deps.as_mut().storage);

        assert!(state::may_load_token_instance(deps.as_ref().storage, chain, token_id)
            .unwrap()
            .is_none());
    }
}
