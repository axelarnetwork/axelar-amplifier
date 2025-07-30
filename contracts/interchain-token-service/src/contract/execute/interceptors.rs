use axelar_wasm_std::{nonempty, FnExt};
use cosmwasm_std::{OverflowError, Storage, Uint256};
use error_stack::{bail, ensure, report, Result, ResultExt};
use interchain_token_service_std::{
    DeployInterchainToken, InterchainTransfer, RegisterTokenMetadata, TokenId,
};
use router_api::ChainNameRaw;

use super::Error;
use crate::shared::NumBits;
use crate::state::{self, TokenConfig, TokenDeploymentType, TokenInstance};

pub fn subtract_supply_amount(
    storage: &mut dyn Storage,
    chain: &ChainNameRaw,
    transfer: &InterchainTransfer,
) -> Result<(), Error> {
    let mut token = try_load_token_instance(storage, chain.clone(), transfer.token_id)?;

    token.supply = token
        .supply
        .checked_sub(transfer.amount)
        .change_context_lazy(|| Error::TokenSupplyInvariantViolated {
            token_id: transfer.token_id,
            chain: chain.clone(),
        })?;

    state::save_token_instance(storage, chain.clone(), transfer.token_id, &token)
        .change_context(Error::State)
}

pub fn add_supply_amount(
    storage: &mut dyn Storage,
    chain: &ChainNameRaw,
    transfer: &InterchainTransfer,
) -> Result<(), Error> {
    let mut token = try_load_token_instance(storage, chain.clone(), transfer.token_id)?;

    token.supply = token
        .supply
        .checked_add(transfer.amount)
        .change_context_lazy(|| Error::TokenSupplyInvariantViolated {
            token_id: transfer.token_id,
            chain: chain.clone(),
        })?;

    state::save_token_instance(storage, chain.clone(), transfer.token_id, &token)
        .change_context(Error::State)
}

pub fn apply_scaling_factor_to_amount(
    storage: &dyn Storage,
    source_chain: &ChainNameRaw,
    destination_chain: &ChainNameRaw,
    mut transfer: InterchainTransfer,
) -> Result<InterchainTransfer, Error> {
    transfer.amount = destination_amount(
        storage,
        source_chain,
        destination_chain,
        transfer.token_id,
        transfer.amount,
    )?;

    Ok(transfer)
}

pub fn deploy_token_to_source_chain(
    storage: &mut dyn Storage,
    chain: &ChainNameRaw,
    token_id: TokenId,
    decimals: u8,
) -> Result<(), Error> {
    match state::may_load_token_config(storage, &token_id).change_context(Error::State)? {
        Some(TokenConfig { origin_chain, .. }) => {
            ensure_matching_original_deployment(storage, origin_chain, chain, token_id, decimals)?;
        }
        None => {
            // Token is being deployed for the first time
            let token_config = TokenConfig {
                origin_chain: chain.clone(),
            };
            state::save_token_config(storage, token_id, &token_config)
                .and_then(|_| {
                    state::save_token_instance(
                        storage,
                        chain.clone(),
                        token_id,
                        &TokenInstance::new_on_origin(decimals),
                    )
                })
                .change_context(Error::State)?;
        }
    }

    Ok(())
}

pub fn deploy_token_to_destination_chain(
    storage: &mut dyn Storage,
    chain: &ChainNameRaw,
    token_id: TokenId,
    decimals: u8,
    deployment_type: TokenDeploymentType,
) -> Result<(), Error> {
    ensure!(
        state::may_load_token_instance(storage, chain.clone(), token_id)
            .change_context(Error::State)?
            .is_none(),
        Error::TokenAlreadyDeployed {
            token_id,
            chain: chain.to_owned(),
        }
    );

    state::save_token_instance(
        storage,
        chain.clone(),
        token_id,
        &TokenInstance::new(&deployment_type, decimals),
    )
    .change_context(Error::State)
    .map(|_| ())
}

pub fn calculate_scaling_factor(
    storage: &dyn Storage,
    source_chain: &ChainNameRaw,
    destination_chain: &ChainNameRaw,
    mut deploy_token: DeployInterchainToken,
) -> Result<DeployInterchainToken, Error> {
    deploy_token.decimals = destination_token_decimals(
        storage,
        source_chain,
        destination_chain,
        deploy_token.decimals,
    )?;

    Ok(deploy_token)
}

fn ensure_matching_original_deployment(
    storage: &dyn Storage,
    origin_chain: ChainNameRaw,
    chain: &ChainNameRaw,
    token_id: TokenId,
    decimals: u8,
) -> Result<(), Error> {
    ensure!(
        origin_chain == *chain,
        Error::TokenDeployedFromNonOriginChain {
            token_id,
            origin_chain: origin_chain.to_owned(),
            chain: chain.clone(),
        }
    );

    let token_instance = state::may_load_token_instance(storage, origin_chain.clone(), token_id)
        .change_context(Error::State)?
        .ok_or(report!(Error::TokenNotDeployed {
            token_id,
            chain: origin_chain.clone()
        }))?;
    ensure!(
        token_instance.decimals == decimals,
        Error::TokenDeployedDecimalsMismatch {
            token_id,
            chain: chain.clone(),
            expected: token_instance.decimals,
            actual: decimals
        }
    );

    Ok(())
}

fn try_load_token_instance(
    storage: &dyn Storage,
    chain: ChainNameRaw,
    token_id: TokenId,
) -> Result<TokenInstance, Error> {
    state::may_load_token_instance(storage, chain.clone(), token_id)
        .change_context(Error::State)?
        .ok_or(report!(Error::TokenNotDeployed { token_id, chain }))
}

/// Calculates the destination token decimals.
///
/// The destination chain's token decimals are calculated and saved as following:
/// 1) If the source chain's `max_uint` is less than or equal to the destination chain's `max_uint`,
///    the source chain's token decimals are used.
/// 2) Otherwise, the minimum of the source chain's token decimals and the source chain's
///    `max_target_decimals` is used.
fn destination_token_decimals(
    storage: &dyn Storage,
    source_chain: &ChainNameRaw,
    destination_chain: &ChainNameRaw,
    source_token_decimals: u8,
) -> Result<u8, Error> {
    let source_chain_config =
        state::load_chain_config(storage, source_chain).change_context(Error::State)?;
    let destination_chain_config =
        state::load_chain_config(storage, destination_chain).change_context(Error::State)?;

    if source_chain_config
        .truncation
        .max_uint_bits
        .le(&destination_chain_config.truncation.max_uint_bits)
    {
        source_token_decimals
    } else {
        destination_chain_config
            .truncation
            .max_decimals_when_truncating
            .min(source_token_decimals)
    }
    .then(Result::Ok)
}

/// Calculates the destination on token transfer amount.
///
/// The amount is calculated based on the token decimals on the source and destination chains.
/// The calculation is done as following:
/// 1) `destination_amount` = `source_amount` * 10 ^ (`destination_chain_decimals` - `source_chain_decimals`)
/// 3) If new_amount is greater than the destination chain's `max_uint`, the translation
///    fails.
/// 4) If new_amount is zero, the translation fails.
fn destination_amount(
    storage: &dyn Storage,
    source_chain: &ChainNameRaw,
    destination_chain: &ChainNameRaw,
    token_id: TokenId,
    source_amount: nonempty::Uint256,
) -> Result<nonempty::Uint256, Error> {
    let source_token = try_load_token_instance(storage, source_chain.clone(), token_id)?;
    let destination_token = try_load_token_instance(storage, destination_chain.clone(), token_id)?;

    let (source_decimals, destination_decimals) =
        (source_token.decimals, destination_token.decimals);

    if source_decimals == destination_decimals {
        return Ok(source_amount);
    }

    let destination_max_uint_bits = state::load_chain_config(storage, destination_chain)
        .change_context(Error::State)?
        .truncation
        .max_uint_bits;

    // It's intentionally written in this way since the end result may still be fine even if
    //     1) amount * (10 ^ (dest_chain_decimals)) overflows
    //     2) amount / (10 ^ (src_chain_decimals)) is zero
    let scaling_factor = Uint256::from_u128(10)
        .checked_pow(source_decimals.abs_diff(destination_decimals).into())
        .change_context_lazy(|| Error::InvalidTransferAmount {
            source_chain: source_chain.to_owned(),
            destination_chain: destination_chain.to_owned(),
            amount: source_amount,
        })?;
    let destination_amount = if source_decimals > destination_decimals {
        source_amount
            .checked_div(scaling_factor)
            .expect("scaling_factor must be non-zero")
    } else {
        source_amount
            .checked_mul(scaling_factor)
            .change_context_lazy(|| Error::InvalidTransferAmount {
                source_chain: source_chain.to_owned(),
                destination_chain: destination_chain.to_owned(),
                amount: source_amount,
            })?
    };

    if amount_overflows(destination_amount, destination_max_uint_bits) {
        bail!(Error::InvalidTransferAmount {
            source_chain: source_chain.to_owned(),
            destination_chain: destination_chain.to_owned(),
            amount: source_amount,
        })
    }

    nonempty::Uint256::try_from(destination_amount).change_context_lazy(|| {
        Error::InvalidTransferAmount {
            source_chain: source_chain.to_owned(),
            destination_chain: destination_chain.to_owned(),
            amount: source_amount,
        }
    })
}

fn amount_overflows(amount: Uint256, target_chain_max_bits: NumBits) -> bool {
    match amount.checked_shr(target_chain_max_bits.into()) {
        Ok(res) => res.gt(&Uint256::zero()),
        // this overflow error occurs when trying to shift 256 bits or more.
        // But this can only happen if max_bits is >= 256, and amount itself is only 256 bits.
        // So in this case, amount cannot possibly overflow the max uint of the target chain
        Err(OverflowError { operation: _ }) => false,
    }
}

pub fn register_custom_token(
    storage: &mut dyn Storage,
    source_chain: ChainNameRaw,
    register_token: RegisterTokenMetadata,
) -> Result<(), Error> {
    let existing_token = state::may_load_custom_token(
        storage,
        source_chain.clone(),
        register_token.token_address.clone(),
    )
    .change_context(Error::State)?;

    if let Some(existing_token) = existing_token {
        ensure!(
            existing_token.decimals == register_token.decimals,
            Error::TokenDecimalsMismatch {
                token_address: register_token.token_address,
                existing_decimals: existing_token.decimals,
                new_decimals: register_token.decimals
            }
        );
    } else {
        state::save_custom_token_metadata(storage, source_chain, register_token)
            .change_context(Error::State)?;
    }

    Ok(())
}

#[cfg(test)]
mod test {

    use assert_ok::assert_ok;
    use axelar_wasm_std::assert_err_contains;
    use cosmwasm_std::testing::{MockApi, MockStorage};
    use cosmwasm_std::{HexBinary, Uint256};
    use interchain_token_service_std::{
        DeployInterchainToken, InterchainTransfer, RegisterTokenMetadata,
    };
    use router_api::ChainNameRaw;

    use super::{register_custom_token, Error};
    use crate::contract::execute::interceptors;
    use crate::msg;
    use crate::msg::TruncationConfig;
    use crate::state::{self, ChainConfig, TokenDeploymentType, TokenInstance};

    #[test]
    fn register_custom_token_allows_reregistration() {
        let mut storage = MockStorage::new();
        let source_chain = ChainNameRaw::try_from("source-chain").unwrap();
        let register_token_msg = RegisterTokenMetadata {
            decimals: 6,
            token_address: HexBinary::from([0; 32]).try_into().unwrap(),
        };
        assert_ok!(register_custom_token(
            &mut storage,
            source_chain.clone(),
            register_token_msg.clone()
        ));
        assert_ok!(register_custom_token(
            &mut storage,
            source_chain,
            register_token_msg
        ));
    }

    #[test]
    fn register_custom_token_errors_on_decimals_mismatch() {
        let mut storage = MockStorage::new();
        let source_chain = ChainNameRaw::try_from("source-chain").unwrap();
        let register_token_msg = RegisterTokenMetadata {
            decimals: 6,
            token_address: HexBinary::from([0; 32]).try_into().unwrap(),
        };
        assert_ok!(register_custom_token(
            &mut storage,
            source_chain.clone(),
            register_token_msg.clone()
        ));
        assert_err_contains!(
            register_custom_token(
                &mut storage,
                source_chain,
                RegisterTokenMetadata {
                    decimals: 12,
                    ..register_token_msg
                }
            ),
            Error,
            Error::TokenDecimalsMismatch { .. }
        );
    }

    #[test]
    fn apply_scaling_factor_to_amount_when_source_decimals_are_bigger() {
        let mut storage = MockStorage::new();
        let source_chain: ChainNameRaw = "sourcechain".try_into().unwrap();
        let destination_chain: ChainNameRaw = "destinationchain".try_into().unwrap();
        let transfer = InterchainTransfer {
            token_id: [1u8; 32].into(),
            source_address: b"source_address".to_vec().try_into().unwrap(),
            destination_address: b"destination_address".to_vec().try_into().unwrap(),
            amount: Uint256::from(1_000_000_000_000u128).try_into().unwrap(),
            data: None,
        };

        state::save_token_instance(
            &mut storage,
            source_chain.clone(),
            transfer.token_id,
            &TokenInstance::new_on_origin(18),
        )
        .unwrap();
        state::save_token_instance(
            &mut storage,
            destination_chain.clone(),
            transfer.token_id,
            &TokenInstance::new(&TokenDeploymentType::Trustless, 12),
        )
        .unwrap();
        state::save_chain_config(
            &mut storage,
            &destination_chain,
            &ChainConfig::new(
                msg::ChainConfig {
                    chain: destination_chain.clone(),
                    its_edge_contract: "itsedgecontract".to_string().try_into().unwrap(),
                    truncation: TruncationConfig {
                        max_uint_bits: 32u32.try_into().unwrap(),
                        max_decimals_when_truncating: 6,
                    },
                    msg_translator: MockApi::default()
                        .addr_make("translation_contract")
                        .to_string()
                        .parse()
                        .unwrap(),
                },
                &MockApi::default(),
            )
            .unwrap(),
        )
        .unwrap();

        let transfer = assert_ok!(interceptors::apply_scaling_factor_to_amount(
            &storage,
            &source_chain,
            &destination_chain,
            transfer,
        ));
        assert_eq!(
            transfer.amount,
            Uint256::from(1_000_000u128).try_into().unwrap()
        );
    }

    #[test]
    fn apply_scaling_factor_to_amount_when_source_decimals_are_smaller() {
        let mut storage = MockStorage::new();
        let source_chain: ChainNameRaw = "sourcechain".try_into().unwrap();
        let destination_chain: ChainNameRaw = "destinationchain".try_into().unwrap();
        let transfer = InterchainTransfer {
            token_id: [1u8; 32].into(),
            source_address: b"source_address".to_vec().try_into().unwrap(),
            destination_address: b"destination_address".to_vec().try_into().unwrap(),
            amount: Uint256::from(1_000_000u128).try_into().unwrap(),
            data: None,
        };

        state::save_token_instance(
            &mut storage,
            source_chain.clone(),
            transfer.token_id,
            &TokenInstance::new_on_origin(12),
        )
        .unwrap();
        state::save_token_instance(
            &mut storage,
            destination_chain.clone(),
            transfer.token_id,
            &TokenInstance::new(&TokenDeploymentType::Trustless, 18),
        )
        .unwrap();
        state::save_chain_config(
            &mut storage,
            &destination_chain,
            &ChainConfig::new(
                msg::ChainConfig {
                    chain: destination_chain.clone(),
                    its_edge_contract: "itsedgecontract".to_string().try_into().unwrap(),
                    truncation: TruncationConfig {
                        max_uint_bits: 64.try_into().unwrap(),
                        max_decimals_when_truncating: 6,
                    },
                    msg_translator: MockApi::default()
                        .addr_make("translation_contract")
                        .to_string()
                        .parse()
                        .unwrap(),
                },
                &MockApi::default(),
            )
            .unwrap(),
        )
        .unwrap();

        let transfer = assert_ok!(interceptors::apply_scaling_factor_to_amount(
            &storage,
            &source_chain,
            &destination_chain,
            transfer,
        ));
        assert_eq!(
            transfer.amount,
            Uint256::from(1_000_000_000_000u128).try_into().unwrap()
        );
    }

    #[test]
    fn apply_scaling_factor_to_amount_when_source_decimals_are_same() {
        let mut storage = MockStorage::new();
        let source_chain: ChainNameRaw = "sourcechain".try_into().unwrap();
        let destination_chain: ChainNameRaw = "destinationchain".try_into().unwrap();
        let transfer = InterchainTransfer {
            token_id: [1u8; 32].into(),
            source_address: b"source_address".to_vec().try_into().unwrap(),
            destination_address: b"destination_address".to_vec().try_into().unwrap(),
            amount: Uint256::from(1_000_000u128).try_into().unwrap(),
            data: None,
        };

        state::save_token_instance(
            &mut storage,
            source_chain.clone(),
            transfer.token_id,
            &TokenInstance::new_on_origin(12),
        )
        .unwrap();
        state::save_token_instance(
            &mut storage,
            destination_chain.clone(),
            transfer.token_id,
            &TokenInstance::new(&TokenDeploymentType::Trustless, 12),
        )
        .unwrap();
        state::save_chain_config(
            &mut storage,
            &destination_chain,
            &ChainConfig::new(
                msg::ChainConfig {
                    chain: destination_chain.clone(),
                    its_edge_contract: "itsedgecontract".to_string().try_into().unwrap(),
                    truncation: TruncationConfig {
                        max_uint_bits: 64.try_into().unwrap(),
                        max_decimals_when_truncating: 6,
                    },
                    msg_translator: MockApi::default()
                        .addr_make("translation_contract")
                        .to_string()
                        .parse()
                        .unwrap(),
                },
                &MockApi::default(),
            )
            .unwrap(),
        )
        .unwrap();

        let transfer = assert_ok!(interceptors::apply_scaling_factor_to_amount(
            &storage,
            &source_chain,
            &destination_chain,
            transfer,
        ));
        assert_eq!(
            transfer.amount,
            Uint256::from(1_000_000u128).try_into().unwrap()
        );
    }

    #[test]
    fn apply_scaling_factor_to_amount_when_result_overflows() {
        let mut storage = MockStorage::new();
        let source_chain: ChainNameRaw = "sourcechain".try_into().unwrap();
        let destination_chain: ChainNameRaw = "destinationchain".try_into().unwrap();
        let transfer = InterchainTransfer {
            token_id: [1u8; 32].into(),
            source_address: b"source_address".to_vec().try_into().unwrap(),
            destination_address: b"destination_address".to_vec().try_into().unwrap(),
            amount: Uint256::from(u64::MAX).try_into().unwrap(),
            data: None,
        };

        state::save_token_instance(
            &mut storage,
            source_chain.clone(),
            transfer.token_id,
            &TokenInstance::new_on_origin(18),
        )
        .unwrap();
        state::save_token_instance(
            &mut storage,
            destination_chain.clone(),
            transfer.token_id,
            &TokenInstance::new(&TokenDeploymentType::Trustless, 12),
        )
        .unwrap();
        state::save_chain_config(
            &mut storage,
            &destination_chain,
            &ChainConfig::new(
                msg::ChainConfig {
                    chain: destination_chain.clone(),
                    its_edge_contract: "itsedgecontract".to_string().try_into().unwrap(),
                    truncation: TruncationConfig {
                        max_uint_bits: 32.try_into().unwrap(),
                        max_decimals_when_truncating: 6,
                    },
                    msg_translator: MockApi::default()
                        .addr_make("translation_contract")
                        .to_string()
                        .parse()
                        .unwrap(),
                },
                &MockApi::default(),
            )
            .unwrap(),
        )
        .unwrap();

        assert_err_contains!(
            interceptors::apply_scaling_factor_to_amount(
                &storage,
                &source_chain,
                &destination_chain,
                transfer,
            ),
            Error,
            Error::InvalidTransferAmount { .. }
        );
    }

    #[test]
    fn apply_scaling_factor_to_amount_when_result_underflows() {
        let mut storage = MockStorage::new();
        let source_chain: ChainNameRaw = "sourcechain".try_into().unwrap();
        let destination_chain: ChainNameRaw = "destinationchain".try_into().unwrap();
        let transfer = InterchainTransfer {
            token_id: [1u8; 32].into(),
            source_address: b"source_address".to_vec().try_into().unwrap(),
            destination_address: b"destination_address".to_vec().try_into().unwrap(),
            amount: Uint256::from(100_000u128).try_into().unwrap(),
            data: None,
        };

        state::save_token_instance(
            &mut storage,
            source_chain.clone(),
            transfer.token_id,
            &TokenInstance::new_on_origin(18),
        )
        .unwrap();
        state::save_token_instance(
            &mut storage,
            destination_chain.clone(),
            transfer.token_id,
            &TokenInstance::new(&TokenDeploymentType::Trustless, 12),
        )
        .unwrap();
        state::save_chain_config(
            &mut storage,
            &destination_chain,
            &ChainConfig::new(
                msg::ChainConfig {
                    chain: destination_chain.clone(),
                    its_edge_contract: "itsedgecontract".to_string().try_into().unwrap(),
                    truncation: TruncationConfig {
                        max_uint_bits: 32.try_into().unwrap(),
                        max_decimals_when_truncating: 6,
                    },
                    msg_translator: MockApi::default()
                        .addr_make("translation_contract")
                        .to_string()
                        .parse()
                        .unwrap(),
                },
                &MockApi::default(),
            )
            .unwrap(),
        )
        .unwrap();

        assert_err_contains!(
            interceptors::apply_scaling_factor_to_amount(
                &storage,
                &source_chain,
                &destination_chain,
                transfer,
            ),
            Error,
            Error::InvalidTransferAmount { .. }
        );
    }

    #[test]
    fn calculate_scaling_factor_when_source_max_uint_is_bigger() {
        let mut storage = MockStorage::new();
        let source_chain: ChainNameRaw = "sourcechain".try_into().unwrap();
        let destination_chain: ChainNameRaw = "destinationchain".try_into().unwrap();

        state::save_chain_config(
            &mut storage,
            &source_chain,
            &ChainConfig::new(
                msg::ChainConfig {
                    chain: source_chain.clone(),
                    its_edge_contract: "itsedgecontract".to_string().try_into().unwrap(),
                    truncation: TruncationConfig {
                        max_uint_bits: 256.try_into().unwrap(),
                        max_decimals_when_truncating: 12,
                    },
                    msg_translator: MockApi::default()
                        .addr_make("translation_contract")
                        .to_string()
                        .parse()
                        .unwrap(),
                },
                &MockApi::default(),
            )
            .unwrap(),
        )
        .unwrap();
        state::save_chain_config(
            &mut storage,
            &destination_chain,
            &ChainConfig::new(
                msg::ChainConfig {
                    chain: destination_chain.clone(),
                    its_edge_contract: "itsedgecontract".to_string().try_into().unwrap(),
                    truncation: TruncationConfig {
                        max_uint_bits: 128.try_into().unwrap(),
                        max_decimals_when_truncating: 6,
                    },
                    msg_translator: MockApi::default()
                        .addr_make("translation_contract")
                        .to_string()
                        .parse()
                        .unwrap(),
                },
                &MockApi::default(),
            )
            .unwrap(),
        )
        .unwrap();
        let deploy_token = DeployInterchainToken {
            token_id: [1u8; 32].into(),
            name: "token".to_string().try_into().unwrap(),
            symbol: "TKN".to_string().try_into().unwrap(),
            decimals: 9,
            minter: None,
        };

        let deploy_token = assert_ok!(interceptors::calculate_scaling_factor(
            &storage,
            &source_chain,
            &destination_chain,
            deploy_token,
        ));
        assert_eq!(deploy_token.decimals, 6);

        let deploy_token = DeployInterchainToken {
            token_id: [1u8; 32].into(),
            name: "token".to_string().try_into().unwrap(),
            symbol: "TKN".to_string().try_into().unwrap(),
            decimals: 3,
            minter: None,
        };
        let deploy_token = assert_ok!(interceptors::calculate_scaling_factor(
            &storage,
            &source_chain,
            &destination_chain,
            deploy_token,
        ));
        assert_eq!(deploy_token.decimals, 3);
    }

    #[test]
    fn calculate_scaling_factor_when_source_max_uint_is_smaller() {
        let mut storage = MockStorage::new();
        let source_chain: ChainNameRaw = "sourcechain".try_into().unwrap();
        let destination_chain: ChainNameRaw = "destinationchain".try_into().unwrap();

        state::save_chain_config(
            &mut storage,
            &source_chain,
            &ChainConfig::new(
                msg::ChainConfig {
                    chain: source_chain.clone(),
                    its_edge_contract: "itsedgecontract".to_string().try_into().unwrap(),
                    truncation: TruncationConfig {
                        max_uint_bits: 128.try_into().unwrap(),
                        max_decimals_when_truncating: 6,
                    },
                    msg_translator: MockApi::default()
                        .addr_make("translation_contract")
                        .to_string()
                        .parse()
                        .unwrap(),
                },
                &MockApi::default(),
            )
            .unwrap(),
        )
        .unwrap();
        state::save_chain_config(
            &mut storage,
            &destination_chain,
            &ChainConfig::new(
                msg::ChainConfig {
                    chain: destination_chain.clone(),
                    its_edge_contract: "itsedgecontract".to_string().try_into().unwrap(),
                    truncation: TruncationConfig {
                        max_uint_bits: 256.try_into().unwrap(),
                        max_decimals_when_truncating: 6,
                    },
                    msg_translator: MockApi::default()
                        .addr_make("translation_contract")
                        .to_string()
                        .parse()
                        .unwrap(),
                },
                &MockApi::default(),
            )
            .unwrap(),
        )
        .unwrap();

        let deploy_token = DeployInterchainToken {
            token_id: [1u8; 32].into(),
            name: "token".to_string().try_into().unwrap(),
            symbol: "TKN".to_string().try_into().unwrap(),
            decimals: 9,
            minter: None,
        };
        let deploy_token = assert_ok!(interceptors::calculate_scaling_factor(
            &storage,
            &source_chain,
            &destination_chain,
            deploy_token,
        ));
        assert_eq!(deploy_token.decimals, 9);

        let deploy_token = DeployInterchainToken {
            token_id: [1u8; 32].into(),
            name: "token".to_string().try_into().unwrap(),
            symbol: "TKN".to_string().try_into().unwrap(),
            decimals: 3,
            minter: None,
        };
        let deploy_token = assert_ok!(interceptors::calculate_scaling_factor(
            &storage,
            &source_chain,
            &destination_chain,
            deploy_token,
        ));
        assert_eq!(deploy_token.decimals, 3);
    }
}
