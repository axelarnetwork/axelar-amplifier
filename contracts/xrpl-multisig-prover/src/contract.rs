use axelar_wasm_std::{address, killswitch, migrate_from_version, permission_control, FnExt};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Reply, Response,
};
use error_stack::ResultExt;
use multisig::key::PublicKey;

mod execute;
mod query;
mod reply;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{
    Config, AVAILABLE_TICKETS, CONFIG, FEE_RESERVE, LAST_ASSIGNED_TICKET_NUMBER,
    NEXT_SEQUENCE_NUMBER,
};

pub const START_MULTISIG_REPLY_ID: u64 = 1;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let config = Config {
        gateway: address::validate_cosmwasm_address(deps.api, &msg.gateway_address)?,
        multisig: address::validate_cosmwasm_address(deps.api, &msg.multisig_address)?,
        coordinator: address::validate_cosmwasm_address(deps.api, &msg.coordinator_address)?,
        service_registry: address::validate_cosmwasm_address(
            deps.api,
            &msg.service_registry_address,
        )?,
        voting_verifier: address::validate_cosmwasm_address(
            deps.api,
            &msg.voting_verifier_address,
        )?,
        signing_threshold: msg.signing_threshold,
        service_name: msg.service_name,
        chain_name: msg.chain_name,
        verifier_set_diff_threshold: msg.verifier_set_diff_threshold,
        xrpl_multisig: msg.xrpl_multisig_address,
        xrpl_transaction_fee: msg.xrpl_transaction_fee,
        xrpl_base_reserve: msg.xrpl_base_reserve,
        xrpl_owner_reserve: msg.xrpl_owner_reserve,
        ticket_count_threshold: msg.ticket_count_threshold,
    };
    CONFIG.save(deps.storage, &config)?;

    permission_control::set_admin(deps.storage, &deps.api.addr_validate(&msg.admin_address)?)?;
    permission_control::set_governance(
        deps.storage,
        &deps.api.addr_validate(&msg.governance_address)?,
    )?;

    killswitch::init(deps.storage, killswitch::State::Disengaged)?;

    NEXT_SEQUENCE_NUMBER.save(deps.storage, &msg.next_sequence_number)?;
    LAST_ASSIGNED_TICKET_NUMBER.save(deps.storage, &msg.last_assigned_ticket_number)?;
    AVAILABLE_TICKETS.save(deps.storage, &msg.available_tickets)?;
    FEE_RESERVE.save(deps.storage, &msg.initial_fee_reserve)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    let config = CONFIG.load(deps.storage).expect("failed to load config");
    let gateway: &xrpl_gateway::Client =
        &client::ContractClient::new(deps.querier, &config.gateway).into();

    match msg.ensure_permissions(deps.storage, &info.sender)? {
        ExecuteMsg::TrustSet { token_id } => execute::construct_trust_set_proof(
            deps.storage,
            gateway,
            env.contract.address,
            &config,
            token_id,
        ),
        ExecuteMsg::ConstructProof { cc_id, payload } => execute::construct_payment_proof(
            deps.storage,
            deps.querier,
            gateway,
            env.contract.address,
            env.block.height,
            &config,
            cc_id,
            payload,
        ),
        ExecuteMsg::UpdateVerifierSet => {
            execute::update_verifier_set(deps.storage, deps.querier, env)
        }
        ExecuteMsg::ConfirmProverMessage { prover_message } => execute::confirm_prover_message(
            deps.storage,
            deps.querier,
            gateway,
            &config,
            prover_message,
        ),
        ExecuteMsg::TicketCreate => {
            execute::construct_ticket_create_proof(deps.storage, env.contract.address, &config)
        }
        ExecuteMsg::UpdateFeeReserve { new_fee_reserve } => {
            execute::update_fee_reserve(deps, new_fee_reserve)
        }
        ExecuteMsg::UpdateSigningThreshold {
            new_signing_threshold,
        } => execute::update_signing_threshold(deps, new_signing_threshold),
        ExecuteMsg::UpdateXrplTransactionFee {
            new_transaction_fee,
        } => execute::update_xrpl_transaction_fee(deps, new_transaction_fee),
        ExecuteMsg::UpdateXrplReserves {
            new_base_reserve,
            new_owner_reserve,
        } => execute::update_xrpl_reserves(deps, new_base_reserve, new_owner_reserve),
        ExecuteMsg::UpdateAdmin { new_admin_address } => {
            execute::update_admin(deps, new_admin_address)
        }
        ExecuteMsg::ConfirmAddReservesMessage {
            add_reserves_message,
        } => execute::confirm_add_reserves_message(
            deps.storage,
            deps.querier,
            &config,
            add_reserves_message,
        ),
        ExecuteMsg::VerifySignature {
            session_id: _,
            message,
            public_key,
            signature,
            signer_address: _,
        } => execute::verify_signature(
            message,
            &PublicKey::Ecdsa(public_key),
            &multisig::key::Signature::try_from((multisig::key::KeyType::Ecdsa, signature))
                .map_err(|_| ContractError::InvalidSignature)?,
        ),
        ExecuteMsg::DisableExecution => execute::disable_execution(deps),
        ExecuteMsg::EnableExecution => execute::enable_execution(deps),
    }?
    .then(Ok)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(
    deps: DepsMut,
    _env: Env,
    reply: Reply,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    match reply.id {
        START_MULTISIG_REPLY_ID => reply::start_multisig_reply(deps, reply),
        _ => unreachable!("unknown reply ID"),
    }
    .map_err(axelar_wasm_std::error::ContractError::from)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps,
    _env: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::error::ContractError> {
    let config = CONFIG.load(deps.storage)?;
    match msg {
        QueryMsg::Proof {
            multisig_session_id,
        } => to_json_binary(&query::proof(
            deps.storage,
            deps.querier,
            &config.multisig,
            multisig_session_id,
        )?),
        QueryMsg::VerifySignature {
            session_id: _,
            message,
            public_key,
            signature,
            signer_address: _,
        } => to_json_binary(&query::verify_signature(
            message,
            &PublicKey::Ecdsa(public_key),
            &multisig::key::Signature::try_from((multisig::key::KeyType::Ecdsa, signature))
                .map_err(|_| ContractError::InvalidSignature)?,
        )?),
        QueryMsg::CurrentVerifierSet => to_json_binary(&query::current_verifier_set(deps.storage)?),
        QueryMsg::NextVerifierSet => to_json_binary(&query::next_verifier_set(deps.storage)?),
        QueryMsg::MultisigSession { cc_id } => {
            to_json_binary(&query::multisig_session(deps.storage, &cc_id)?)
        }
        QueryMsg::TicketCreate => to_json_binary(&query::ticket_create(
            deps.storage,
            config.ticket_count_threshold,
        )?),
        QueryMsg::IsEnabled => to_json_binary(&killswitch::is_contract_active(deps.storage)),
        QueryMsg::AvailableTickets => to_json_binary(&AVAILABLE_TICKETS.load(deps.storage)?),
        QueryMsg::NextSequenceNumber => to_json_binary(&NEXT_SEQUENCE_NUMBER.load(deps.storage)?),
        QueryMsg::FeeReserve => to_json_binary(&FEE_RESERVE.load(deps.storage)?),
    }
    .change_context(ContractError::SerializeResponse)
    .map_err(axelar_wasm_std::error::ContractError::from)
}

#[cfg_attr(not(feature = "library"), entry_point)]
#[migrate_from_version("1.4")]
pub fn migrate(
    _deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    Ok(Response::default())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use axelar_wasm_std::msg_id::HexTxHash;
    use axelar_wasm_std::permission_control::Permission;
    use axelar_wasm_std::{
        nonempty, permission_control, MajorityThreshold, Threshold, VerificationStatus,
    };
    use cosmwasm_std::testing::{
        message_info, mock_dependencies, mock_env, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{
        from_json, Addr, Empty, Fraction, HexBinary, OwnedDeps, SubMsgResponse, SubMsgResult,
        Uint128, Uint256, Uint64,
    };
    use cw_utils::ParseReplyError;
    use interchain_token_service_std::{
        DeployInterchainToken, HubMessage, InterchainTransfer, LinkToken, Message as ItsMessage,
        RegisterTokenMetadata, TokenId,
    };
    use its_abi_translator::abi::hub_message_abi_encode;
    use multisig::events::Event;
    use multisig::msg::Signer;
    use multisig::types::MultisigState;
    use multisig::verifier_set::VerifierSet;
    use prost::Message;
    use router_api::{ChainName, CrossChainId, Message as RouterMessage};
    use sha3::{Digest, Keccak256};
    use xrpl_types::msg::{XRPLAddReservesMessage, XRPLProverMessage};
    use xrpl_types::types::{
        canonicalize_token_amount, hash_signed_tx, XRPLAccountId, XRPLPaymentAmount, XRPLSequence,
        XRPLTxStatus, XRPLUnsignedTx, XRPLUnsignedTxToSign, XRP_MAX_UINT,
    };

    use super::*;
    use crate::axelar_verifiers::should_update_verifier_set;
    use crate::msg::{ProofResponse, ProofStatus};
    use crate::state::{MultisigSession, UNSIGNED_TX_HASH_TO_TX_INFO};
    use crate::test::test_data::{self, TestOperator};
    use crate::test::test_utils::{
        local_token, mock_querier_handler, mock_querier_handler_with, remote_token, MockResponses,
        ADMIN, CHAIN_NAME, COORDINATOR_ADDRESS, GATEWAY_ADDRESS, GOVERNANCE, LOCAL_TOKEN_ID,
        MULTISIG_ADDRESS, REMOTE_TOKEN_ID, SERVICE_NAME, SERVICE_REGISTRY_ADDRESS,
        VOTING_VERIFIER_ADDRESS, XRPL_MULITISIG_ADDRESS, XRPL_TOKEN_DECIMALS, XRP_TOKEN_ID,
    };
    use crate::xrpl_serialize::XRPLSerialize;

    /// Version deployed on mainnet; the migration test upgrades from it.
    const BASE_VERSION: &str = "1.4.2";

    const RELAYER: &str = "relayer";
    const MULTISIG_SESSION_ID: Uint64 = Uint64::one();

    // Parameters of `setup_test_case`.
    const INITIAL_FEE_RESERVE: u64 = 60_000_000;
    const INITIAL_SEQUENCE_NUMBER: u32 = 44218446;
    const INITIAL_TICKETS: std::ops::Range<u32> = 44218195..44218200;
    /// Fee of every multisig transaction: `xrpl_transaction_fee * (1 + MAX_SIGNERS)`.
    const TX_FEE: u64 = 10 * 33;
    /// XRP the multisig account must keep: the base reserve plus the owner reserve of the
    /// account itself and its 250 tickets.
    const ACCOUNT_RESERVE: u64 = 1_000_000 + 200_000 * 251;
    /// Tickets the multisig can still create: 250 minus the initial tickets.
    const TICKETS_TO_CREATE: u32 = 245;
    const XRPL_DESTINATION: &str = "rKdBdHeBVFC5Fi4phMgpZqmZmh87AsyaVU";

    type TestDeps = OwnedDeps<MockStorage, MockApi, MockQuerier, Empty>;

    pub fn setup_test_case() -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        setup_test_case_with(test_data::operators())
    }

    fn setup_test_case_with(
        operators: Vec<TestOperator>,
    ) -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();
        let api = deps.api;

        deps.querier.update_wasm(mock_querier_handler(
            operators,
            VerificationStatus::SucceededOnSourceChain,
        ));

        instantiate(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN), &[]),
            InstantiateMsg {
                admin_address: api.addr_make(ADMIN).to_string(),
                governance_address: api.addr_make(GOVERNANCE).to_string(),
                gateway_address: api.addr_make(GATEWAY_ADDRESS).to_string(),
                multisig_address: api.addr_make(MULTISIG_ADDRESS).to_string(),
                coordinator_address: api.addr_make(COORDINATOR_ADDRESS).to_string(),
                service_registry_address: api.addr_make(SERVICE_REGISTRY_ADDRESS).to_string(),
                voting_verifier_address: api.addr_make(VOTING_VERIFIER_ADDRESS).to_string(),
                signing_threshold: test_data::threshold(),
                service_name: SERVICE_NAME.to_string(),
                chain_name: CHAIN_NAME.parse().unwrap(),
                xrpl_multisig_address: XRPL_MULITISIG_ADDRESS.parse().unwrap(),
                verifier_set_diff_threshold: 0,
                xrpl_transaction_fee: 10,
                xrpl_base_reserve: 1000000,
                xrpl_owner_reserve: 200000,
                initial_fee_reserve: 60000000,
                ticket_count_threshold: 1,
                next_sequence_number: 44218446,
                last_assigned_ticket_number: 44218195,
                available_tickets: (44218195..44218200).collect::<Vec<_>>(),
            },
        )
        .unwrap();

        deps
    }

    #[test]
    fn make_verifier_set_keeps_highest_weight_when_exceeding_max_signers() {
        use crate::axelar_verifiers::make_verifier_set;
        use crate::state::CONFIG;

        let max_signers = crate::xrpl_multisig::MAX_SIGNERS as usize;
        let api = MockApi::default();
        let valid_pub_key = test_data::operators()[0].pub_key.clone();

        // One more verifier than XRPL's MAX_SIGNERS, each with a distinct weight (1..=N).
        let operators: Vec<TestOperator> = (0..=max_signers)
            .map(|i| TestOperator {
                address: api.addr_make(&format!("verifier{i}")),
                pub_key: valid_pub_key.clone(),
                operator: HexBinary::from(vec![0u8; 20]),
                weight: Uint128::from(i as u128 + 1),
                signature: None,
            })
            .collect();
        let lowest_weight_addr = operators[0].address.clone(); // weight == 1

        let deps = setup_test_case_with(operators.clone());
        let config = CONFIG.load(deps.as_ref().storage).unwrap();

        let verifier_set =
            make_verifier_set(&config, deps.as_ref().querier, mock_env().block.height).unwrap();

        // truncated to the ledger cap
        assert_eq!(verifier_set.signers.len(), max_signers);

        // Tests that the highest-weight verifiers are retained instead of the lowest-weight ones
        let contains = |addr: &Addr| verifier_set.signers.iter().any(|s| s.address == *addr);
        assert!(!contains(&lowest_weight_addr));
        for op in operators.iter().skip(1) {
            assert!(contains(&op.address), "missing {}", op.address);
        }
    }

    fn execute_update_verifier_set(
        deps: DepsMut,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let msg = ExecuteMsg::UpdateVerifierSet {};
        execute(
            deps,
            mock_env(),
            message_info(&MockApi::default().addr_make(ADMIN), &[]),
            msg,
        )
    }

    fn reply_update_verifier_set(
        deps: DepsMut,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let session_id = to_json_binary(&MULTISIG_SESSION_ID).unwrap();
        let event = wasm_prefixed_event(Event::SigningStarted {
            session_id: MULTISIG_SESSION_ID,
            verifier_set_id: "".to_string(),
            pub_keys: HashMap::new(),
            msg: HexBinary::from([0u8; 32]).into(),
            chain_name: "xrpl".parse().unwrap(),
            expires_at: 1000,
        });

        #[allow(deprecated)]
        // TODO: use `msg_responses` instead when the cosmwasm vm is updated to 2.x.x
        let response = SubMsgResponse {
            events: vec![event],
            // the reply data gets protobuf encoded when moving through the wasm module. We need to emulate this behaviour in tests as well
            data: Some(
                prost::bytes::Bytes::from(session_id.to_vec())
                    .encode_to_vec()
                    .into(),
            ),
            msg_responses: vec![],
        };

        reply(
            deps,
            mock_env(),
            Reply {
                id: START_MULTISIG_REPLY_ID,
                result: SubMsgResult::Ok(response),
                payload: vec![].into(),
                gas_used: 0,
            },
        )
    }

    fn confirm_prover_message(
        deps: DepsMut,
        prover_message: XRPLProverMessage,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let msg = ExecuteMsg::ConfirmProverMessage { prover_message };
        execute(
            deps,
            mock_env(),
            message_info(&MockApi::default().addr_make(RELAYER), &[]),
            msg,
        )
    }

    fn execute_update_signing_threshold(
        deps: DepsMut,
        sender: Addr,
        new_signing_threshold: MajorityThreshold,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let msg = ExecuteMsg::UpdateSigningThreshold {
            new_signing_threshold,
        };
        execute(deps, mock_env(), message_info(&sender, &[]), msg)
    }

    fn execute_update_admin(
        deps: DepsMut,
        sender: Addr,
        new_admin_address: String,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let msg = ExecuteMsg::UpdateAdmin { new_admin_address };
        execute(deps, mock_env(), message_info(&sender, &[]), msg)
    }

    fn execute_construct_proof(
        deps: DepsMut,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let outgoing_messages = test_data::outgoing_messages();
        let (message, payload) = outgoing_messages.first().unwrap();
        let msg = ExecuteMsg::ConstructProof {
            cc_id: message.cc_id.clone(),
            payload: payload.clone(),
        };
        execute(
            deps,
            mock_env(),
            message_info(&MockApi::default().addr_make(RELAYER), &[]),
            msg,
        )
    }

    fn wasm_prefixed_event(e: Event) -> cosmwasm_std::Event {
        let mut event: cosmwasm_std::Event = e.into();
        event.ty = format!("wasm-{}", event.ty);
        event
    }

    fn reply_construct_proof(
        deps: DepsMut,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let session_id = to_json_binary(&MULTISIG_SESSION_ID).unwrap();
        let event = wasm_prefixed_event(Event::SigningStarted {
            session_id: MULTISIG_SESSION_ID,
            verifier_set_id: "".to_string(),
            pub_keys: HashMap::new(),
            msg: HexBinary::from([0u8; 32]).into(),
            chain_name: "xrpl".parse().unwrap(),
            expires_at: 1000,
        });

        #[allow(deprecated)]
        // TODO: use `msg_responses` instead when the cosmwasm vm is updated to 2.x.x
        let response = SubMsgResponse {
            events: vec![event],
            // the reply data gets protobuf encoded when moving through the wasm module. We need to emulate this behaviour in tests as well
            data: Some(
                prost::bytes::Bytes::from(session_id.to_vec())
                    .encode_to_vec()
                    .into(),
            ),
            msg_responses: vec![],
        };

        reply(
            deps,
            mock_env(),
            Reply {
                id: START_MULTISIG_REPLY_ID,
                result: SubMsgResult::Ok(response),
                payload: vec![].into(),
                gas_used: 0,
            },
        )
    }

    fn query_proof(
        deps: Deps,
        multisig_session_id: Option<Uint64>,
    ) -> Result<ProofResponse, axelar_wasm_std::error::ContractError> {
        let multisig_session_id = match multisig_session_id {
            Some(id) => id,
            None => MULTISIG_SESSION_ID,
        };

        query(
            deps,
            mock_env(),
            QueryMsg::Proof {
                multisig_session_id,
            },
        )
        .map(|res| from_json(res).unwrap())
    }

    fn query_verifier_set(
        deps: Deps,
    ) -> Result<Option<multisig::verifier_set::VerifierSet>, axelar_wasm_std::error::ContractError>
    {
        query(deps, mock_env(), QueryMsg::CurrentVerifierSet {}).map(|res| from_json(res).unwrap())
    }

    #[test]
    fn migrate_sets_contract_version() {
        let mut deps = setup_test_case();

        cw2::CONTRACT
            .save(
                deps.as_mut().storage,
                &cw2::ContractVersion {
                    contract: CONTRACT_NAME.to_string(),
                    version: BASE_VERSION.to_string(),
                },
            )
            .unwrap();

        migrate(deps.as_mut(), mock_env(), Empty {}).unwrap();

        let contract_version = cw2::get_contract_version(deps.as_mut().storage).unwrap();
        assert_eq!(contract_version.contract, CONTRACT_NAME);
        assert_eq!(contract_version.version, CONTRACT_VERSION);
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn test_instantiation() {
        let api = MockApi::default();
        let instantiator = api.addr_make("instantiator");
        let admin = api.addr_make("admin");
        let governance = api.addr_make("governance");
        let gateway_address = api.addr_make("gateway_address");
        let multisig_address = api.addr_make("multisig_address");
        let coordinator_address = api.addr_make("coordinator_address");
        let service_registry_address = api.addr_make("service_registry_address");
        let voting_verifier_address = api.addr_make("voting_verifier");
        let signing_threshold = Threshold::try_from((
            test_data::threshold().numerator(),
            test_data::threshold().denominator(),
        ))
        .unwrap()
        .try_into()
        .unwrap();
        let service_name = "service_name";
        let chain_name: ChainName = "xrpl".parse().unwrap();
        let xrpl_multisig_address: XRPLAccountId =
            "rGAbJZEzU6WaYv5y1LfyN7LBBcQJ3TxsKC".parse().unwrap();

        let verifier_set_diff_threshold = 0u32;
        let xrpl_transaction_fee = 10u64;
        let xrpl_base_reserve = 1000000u64;
        let xrpl_owner_reserve = 200000u64;
        let initial_fee_reserve = 60000000u64;
        let ticket_count_threshold = 1u32;
        let next_sequence_number = 44218446u32;
        let last_assigned_ticket_number = 44218195u32;
        let available_tickets = (44218195..44218200).collect::<Vec<_>>();

        let mut deps = mock_dependencies();
        let info = message_info(&instantiator, &[]);
        let env = mock_env();

        let msg = InstantiateMsg {
            admin_address: admin.to_string(),
            governance_address: governance.to_string(),
            gateway_address: gateway_address.to_string(),
            multisig_address: multisig_address.to_string(),
            coordinator_address: coordinator_address.to_string(),
            voting_verifier_address: voting_verifier_address.to_string(),
            service_registry_address: service_registry_address.to_string(),
            signing_threshold,
            service_name: service_name.to_string(),
            chain_name,
            xrpl_multisig_address,
            verifier_set_diff_threshold,
            xrpl_transaction_fee,
            xrpl_base_reserve,
            xrpl_owner_reserve,
            initial_fee_reserve,
            ticket_count_threshold,
            next_sequence_number,
            last_assigned_ticket_number,
            available_tickets,
        };

        let res = instantiate(deps.as_mut(), env, info, msg);

        assert!(res.is_ok());
        let res = res.unwrap();

        assert_eq!(res.messages.len(), 0);

        let config = CONFIG.load(deps.as_ref().storage).unwrap();
        assert_eq!(config.gateway, gateway_address);
        assert_eq!(config.multisig, multisig_address);
        assert_eq!(config.service_registry, service_registry_address);
        assert_eq!(config.signing_threshold, signing_threshold);
        assert_eq!(config.service_name, service_name);

        assert_eq!(
            permission_control::sender_role(deps.as_ref().storage, &admin).unwrap(),
            Permission::Admin.into()
        );

        assert_eq!(
            permission_control::sender_role(deps.as_ref().storage, &governance).unwrap(),
            Permission::Governance.into()
        );
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn test_operators_to_verifier_set(operators: Vec<TestOperator>, nonce: u64) -> VerifierSet {
        let total_weight: Uint128 = operators
            .iter()
            .fold(Uint128::zero(), |acc, x| acc + x.weight);
        let quorum = total_weight.mul_ceil(test_data::threshold());
        VerifierSet {
            signers: operators
                .into_iter()
                .map(|op| {
                    (
                        op.address.clone().to_string(),
                        Signer {
                            address: op.address,
                            pub_key: op.pub_key,
                            weight: op.weight,
                        },
                    )
                })
                .collect(),
            threshold: quorum,
            created_at: nonce,
        }
    }

    #[test]
    fn test_update_verifier_set_fresh() {
        let mut deps = setup_test_case();
        let verifier_set = query_verifier_set(deps.as_ref());
        assert!(verifier_set.is_ok());
        assert!(verifier_set.unwrap().is_none());
        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_ok());

        let verifier_set = query_verifier_set(deps.as_ref());
        assert!(verifier_set.is_ok());

        let verifier_set = verifier_set.unwrap().unwrap();

        let expected_verifier_set =
            test_operators_to_verifier_set(test_data::operators(), mock_env().block.height);

        assert_eq!(verifier_set, expected_verifier_set);
    }

    #[test]
    fn test_update_verifier_set_from_non_admin_or_governance_should_fail() {
        let mut deps = setup_test_case();
        let api = deps.api;
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("some random address"), &[]),
            ExecuteMsg::UpdateVerifierSet {},
        );
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(
                permission_control::Error::GeneralPermissionDenied {
                    expected: Permission::Elevated.into(),
                    actual: Permission::NoPrivilege.into()
                }
            )
            .to_string()
        );
    }

    #[test]
    fn test_update_verifier_set_from_governance_should_succeed() {
        let mut deps = setup_test_case();
        let api = deps.api;
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(GOVERNANCE), &[]),
            ExecuteMsg::UpdateVerifierSet {},
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_update_verifier_set_from_admin_should_succeed() {
        let mut deps = setup_test_case();
        let api = deps.api;
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN), &[]),
            ExecuteMsg::UpdateVerifierSet {},
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_update_verifier_set_remove_one() {
        let mut deps = setup_test_case();
        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_ok());

        let mut new_verifier_set = test_data::operators();
        new_verifier_set.pop();

        deps.querier.update_wasm(mock_querier_handler(
            new_verifier_set,
            VerificationStatus::SucceededOnSourceChain,
        ));

        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_ok());

        let verifier_set = query_verifier_set(deps.as_ref());
        assert!(verifier_set.is_ok());

        let verifier_set = verifier_set.unwrap().unwrap();

        let expected_verifier_set =
            test_operators_to_verifier_set(test_data::operators(), mock_env().block.height);

        assert_eq!(verifier_set, expected_verifier_set);
    }

    #[test]
    fn test_update_verifier_set_add_one() {
        let mut deps = setup_test_case();

        let mut new_verifier_set = test_data::operators();
        new_verifier_set.pop();

        deps.querier.update_wasm(mock_querier_handler(
            new_verifier_set.clone(),
            VerificationStatus::SucceededOnSourceChain,
        ));

        let res = execute_update_verifier_set(deps.as_mut());
        assert!(res.is_ok());

        deps.querier.update_wasm(mock_querier_handler(
            test_data::operators(),
            VerificationStatus::SucceededOnSourceChain,
        ));

        let res = execute_update_verifier_set(deps.as_mut());
        assert!(res.is_ok());

        let verifier_set = query_verifier_set(deps.as_ref());
        assert!(verifier_set.is_ok());

        let verifier_set = verifier_set.unwrap().unwrap();

        let expected_verifier_set =
            test_operators_to_verifier_set(new_verifier_set, mock_env().block.height);

        assert_eq!(verifier_set, expected_verifier_set);
    }

    #[test]
    fn test_update_verifier_set_change_public_key() {
        let mut deps = setup_test_case();
        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_ok());

        let mut new_verifier_set = test_data::operators();
        let (a, b) = (
            new_verifier_set[0].pub_key.clone(),
            new_verifier_set[1].pub_key.clone(),
        );
        new_verifier_set[0].pub_key = b;
        new_verifier_set[1].pub_key = a;

        deps.querier.update_wasm(mock_querier_handler(
            new_verifier_set,
            VerificationStatus::SucceededOnSourceChain,
        ));
        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_ok());

        let verifier_set = query_verifier_set(deps.as_ref());
        assert!(verifier_set.is_ok());

        let verifier_set = verifier_set.unwrap().unwrap();

        let expected_verifier_set =
            test_operators_to_verifier_set(test_data::operators(), mock_env().block.height);

        assert_eq!(verifier_set, expected_verifier_set);
    }

    #[test]
    fn test_update_verifier_set_unchanged() {
        let mut deps = setup_test_case();
        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_ok());

        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::VerifierSetUnchanged)
                .to_string()
        );
    }

    #[test]
    fn test_confirm_verifier_set_unconfirmed() {
        let mut deps = setup_test_case();

        let res = execute_update_verifier_set(deps.as_mut());
        assert!(res.is_ok());

        let mut new_verifier_set = test_data::operators();
        new_verifier_set.pop();
        deps.querier.update_wasm(mock_querier_handler(
            new_verifier_set,
            VerificationStatus::Unknown,
        ));

        let res = execute_update_verifier_set(deps.as_mut());
        assert!(res.is_ok());
        let res = reply_update_verifier_set(deps.as_mut());
        assert!(res.is_ok());

        let res = query_proof(deps.as_ref(), None).unwrap();
        let execute_data = match res.status {
            ProofStatus::Completed { execute_data } => execute_data,
            _ => panic!("Expected proof status to be completed"), // multisig mock will always return completed multisig
        };

        let prover_message = XRPLProverMessage {
            tx_id: hash_signed_tx(execute_data.as_slice()).unwrap(),
            unsigned_tx_hash: res.unsigned_tx_hash,
        };

        let res = confirm_prover_message(deps.as_mut(), prover_message);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::TxStatusUnknown).to_string()
        );
    }

    #[test]
    fn test_confirm_verifier_set_wrong_set() {
        let mut deps = setup_test_case();
        let res = execute_update_verifier_set(deps.as_mut());
        assert!(res.is_ok());

        let mut new_verifier_set = test_data::operators();
        new_verifier_set.pop();
        deps.querier.update_wasm(mock_querier_handler(
            new_verifier_set.clone(),
            VerificationStatus::SucceededOnSourceChain,
        ));
        execute_update_verifier_set(deps.as_mut()).unwrap();
        let res = reply_update_verifier_set(deps.as_mut());
        assert!(res.is_ok());

        new_verifier_set.pop();
        deps.querier.update_wasm(mock_querier_handler(
            new_verifier_set,
            VerificationStatus::Unknown,
        ));

        let res = query_proof(deps.as_ref(), None).unwrap();
        let execute_data = match res.status {
            ProofStatus::Completed { execute_data } => execute_data,
            _ => panic!("Expected proof status to be completed"), // multisig mock will always return completed multisig
        };

        let prover_message = XRPLProverMessage {
            tx_id: hash_signed_tx(execute_data.as_slice()).unwrap(),
            unsigned_tx_hash: res.unsigned_tx_hash,
        };

        let res = confirm_prover_message(deps.as_mut(), prover_message);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::TxStatusUnknown).to_string()
        );
    }

    #[test]
    fn confirm_prover_message_for_non_existent_proof_should_fail() {
        let mut deps = setup_test_case();

        let prover_message = XRPLProverMessage {
            tx_id: hash_signed_tx(&test_data::payment_proof()).unwrap(),
            unsigned_tx_hash: test_data::payment_unsigned_tx_hash(),
        };

        let res = confirm_prover_message(deps.as_mut(), prover_message);
        assert!(res.is_err());
        // assert_eq!(
        //     res.unwrap_err().to_string(),
        //     axelar_wasm_std::error::ContractError::from(ContractError::TxNotFound)
        //         .to_string()
        // );
    }

    #[test]
    fn test_construct_proof() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();

        execute_construct_proof(deps.as_mut()).unwrap();
        let res = reply_construct_proof(deps.as_mut()).unwrap();

        let event = res
            .events
            .iter()
            .find(|event| event.ty == "proof_under_construction");

        assert!(event.is_some());

        // test case where there is an existing payload
        execute_construct_proof(deps.as_mut()).unwrap();
        let res = reply_construct_proof(deps.as_mut()).unwrap(); // simulate reply from multisig
        let event = res
            .events
            .iter()
            .find(|event| event.ty == "proof_under_construction");

        assert!(event.is_some());
    }

    #[test]
    fn test_query_proof() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();
        execute_construct_proof(deps.as_mut()).unwrap();
        reply_construct_proof(deps.as_mut()).unwrap(); // simulate reply from multisig

        let res = query_proof(deps.as_ref(), None).unwrap();

        assert_eq!(res.unsigned_tx_hash, test_data::payment_unsigned_tx_hash());
        match res.status {
            ProofStatus::Completed { execute_data } => {
                assert_eq!(execute_data, test_data::payment_proof());
            }
            _ => panic!("Expected proof status to be completed"), // multisig mock will always return completed multisig
        }
    }

    #[test]
    fn test_construct_proof_no_verifier_set() {
        let mut deps = setup_test_case();
        let res = execute_construct_proof(deps.as_mut());
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::NoVerifierSet).to_string()
        );
    }

    #[test]
    fn non_governance_should_not_be_able_to_call_update_signing_threshold() {
        let mut deps = setup_test_case();
        let api = deps.api;
        let res = execute_update_signing_threshold(
            deps.as_mut(),
            api.addr_make("random"),
            Threshold::try_from((6, 10)).unwrap().try_into().unwrap(),
        );
        assert!(res.is_err());
    }

    #[test]
    fn governance_should_be_able_to_call_update_signing_threshold() {
        let mut deps = setup_test_case();
        let governance = deps.api.addr_make(GOVERNANCE);
        let res = execute_update_signing_threshold(
            deps.as_mut(),
            governance,
            Threshold::try_from((6, 10)).unwrap().try_into().unwrap(),
        );
        assert!(res.is_ok());
    }

    /// Calls update_signing_threshold, increasing the threshold by one.
    /// Returns (initial threshold, new threshold)
    fn update_signing_threshold_increase_by_one(deps: DepsMut) -> (Uint128, Uint128) {
        let verifier_set = query_verifier_set(deps.as_ref()).unwrap().unwrap();
        let initial_threshold = verifier_set.threshold;
        let total_weight = verifier_set
            .signers
            .iter()
            .fold(Uint128::zero(), |acc, signer| {
                acc.checked_add(signer.1.weight).unwrap()
            });
        let new_threshold = initial_threshold.checked_add(Uint128::one()).unwrap();

        let governance = MockApi::default().addr_make(GOVERNANCE);
        execute_update_signing_threshold(
            deps,
            governance.clone(),
            Threshold::try_from((
                Uint64::try_from(new_threshold).unwrap(),
                Uint64::try_from(total_weight).unwrap(),
            ))
            .unwrap()
            .try_into()
            .unwrap(),
        )
        .unwrap();
        (initial_threshold, new_threshold)
    }

    #[test]
    fn update_signing_threshold_should_not_change_current_threshold() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();

        let (initial_threshold, new_threshold) =
            update_signing_threshold_increase_by_one(deps.as_mut());
        assert_ne!(initial_threshold, new_threshold);

        let verifier_set = query_verifier_set(deps.as_ref()).unwrap().unwrap();
        assert_eq!(verifier_set.threshold, initial_threshold);
    }

    #[test]
    fn update_signing_threshold_should_change_future_threshold() {
        let mut deps = setup_test_case();

        execute_update_verifier_set(deps.as_mut()).unwrap();

        let (initial_threshold, new_threshold) =
            update_signing_threshold_increase_by_one(deps.as_mut());
        assert_ne!(initial_threshold, new_threshold);

        execute_update_verifier_set(deps.as_mut()).unwrap();
        let res = reply_update_verifier_set(deps.as_mut()).unwrap();

        let proof_under_construction_event = res
            .events
            .iter()
            .find(|event| event.ty == "proof_under_construction");
        assert!(proof_under_construction_event.is_some());

        let unsigned_tx_hash: HexTxHash = from_json(
            proof_under_construction_event
                .as_ref()
                .unwrap()
                .attributes
                .iter()
                .find(|attr| attr.key == "unsigned_tx_hash")
                .unwrap()
                .value
                .clone(),
        )
        .unwrap();

        let signing_started_event = res
            .events
            .iter()
            .find(|event| event.ty == "xrpl_signing_started");
        assert!(signing_started_event.is_some());

        let res = query_proof(deps.as_ref(), None).unwrap();
        assert_eq!(res.unsigned_tx_hash, unsigned_tx_hash);
        let execute_data = match res.status {
            ProofStatus::Completed { execute_data } => {
                assert_eq!(execute_data, test_data::signer_list_set_proof());
                execute_data
            }
            _ => panic!("Expected proof status to be completed"), // multisig mock will always return completed multisig
        };

        let prover_message = XRPLProverMessage {
            tx_id: hash_signed_tx(execute_data.as_slice()).unwrap(),
            unsigned_tx_hash,
        };

        confirm_prover_message(deps.as_mut(), prover_message).unwrap();

        let verifier_set = query_verifier_set(deps.as_ref()).unwrap().unwrap();
        assert_eq!(verifier_set.threshold, new_threshold);
    }

    #[test]
    fn should_confirm_new_threshold() {
        let mut deps = setup_test_case();

        execute_update_verifier_set(deps.as_mut()).unwrap();

        let (initial_threshold, new_threshold) =
            update_signing_threshold_increase_by_one(deps.as_mut());
        assert_ne!(initial_threshold, new_threshold);

        execute_update_verifier_set(deps.as_mut()).unwrap();
        let res = reply_update_verifier_set(deps.as_mut());
        assert!(res.is_ok());

        let res = query_proof(deps.as_ref(), None).unwrap();
        let execute_data = match res.status {
            ProofStatus::Completed { execute_data } => execute_data,
            _ => panic!("Expected proof status to be completed"), // multisig mock will always return completed multisig
        };

        let prover_message = XRPLProverMessage {
            tx_id: hash_signed_tx(execute_data.as_slice()).unwrap(),
            unsigned_tx_hash: res.unsigned_tx_hash,
        };

        let res = confirm_prover_message(deps.as_mut(), prover_message);
        assert!(res.is_ok());

        let verifier_set = query_verifier_set(deps.as_ref()).unwrap().unwrap();
        assert_eq!(verifier_set.threshold, new_threshold);
    }

    #[test]
    fn should_update_verifier_set_no_change() {
        let verifier_set = test_data::new_verifier_set();
        assert!(!should_update_verifier_set(&verifier_set, &verifier_set, 0));
    }

    #[test]
    fn should_update_verifier_set_one_more() {
        let verifier_set = test_data::new_verifier_set();
        let mut new_verifier_set = verifier_set.clone();
        new_verifier_set.signers.pop_first();
        assert!(should_update_verifier_set(
            &verifier_set,
            &new_verifier_set,
            0
        ));
    }

    #[test]
    fn should_update_verifier_set_one_less() {
        let verifier_set = test_data::new_verifier_set();
        let mut new_verifier_set = verifier_set.clone();
        new_verifier_set.signers.pop_first();
        assert!(should_update_verifier_set(
            &new_verifier_set,
            &verifier_set,
            0
        ));
    }

    #[test]
    fn should_update_verifier_set_one_more_higher_threshold() {
        let verifier_set = test_data::new_verifier_set();
        let mut new_verifier_set = verifier_set.clone();
        new_verifier_set.signers.pop_first();
        assert!(!should_update_verifier_set(
            &verifier_set,
            &new_verifier_set,
            1
        ));
    }

    #[test]
    fn should_update_verifier_set_diff_pub_key() {
        let verifier_set = test_data::new_verifier_set();
        let mut new_verifier_set = verifier_set.clone();
        let (first_key, first) = new_verifier_set.signers.pop_first().unwrap();
        let (last_key, last) = new_verifier_set.signers.pop_last().unwrap();
        new_verifier_set.signers.insert(
            last_key,
            Signer {
                pub_key: first.clone().pub_key,
                ..last.clone()
            },
        );
        new_verifier_set.signers.insert(
            first_key,
            Signer {
                pub_key: last.pub_key,
                ..first
            },
        );
        assert!(should_update_verifier_set(
            &verifier_set,
            &new_verifier_set,
            0
        ));
    }

    #[test]
    fn non_governance_should_not_be_able_to_call_update_admin() {
        let mut deps = setup_test_case();
        let api = deps.api;
        let res = execute_update_admin(
            deps.as_mut(),
            api.addr_make("unauthorized"),
            "new admin".to_string(),
        );
        assert!(res.is_err());
    }

    #[test]
    fn governance_should_be_able_to_call_update_admin() {
        let mut deps = setup_test_case();
        let api = deps.api;
        let new_admin = api.addr_make("new admin");

        let res = execute_update_admin(
            deps.as_mut(),
            api.addr_make(GOVERNANCE),
            new_admin.to_string(),
        );
        assert!(res.is_ok(), "{:?}", res);

        assert_eq!(
            permission_control::sender_role(deps.as_ref().storage, &new_admin).unwrap(),
            Permission::Admin.into()
        );

        assert_eq!(
            permission_control::sender_role(deps.as_ref().storage, &api.addr_make(ADMIN)).unwrap(),
            Permission::NoPrivilege.into()
        );
    }

    #[test]
    fn admin_should_be_able_to_call_update_admin() {
        let mut deps = setup_test_case();
        let api = deps.api;
        let new_admin = api.addr_make("new admin");

        let res = execute_update_admin(deps.as_mut(), api.addr_make(ADMIN), new_admin.to_string());
        assert!(res.is_ok(), "{:?}", res);

        assert_eq!(
            permission_control::sender_role(deps.as_ref().storage, &new_admin).unwrap(),
            Permission::Admin.into()
        );

        assert_eq!(
            permission_control::sender_role(deps.as_ref().storage, &api.addr_make(ADMIN)).unwrap(),
            Permission::NoPrivilege.into()
        );
    }

    fn execute_as(
        deps: DepsMut,
        sender: &str,
        msg: ExecuteMsg,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        execute(
            deps,
            mock_env(),
            message_info(&MockApi::default().addr_make(sender), &[]),
            msg,
        )
    }

    fn query_ok(deps: Deps, msg: QueryMsg) -> Binary {
        query(deps, mock_env(), msg).unwrap()
    }

    fn fee_reserve(deps: Deps) -> u64 {
        from_json(query_ok(deps, QueryMsg::FeeReserve)).unwrap()
    }

    fn available_tickets(deps: Deps) -> Vec<u32> {
        from_json(query_ok(deps, QueryMsg::AvailableTickets)).unwrap()
    }

    fn next_sequence_number(deps: Deps) -> u32 {
        from_json(query_ok(deps, QueryMsg::NextSequenceNumber)).unwrap()
    }

    fn is_enabled(deps: Deps) -> bool {
        from_json(query_ok(deps, QueryMsg::IsEnabled)).unwrap()
    }

    fn next_verifier_set(deps: Deps) -> Option<VerifierSet> {
        from_json(query_ok(deps, QueryMsg::NextVerifierSet)).unwrap()
    }

    fn assert_err(
        result: Result<Response, axelar_wasm_std::error::ContractError>,
        expected: ContractError,
    ) {
        assert_eq!(
            result.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(expected).to_string()
        );
    }

    fn assert_permission_denied(result: Result<Response, axelar_wasm_std::error::ContractError>) {
        assert_eq!(
            result.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(
                permission_control::Error::GeneralPermissionDenied {
                    expected: Permission::Elevated.into(),
                    actual: Permission::NoPrivilege.into(),
                }
            )
            .to_string()
        );
    }

    fn find_event<'a>(response: &'a Response, ty: &str) -> &'a cosmwasm_std::Event {
        response
            .events
            .iter()
            .find(|event| event.ty == ty)
            .unwrap_or_else(|| panic!("no {ty} event in {:?}", response.events))
    }

    /// Attribute values of `IntoEvent` events are JSON encoded.
    fn event_attribute<T: cosmwasm_schema::serde::de::DeserializeOwned>(
        event: &cosmwasm_std::Event,
        key: &str,
    ) -> T {
        let attribute = event
            .attributes
            .iter()
            .find(|attribute| attribute.key == key)
            .unwrap_or_else(|| panic!("no {key} attribute in {:?}", event));
        from_json(attribute.value.as_bytes()).unwrap()
    }

    /// Replies to the multisig's `StartSigningSession` for `session_id`, as the multisig would.
    fn reply_signing_started(
        deps: DepsMut,
        session_id: Uint64,
        expires_at: u64,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let event = wasm_prefixed_event(Event::SigningStarted {
            session_id,
            verifier_set_id: "".to_string(),
            pub_keys: HashMap::new(),
            msg: HexBinary::from([0u8; 32]).into(),
            chain_name: CHAIN_NAME.parse().unwrap(),
            expires_at,
        });

        #[allow(deprecated)]
        let response = SubMsgResponse {
            events: vec![event],
            data: Some(
                prost::bytes::Bytes::from(to_json_binary(&session_id).unwrap().to_vec())
                    .encode_to_vec()
                    .into(),
            ),
            msg_responses: vec![],
        };

        reply(
            deps,
            mock_env(),
            Reply {
                id: START_MULTISIG_REPLY_ID,
                result: SubMsgResult::Ok(response),
                payload: vec![].into(),
                gas_used: 0,
            },
        )
    }

    /// Confirms the proof of `session_id` with the status the verifier reports for it on XRPL.
    fn confirm_proof(
        deps: &mut TestDeps,
        session_id: Uint64,
        status: VerificationStatus,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        deps.querier
            .update_wasm(mock_querier_handler(test_data::operators(), status));

        let proof = query_proof(deps.as_ref(), Some(session_id)).unwrap();
        let prover_message = XRPLProverMessage {
            tx_id: hash_signed_tx(completed_proof(&proof).as_slice()).unwrap(),
            unsigned_tx_hash: proof.unsigned_tx_hash,
        };

        confirm_prover_message(deps.as_mut(), prover_message)
    }

    fn completed_proof(proof: &ProofResponse) -> HexBinary {
        match &proof.status {
            ProofStatus::Completed { execute_data } => execute_data.clone(),
            ProofStatus::Pending => panic!("expected a completed proof"),
        }
    }

    /// The transaction behind the proof of `session_id`.
    fn proof_tx(deps: Deps, session_id: Uint64) -> XRPLUnsignedTx {
        let proof = query_proof(deps, Some(session_id)).unwrap();
        UNSIGNED_TX_HASH_TO_TX_INFO
            .load(deps.storage, &proof.unsigned_tx_hash.tx_hash)
            .unwrap()
            .unsigned_tx
    }

    fn proof_sequence(deps: Deps, session_id: Uint64) -> XRPLSequence {
        proof_tx(deps, session_id).sequence().clone()
    }

    /// An ITS hub message delivering a transfer to XRPL.
    fn incoming_transfer(
        token_id: TokenId,
        amount: u128,
        destination_address: &[u8],
        data: Option<nonempty::HexBinary>,
    ) -> HubMessage {
        HubMessage::ReceiveFromHub {
            source_chain: "xrpl-evm".parse().unwrap(),
            message: ItsMessage::InterchainTransfer(InterchainTransfer {
                token_id,
                source_address: vec![1u8; 20].try_into().unwrap(),
                destination_address: destination_address.to_vec().try_into().unwrap(),
                amount: Uint256::from(amount).try_into().unwrap(),
                data,
            }),
        }
    }

    /// Installs an outgoing message carrying `hub_message` towards `destination_chain` in the
    /// mocked gateway and returns its id and payload.
    fn mock_outgoing_message(
        deps: &mut TestDeps,
        hub_message: HubMessage,
        destination_chain: &str,
    ) -> (CrossChainId, HexBinary) {
        let payload = hub_message_abi_encode(hub_message);
        let (template, _) = test_data::outgoing_messages().remove(0);
        let message = RouterMessage {
            destination_chain: destination_chain.parse().unwrap(),
            payload_hash: Keccak256::digest(payload.as_slice()).into(),
            ..template
        };

        let mut responses = MockResponses::new(
            test_data::operators(),
            VerificationStatus::SucceededOnSourceChain,
        );
        responses.outgoing_messages = vec![(message.clone(), payload.clone())];
        deps.querier
            .update_wasm(mock_querier_handler_with(responses));

        (message.cc_id, payload)
    }

    fn construct_proof(
        deps: DepsMut,
        cc_id: CrossChainId,
        payload: HexBinary,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        execute_as(deps, RELAYER, ExecuteMsg::ConstructProof { cc_id, payload })
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn ticket_create_proof_creates_tickets_when_confirmed() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();
        assert_eq!(
            from_json::<u32>(query_ok(deps.as_ref(), QueryMsg::TicketCreate)).unwrap(),
            TICKETS_TO_CREATE
        );

        let response = execute_as(deps.as_mut(), RELAYER, ExecuteMsg::TicketCreate).unwrap();
        assert_eq!(response.messages.len(), 1);
        reply_signing_started(deps.as_mut(), MULTISIG_SESSION_ID, 1000).unwrap();
        assert_eq!(
            proof_sequence(deps.as_ref(), MULTISIG_SESSION_ID),
            XRPLSequence::Plain(INITIAL_SEQUENCE_NUMBER)
        );
        // the fee leaves the reserve as soon as the sequence number is taken
        assert_eq!(fee_reserve(deps.as_ref()), INITIAL_FEE_RESERVE - TX_FEE);

        let response = confirm_proof(
            &mut deps,
            MULTISIG_SESSION_ID,
            VerificationStatus::SucceededOnSourceChain,
        )
        .unwrap();

        let event = find_event(&response, "tickets_created");
        assert_eq!(
            event_attribute::<u32>(event, "first"),
            INITIAL_SEQUENCE_NUMBER + 1
        );
        let new_tickets = INITIAL_SEQUENCE_NUMBER + 1..=INITIAL_SEQUENCE_NUMBER + TICKETS_TO_CREATE;
        assert_eq!(
            available_tickets(deps.as_ref()),
            INITIAL_TICKETS.chain(new_tickets).collect::<Vec<_>>()
        );
        // the sequence number skips the created tickets
        assert_eq!(
            next_sequence_number(deps.as_ref()),
            INITIAL_SEQUENCE_NUMBER + TICKETS_TO_CREATE + 1
        );
        // the ticket pool is full
        assert_err(
            execute_as(deps.as_mut(), RELAYER, ExecuteMsg::TicketCreate),
            ContractError::TicketCountThresholdNotReached,
        );
        assert!(query(deps.as_ref(), mock_env(), QueryMsg::TicketCreate).is_err());
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn failed_ticket_create_only_consumes_its_sequence_number() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();
        execute_as(deps.as_mut(), RELAYER, ExecuteMsg::TicketCreate).unwrap();
        reply_signing_started(deps.as_mut(), MULTISIG_SESSION_ID, 1000).unwrap();

        let response = confirm_proof(
            &mut deps,
            MULTISIG_SESSION_ID,
            VerificationStatus::FailedOnSourceChain,
        )
        .unwrap();

        assert!(response.events.is_empty());
        assert_eq!(
            available_tickets(deps.as_ref()),
            INITIAL_TICKETS.collect::<Vec<_>>()
        );
        assert_eq!(
            next_sequence_number(deps.as_ref()),
            INITIAL_SEQUENCE_NUMBER + 1
        );
        // XRPL charges the fee of a failed transaction too
        assert_eq!(fee_reserve(deps.as_ref()), INITIAL_FEE_RESERVE - TX_FEE);
        // tickets can be requested again
        execute_as(deps.as_mut(), RELAYER, ExecuteMsg::TicketCreate).unwrap();
    }

    #[test]
    fn ticket_create_requires_a_verifier_set() {
        let mut deps = setup_test_case();

        assert_err(
            execute_as(deps.as_mut(), RELAYER, ExecuteMsg::TicketCreate),
            ContractError::NoVerifierSet,
        );
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn trust_set_proof_registers_trust_line_when_confirmed() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();
        let token_id = TokenId::new(LOCAL_TOKEN_ID);

        execute_as(deps.as_mut(), ADMIN, ExecuteMsg::TrustSet { token_id }).unwrap();
        reply_signing_started(deps.as_mut(), MULTISIG_SESSION_ID, 1000).unwrap();
        assert_eq!(fee_reserve(deps.as_ref()), INITIAL_FEE_RESERVE - TX_FEE);
        let proof = query_proof(deps.as_ref(), None).unwrap();
        goldie::assert!(completed_proof(&proof).to_string());

        let response = confirm_proof(
            &mut deps,
            MULTISIG_SESSION_ID,
            VerificationStatus::SucceededOnSourceChain,
        )
        .unwrap();

        let event = find_event(&response, "trust_line_created");
        assert_eq!(event_attribute::<TokenId>(event, "token_id"), token_id);
        assert_eq!(
            event_attribute::<xrpl_types::types::XRPLToken>(event, "token"),
            local_token()
        );
        // the trust line exists now
        assert_err(
            execute_as(deps.as_mut(), ADMIN, ExecuteMsg::TrustSet { token_id }),
            ContractError::TrustLineAlreadyExists(local_token()),
        );
        // and raises the reserve the account has to keep by one owned object
        let required_reserve = ACCOUNT_RESERVE + 200_000 + TX_FEE;
        execute_as(
            deps.as_mut(),
            ADMIN,
            ExecuteMsg::UpdateFeeReserve {
                new_fee_reserve: required_reserve - 1,
            },
        )
        .unwrap();
        assert_err(
            execute_as(deps.as_mut(), RELAYER, ExecuteMsg::TicketCreate),
            ContractError::InsufficientFeeReserve {
                current_reserve: required_reserve - 1,
                required_reserve,
            },
        );
    }

    #[test]
    fn trust_set_rejects_remote_and_unknown_tokens() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();

        assert_err(
            execute_as(
                deps.as_mut(),
                ADMIN,
                ExecuteMsg::TrustSet {
                    token_id: TokenId::new(REMOTE_TOKEN_ID),
                },
            ),
            ContractError::TokenNotLocal(remote_token()),
        );

        let unknown = TokenId::new([0x99; 32]);
        assert_err(
            execute_as(
                deps.as_mut(),
                ADMIN,
                ExecuteMsg::TrustSet { token_id: unknown },
            ),
            ContractError::FailedToGetXrplToken(unknown),
        );
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn proof_construction_requires_the_reserve_to_cover_account_reserve_and_fee() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();
        let required_reserve = ACCOUNT_RESERVE + TX_FEE;

        execute_as(
            deps.as_mut(),
            ADMIN,
            ExecuteMsg::UpdateFeeReserve {
                new_fee_reserve: required_reserve - 1,
            },
        )
        .unwrap();
        assert_err(
            execute_as(deps.as_mut(), RELAYER, ExecuteMsg::TicketCreate),
            ContractError::InsufficientFeeReserve {
                current_reserve: required_reserve - 1,
                required_reserve,
            },
        );

        execute_as(
            deps.as_mut(),
            ADMIN,
            ExecuteMsg::UpdateFeeReserve {
                new_fee_reserve: required_reserve,
            },
        )
        .unwrap();
        execute_as(deps.as_mut(), RELAYER, ExecuteMsg::TicketCreate).unwrap();
        assert_eq!(fee_reserve(deps.as_ref()), ACCOUNT_RESERVE);
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn concurrent_sequential_transactions_share_the_sequence_number_and_pay_one_fee() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();
        let (ticket_create, trust_set, signer_list_set) =
            (Uint64::new(1), Uint64::new(2), Uint64::new(3));

        execute_as(deps.as_mut(), RELAYER, ExecuteMsg::TicketCreate).unwrap();
        reply_signing_started(deps.as_mut(), ticket_create, 1000).unwrap();
        // a trust line adds an owned object, so the reserve is checked again
        execute_as(
            deps.as_mut(),
            ADMIN,
            ExecuteMsg::TrustSet {
                token_id: TokenId::new(LOCAL_TOKEN_ID),
            },
        )
        .unwrap();
        reply_signing_started(deps.as_mut(), trust_set, 1000).unwrap();
        // a signer list adds none, so it is not
        let mut new_operators = test_data::operators();
        new_operators.pop();
        deps.querier.update_wasm(mock_querier_handler(
            new_operators,
            VerificationStatus::SucceededOnSourceChain,
        ));
        execute_update_verifier_set(deps.as_mut()).unwrap();
        reply_signing_started(deps.as_mut(), signer_list_set, 1000).unwrap();

        for session_id in [ticket_create, trust_set, signer_list_set] {
            assert_eq!(
                proof_sequence(deps.as_ref(), session_id),
                XRPLSequence::Plain(INITIAL_SEQUENCE_NUMBER)
            );
        }
        assert_eq!(fee_reserve(deps.as_ref()), INITIAL_FEE_RESERVE - TX_FEE);

        // only one of them can make it on chain
        confirm_proof(
            &mut deps,
            ticket_create,
            VerificationStatus::SucceededOnSourceChain,
        )
        .unwrap();
        confirm_proof(
            &mut deps,
            trust_set,
            VerificationStatus::FailedOnSourceChain,
        )
        .unwrap();
        confirm_proof(
            &mut deps,
            signer_list_set,
            VerificationStatus::FailedOnSourceChain,
        )
        .unwrap();

        assert_eq!(
            next_sequence_number(deps.as_ref()),
            INITIAL_SEQUENCE_NUMBER + TICKETS_TO_CREATE + 1
        );
        assert!(next_verifier_set(deps.as_ref()).is_some());
        // the failed trust set is retried with the next sequence number, paying its own fee
        execute_as(
            deps.as_mut(),
            ADMIN,
            ExecuteMsg::TrustSet {
                token_id: TokenId::new(LOCAL_TOKEN_ID),
            },
        )
        .unwrap();
        reply_signing_started(deps.as_mut(), Uint64::new(4), 1000).unwrap();
        assert_eq!(
            proof_sequence(deps.as_ref(), Uint64::new(4)),
            XRPLSequence::Plain(INITIAL_SEQUENCE_NUMBER + TICKETS_TO_CREATE + 1)
        );
        assert_eq!(fee_reserve(deps.as_ref()), INITIAL_FEE_RESERVE - 2 * TX_FEE);
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn confirm_add_reserves_message_tops_up_the_fee_reserve_once_per_transaction() {
        let mut deps = setup_test_case();
        let add_reserves_message = XRPLAddReservesMessage {
            tx_id: HexTxHash::new([3; 32]),
            amount: 1_000,
        };

        execute_as(
            deps.as_mut(),
            RELAYER,
            ExecuteMsg::ConfirmAddReservesMessage {
                add_reserves_message: add_reserves_message.clone(),
            },
        )
        .unwrap();
        assert_eq!(fee_reserve(deps.as_ref()), INITIAL_FEE_RESERVE + 1_000);

        // replaying the transaction does not count it again
        execute_as(
            deps.as_mut(),
            RELAYER,
            ExecuteMsg::ConfirmAddReservesMessage {
                add_reserves_message,
            },
        )
        .unwrap();
        assert_eq!(fee_reserve(deps.as_ref()), INITIAL_FEE_RESERVE + 1_000);

        // empty top-ups change nothing
        execute_as(
            deps.as_mut(),
            RELAYER,
            ExecuteMsg::ConfirmAddReservesMessage {
                add_reserves_message: XRPLAddReservesMessage {
                    tx_id: HexTxHash::new([4; 32]),
                    amount: 0,
                },
            },
        )
        .unwrap();
        assert_eq!(fee_reserve(deps.as_ref()), INITIAL_FEE_RESERVE + 1_000);
    }

    #[test]
    fn confirm_add_reserves_message_ignores_unverified_transactions() {
        let mut deps = setup_test_case();
        let unverified = [
            VerificationStatus::Unknown,
            VerificationStatus::InProgress,
            VerificationStatus::FailedToVerify,
            VerificationStatus::NotFoundOnSourceChain,
            VerificationStatus::FailedOnSourceChain,
        ];

        for status in unverified {
            deps.querier
                .update_wasm(mock_querier_handler(test_data::operators(), status));
            execute_as(
                deps.as_mut(),
                RELAYER,
                ExecuteMsg::ConfirmAddReservesMessage {
                    add_reserves_message: XRPLAddReservesMessage {
                        tx_id: HexTxHash::new([3; 32]),
                        amount: 1_000,
                    },
                },
            )
            .unwrap();
            assert_eq!(fee_reserve(deps.as_ref()), INITIAL_FEE_RESERVE);
        }
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn fee_parameter_updates_apply_to_the_next_transaction() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();

        execute_as(
            deps.as_mut(),
            ADMIN,
            ExecuteMsg::UpdateXrplTransactionFee {
                new_transaction_fee: 20,
            },
        )
        .unwrap();
        execute_as(
            deps.as_mut(),
            GOVERNANCE,
            ExecuteMsg::UpdateXrplReserves {
                new_base_reserve: 2_000_000,
                new_owner_reserve: 100_000,
            },
        )
        .unwrap();

        let config = CONFIG.load(deps.as_ref().storage).unwrap();
        assert_eq!(config.xrpl_transaction_fee, 20);
        assert_eq!(config.xrpl_base_reserve, 2_000_000);
        assert_eq!(config.xrpl_owner_reserve, 100_000);

        let required_reserve = 2_000_000 + 100_000 * 251 + 20 * 33;
        execute_as(
            deps.as_mut(),
            ADMIN,
            ExecuteMsg::UpdateFeeReserve {
                new_fee_reserve: required_reserve - 1,
            },
        )
        .unwrap();
        assert_err(
            execute_as(deps.as_mut(), RELAYER, ExecuteMsg::TicketCreate),
            ContractError::InsufficientFeeReserve {
                current_reserve: required_reserve - 1,
                required_reserve,
            },
        );
    }

    #[test]
    fn elevated_messages_reject_unprivileged_senders() {
        let mut deps = setup_test_case();
        let elevated_msgs = [
            ExecuteMsg::TrustSet {
                token_id: TokenId::new(LOCAL_TOKEN_ID),
            },
            ExecuteMsg::UpdateFeeReserve { new_fee_reserve: 1 },
            ExecuteMsg::UpdateXrplTransactionFee {
                new_transaction_fee: 1,
            },
            ExecuteMsg::UpdateXrplReserves {
                new_base_reserve: 1,
                new_owner_reserve: 1,
            },
            ExecuteMsg::DisableExecution,
            ExecuteMsg::EnableExecution,
        ];

        for msg in elevated_msgs {
            assert_permission_denied(execute_as(deps.as_mut(), RELAYER, msg));
        }
        // the signing threshold is reserved for governance
        assert!(execute_as(
            deps.as_mut(),
            ADMIN,
            ExecuteMsg::UpdateSigningThreshold {
                new_signing_threshold: test_data::threshold(),
            },
        )
        .is_err());
    }

    #[test]
    fn disabling_execution_blocks_proof_construction_until_re_enabled() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();

        execute_as(deps.as_mut(), ADMIN, ExecuteMsg::DisableExecution).unwrap();
        assert!(!is_enabled(deps.as_ref()));
        assert_err(
            execute_construct_proof(deps.as_mut()),
            ContractError::ExecutionDisabled,
        );
        assert_err(
            execute_as(deps.as_mut(), RELAYER, ExecuteMsg::TicketCreate),
            ContractError::ExecutionDisabled,
        );

        execute_as(deps.as_mut(), GOVERNANCE, ExecuteMsg::EnableExecution).unwrap();
        assert!(is_enabled(deps.as_ref()));
        execute_construct_proof(deps.as_mut()).unwrap();
    }

    #[test]
    fn verify_signature_accepts_only_signatures_over_the_signer_specific_digest() {
        let mut deps = setup_test_case();
        let message: HexBinary = XRPLUnsignedTxToSign {
            unsigned_tx: test_data::ticket_create_tx(),
            unsigned_tx_hash: HexTxHash::new(test_data::ticket_create_unsigned_tx_hash()),
            cc_id: None,
        }
        .xrpl_serialize()
        .unwrap()
        .into();
        let (public_key, signature) = test_data::ticket_create_signer();
        let verify = |message: HexBinary, signature: HexBinary| ExecuteMsg::VerifySignature {
            signature,
            message,
            public_key: public_key.clone(),
            signer_address: "signer".to_string(),
            session_id: MULTISIG_SESSION_ID,
        };
        let query_verify = |message: HexBinary, signature: HexBinary| QueryMsg::VerifySignature {
            signature,
            message,
            public_key: public_key.clone(),
            signer_address: "signer".to_string(),
            session_id: MULTISIG_SESSION_ID,
        };

        execute_as(
            deps.as_mut(),
            RELAYER,
            verify(message.clone(), signature.clone()),
        )
        .unwrap();
        assert!(from_json::<bool>(query_ok(
            deps.as_ref(),
            query_verify(message.clone(), signature.clone())
        ))
        .unwrap());

        // the signature does not cover another transaction
        let mut other_message = message.to_vec();
        *other_message.last_mut().unwrap() ^= 1;
        let other_message = HexBinary::from(other_message);
        assert_err(
            execute_as(
                deps.as_mut(),
                RELAYER,
                verify(other_message.clone(), signature.clone()),
            ),
            ContractError::InvalidSignature,
        );
        assert!(!from_json::<bool>(query_ok(
            deps.as_ref(),
            query_verify(other_message, signature)
        ))
        .unwrap());

        // malformed signatures are rejected before verification
        let malformed = HexBinary::from(vec![1, 2, 3]);
        assert_err(
            execute_as(
                deps.as_mut(),
                RELAYER,
                verify(message.clone(), malformed.clone()),
            ),
            ContractError::InvalidSignature,
        );
        assert!(query(deps.as_ref(), mock_env(), query_verify(message, malformed)).is_err());
    }

    #[test]
    fn multisig_session_query_tracks_payment_signing_sessions() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();
        let cc_id = test_data::outgoing_messages().remove(0).0.cc_id;
        let session = |deps: Deps| -> Option<MultisigSession> {
            from_json(query_ok(
                deps,
                QueryMsg::MultisigSession {
                    cc_id: cc_id.clone(),
                },
            ))
            .unwrap()
        };

        assert_eq!(session(deps.as_ref()), None);

        execute_construct_proof(deps.as_mut()).unwrap();
        reply_signing_started(deps.as_mut(), MULTISIG_SESSION_ID, 1000).unwrap();

        assert_eq!(
            session(deps.as_ref()),
            Some(MultisigSession {
                id: MULTISIG_SESSION_ID.u64(),
                expires_at: 1000,
            })
        );
    }

    #[test]
    fn next_verifier_set_query_shows_pending_rotation_until_confirmed() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();
        assert_eq!(next_verifier_set(deps.as_ref()), None);

        let mut new_operators = test_data::operators();
        new_operators.pop();
        deps.querier.update_wasm(mock_querier_handler(
            new_operators.clone(),
            VerificationStatus::SucceededOnSourceChain,
        ));
        execute_update_verifier_set(deps.as_mut()).unwrap();
        reply_signing_started(deps.as_mut(), MULTISIG_SESSION_ID, 1000).unwrap();

        let pending = test_operators_to_verifier_set(new_operators, mock_env().block.height);
        assert_eq!(next_verifier_set(deps.as_ref()), Some(pending.clone()));
        // re-running the update while the rotation is pending re-signs the same set
        let response = execute_update_verifier_set(deps.as_mut()).unwrap();
        assert_eq!(response.messages.len(), 2);
        assert_eq!(next_verifier_set(deps.as_ref()), Some(pending.clone()));

        confirm_proof(
            &mut deps,
            MULTISIG_SESSION_ID,
            VerificationStatus::SucceededOnSourceChain,
        )
        .unwrap();

        assert_eq!(next_verifier_set(deps.as_ref()), None);
        assert_eq!(query_verifier_set(deps.as_ref()).unwrap(), Some(pending));
    }

    #[test]
    fn payment_proof_rejects_payloads_that_are_not_incoming_transfers() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();
        let token_id = TokenId::new(LOCAL_TOKEN_ID);
        let token_address: nonempty::HexBinary = vec![1u8; 20].try_into().unwrap();
        let not_incoming_transfers = [
            HubMessage::SendToHub {
                destination_chain: "xrpl-evm".parse().unwrap(),
                message: ItsMessage::InterchainTransfer(InterchainTransfer {
                    token_id,
                    source_address: token_address.clone(),
                    destination_address: token_address.clone(),
                    amount: Uint256::one().try_into().unwrap(),
                    data: None,
                }),
            },
            HubMessage::RegisterTokenMetadata(RegisterTokenMetadata {
                decimals: 6,
                token_address: token_address.clone(),
            }),
            HubMessage::ReceiveFromHub {
                source_chain: "xrpl-evm".parse().unwrap(),
                message: ItsMessage::DeployInterchainToken(DeployInterchainToken {
                    token_id,
                    name: "Token".to_string().try_into().unwrap(),
                    symbol: "TKN".to_string().try_into().unwrap(),
                    decimals: 6,
                    minter: None,
                }),
            },
            HubMessage::ReceiveFromHub {
                source_chain: "xrpl-evm".parse().unwrap(),
                message: ItsMessage::LinkToken(LinkToken {
                    token_id,
                    token_manager_type: Uint256::zero(),
                    source_token_address: token_address.clone(),
                    destination_token_address: token_address,
                    params: None,
                }),
            },
        ];

        for hub_message in not_incoming_transfers {
            let (cc_id, payload) = mock_outgoing_message(&mut deps, hub_message, CHAIN_NAME);
            assert_err(
                construct_proof(deps.as_mut(), cc_id, payload),
                ContractError::InvalidPayload,
            );
        }
    }

    #[test]
    fn payment_proof_rejects_transfers_with_data() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();
        let (cc_id, payload) = mock_outgoing_message(
            &mut deps,
            incoming_transfer(
                TokenId::new(LOCAL_TOKEN_ID),
                1,
                XRPL_DESTINATION.as_bytes(),
                Some(vec![1u8].try_into().unwrap()),
            ),
            CHAIN_NAME,
        );

        assert_err(
            construct_proof(deps.as_mut(), cc_id, payload),
            ContractError::DataNotSupported,
        );
    }

    #[test]
    fn payment_proof_rejects_invalid_xrpl_destination_addresses() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();

        for destination_address in [b"not an xrpl address".as_slice(), &[0xff, 0xfe]] {
            let (cc_id, payload) = mock_outgoing_message(
                &mut deps,
                incoming_transfer(TokenId::new(LOCAL_TOKEN_ID), 1, destination_address, None),
                CHAIN_NAME,
            );
            assert_err(
                construct_proof(deps.as_mut(), cc_id, payload),
                ContractError::InvalidDestinationAddress,
            );
        }
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn payment_proof_rejects_xrp_amounts_above_the_supply_cap() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();
        let amount = u128::from(XRP_MAX_UINT) + 1;
        let (cc_id, payload) = mock_outgoing_message(
            &mut deps,
            incoming_transfer(
                TokenId::new(XRP_TOKEN_ID),
                amount,
                XRPL_DESTINATION.as_bytes(),
                None,
            ),
            CHAIN_NAME,
        );

        assert_err(
            construct_proof(deps.as_mut(), cc_id, payload),
            ContractError::InvalidTransferAmount {
                source_chain: "xrpl-evm".parse().unwrap(),
                amount: Uint256::from(amount),
            },
        );
    }

    #[test]
    fn payment_proof_rejects_messages_for_other_chains() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();
        let (cc_id, payload) = mock_outgoing_message(
            &mut deps,
            incoming_transfer(
                TokenId::new(LOCAL_TOKEN_ID),
                1,
                XRPL_DESTINATION.as_bytes(),
                None,
            ),
            "ethereum",
        );

        assert_err(
            construct_proof(deps.as_mut(), cc_id, payload),
            ContractError::InvalidDestinationChain {
                expected: CHAIN_NAME.parse().unwrap(),
                actual: "ethereum".parse().unwrap(),
            },
        );
    }

    #[test]
    fn payment_proof_rejects_payload_that_does_not_match_the_message() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();
        let (message, payload) = test_data::outgoing_messages().remove(0);
        let other_payload = HexBinary::from(vec![1u8, 2, 3]);

        assert_err(
            construct_proof(deps.as_mut(), message.cc_id, other_payload.clone()),
            ContractError::PayloadHashMismatch {
                expected: message.payload_hash,
                actual: Keccak256::digest(other_payload.as_slice()).into(),
            },
        );
        assert_ne!(payload, other_payload);
    }

    #[test]
    fn payment_proof_fails_when_the_gateway_does_not_know_the_message() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();
        let (_, payload) = test_data::outgoing_messages().remove(0);

        assert_err(
            construct_proof(
                deps.as_mut(),
                CrossChainId::new("axelar", "0x1234").unwrap(),
                payload,
            ),
            ContractError::FailedToGetMessages,
        );
    }

    #[test]
    fn payment_proof_for_issued_token() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();
        let token_id = TokenId::new(LOCAL_TOKEN_ID);
        let (cc_id, payload) = mock_outgoing_message(
            &mut deps,
            incoming_transfer(token_id, 1_500_000, XRPL_DESTINATION.as_bytes(), None),
            CHAIN_NAME,
        );

        construct_proof(deps.as_mut(), cc_id.clone(), payload).unwrap();
        reply_signing_started(deps.as_mut(), MULTISIG_SESSION_ID, 1000).unwrap();

        // the amount is expressed in the token's XRPL decimals
        let expected_amount = XRPLPaymentAmount::Issued(
            local_token(),
            canonicalize_token_amount(Uint256::from(1_500_000u128), XRPL_TOKEN_DECIMALS).unwrap(),
        );
        match proof_tx(deps.as_ref(), MULTISIG_SESSION_ID) {
            XRPLUnsignedTx::Payment(tx) => {
                assert_eq!(tx.amount, expected_amount);
                assert_eq!(tx.destination, XRPL_DESTINATION.parse().unwrap());
                assert_eq!(tx.cc_id, Some(cc_id.clone()));
            }
            other => panic!("expected a payment, got {:?}", other),
        }
        let proof = query_proof(deps.as_ref(), None).unwrap();
        goldie::assert!(completed_proof(&proof).to_string());

        let response = confirm_proof(
            &mut deps,
            MULTISIG_SESSION_ID,
            VerificationStatus::SucceededOnSourceChain,
        )
        .unwrap();

        let event = find_event(&response, "interchain_transfer_received");
        assert_eq!(event_attribute::<TokenId>(event, "token_id"), token_id);
        assert_eq!(
            event_attribute::<nonempty::String>(event, "message_id"),
            cc_id.message_id
        );
        assert_eq!(
            event_attribute::<XRPLPaymentAmount>(event, "amount"),
            expected_amount
        );
    }

    #[test]
    fn payment_proof_cannot_be_rebuilt_while_its_signing_session_is_active() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();
        execute_construct_proof(deps.as_mut()).unwrap();
        // the session is still open at the current height
        reply_signing_started(deps.as_mut(), MULTISIG_SESSION_ID, mock_env().block.height).unwrap();
        let mut responses = MockResponses::new(
            test_data::operators(),
            VerificationStatus::SucceededOnSourceChain,
        );
        responses.multisig_state = MultisigState::Pending;
        deps.querier
            .update_wasm(mock_querier_handler_with(responses));

        assert_err(
            execute_construct_proof(deps.as_mut()),
            ContractError::PaymentAlreadyHasActiveSigningSession(MULTISIG_SESSION_ID.u64()),
        );
    }

    #[test]
    fn payment_proof_cannot_be_rebuilt_after_the_payment_succeeded() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();
        let (message, _) = test_data::outgoing_messages().remove(0);
        execute_construct_proof(deps.as_mut()).unwrap();
        reply_signing_started(deps.as_mut(), MULTISIG_SESSION_ID, 1000).unwrap();

        let response = confirm_proof(
            &mut deps,
            MULTISIG_SESSION_ID,
            VerificationStatus::SucceededOnSourceChain,
        )
        .unwrap();

        let event = find_event(&response, "interchain_transfer_received");
        assert_eq!(
            event_attribute::<TokenId>(event, "token_id"),
            TokenId::new(XRP_TOKEN_ID)
        );
        assert_eq!(
            event_attribute::<XRPLPaymentAmount>(event, "amount"),
            XRPLPaymentAmount::Drops(3_000_000)
        );
        assert_eq!(
            event_attribute::<XRPLAccountId>(event, "destination_address"),
            XRPL_DESTINATION.parse().unwrap()
        );
        assert_err(
            execute_construct_proof(deps.as_mut()),
            ContractError::PaymentAlreadySucceeded(message.cc_id),
        );
    }

    #[test]
    fn failed_payment_is_retried_with_a_new_ticket() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();
        execute_construct_proof(deps.as_mut()).unwrap();
        reply_signing_started(deps.as_mut(), Uint64::new(1), 1000).unwrap();
        let first_ticket = 44218196;
        assert_eq!(
            proof_sequence(deps.as_ref(), Uint64::new(1)),
            XRPLSequence::Ticket(first_ticket)
        );

        confirm_proof(
            &mut deps,
            Uint64::new(1),
            VerificationStatus::FailedOnSourceChain,
        )
        .unwrap();

        // the ticket is spent even though the payment failed
        assert_eq!(
            available_tickets(deps.as_ref()),
            INITIAL_TICKETS
                .filter(|ticket| *ticket != first_ticket)
                .collect::<Vec<_>>()
        );
        execute_construct_proof(deps.as_mut()).unwrap();
        reply_signing_started(deps.as_mut(), Uint64::new(2), 1000).unwrap();
        assert_eq!(
            proof_sequence(deps.as_ref(), Uint64::new(2)),
            XRPLSequence::Ticket(44218197)
        );
    }

    #[test]
    fn confirm_prover_message_rejects_double_confirmation_and_unverified_statuses() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();
        execute_construct_proof(deps.as_mut()).unwrap();
        reply_signing_started(deps.as_mut(), MULTISIG_SESSION_ID, 1000).unwrap();

        assert_err(
            confirm_proof(
                &mut deps,
                MULTISIG_SESSION_ID,
                VerificationStatus::InProgress,
            ),
            ContractError::TxStatusVerificationInProgress,
        );
        for status in [
            VerificationStatus::Unknown,
            VerificationStatus::FailedToVerify,
        ] {
            assert_err(
                confirm_proof(&mut deps, MULTISIG_SESSION_ID, status),
                ContractError::TxStatusUnknown,
            );
        }
        assert_err(
            confirm_proof(
                &mut deps,
                MULTISIG_SESSION_ID,
                VerificationStatus::NotFoundOnSourceChain,
            ),
            ContractError::InvalidTxStatus(XRPLTxStatus::Inconclusive),
        );

        confirm_proof(
            &mut deps,
            MULTISIG_SESSION_ID,
            VerificationStatus::SucceededOnSourceChain,
        )
        .unwrap();
        assert_err(
            confirm_proof(
                &mut deps,
                MULTISIG_SESSION_ID,
                VerificationStatus::SucceededOnSourceChain,
            ),
            ContractError::TxStatusAlreadyConfirmed,
        );
    }

    #[test]
    fn reply_rejects_missing_or_malformed_session_id() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();
        execute_construct_proof(deps.as_mut()).unwrap();
        let reply_with = |deps: DepsMut, data: Option<Binary>| {
            #[allow(deprecated)]
            let response = SubMsgResponse {
                events: vec![],
                data,
                msg_responses: vec![],
            };
            reply(
                deps,
                mock_env(),
                Reply {
                    id: START_MULTISIG_REPLY_ID,
                    result: SubMsgResult::Ok(response),
                    payload: vec![].into(),
                    gas_used: 0,
                },
            )
        };

        assert_err(
            reply_with(deps.as_mut(), None),
            ParseReplyError::ParseFailure("missing reply data".to_owned()).into(),
        );
        // an execute response without data encodes to no bytes at all
        assert_err(
            reply_with(deps.as_mut(), Some(Binary::default())),
            ContractError::InvalidContractReply {
                reason: "no data".to_string(),
            },
        );
        assert_err(
            reply_with(
                deps.as_mut(),
                Some(
                    prost::bytes::Bytes::from(b"not a session id".to_vec())
                        .encode_to_vec()
                        .into(),
                ),
            ),
            ContractError::InvalidContractReply {
                reason: "invalid multisig session ID".to_string(),
            },
        );
    }
}
