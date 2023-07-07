use aggregate_verifier::error::ContractError;
use connection_router::msg::Message;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{to_binary, Addr, DepsMut, Env, MessageInfo, Response};
use cw_multi_test::{App, ContractWrapper, Executor};
use cw_storage_plus::Map;

const MOCK_VOTING_VERIFIER_MESSAGES: Map<String, bool> = Map::new("voting_verifier_messages");

#[cw_serde]
pub enum MockVotingVerifierExecuteMsg {
    VerifyMessages { messages: Vec<Message> },
    MessagesVerified { messages: Vec<Message> },
}

#[cw_serde]
pub struct MockVotingVerifierInstantiateMsg {}

pub fn mock_verifier_execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: MockVotingVerifierExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        MockVotingVerifierExecuteMsg::VerifyMessages { messages } => {
            let mut res = vec![];
            for m in messages {
                let m = connection_router::state::Message::try_from(m).unwrap();
                match MOCK_VOTING_VERIFIER_MESSAGES.may_load(deps.storage, m.id.to_string())? {
                    Some(b) => res.push((m.id.to_string(), b)),
                    None => res.push((m.id.to_string(), false)),
                }
            }
            Ok(Response::new().set_data(to_binary(&res)?))
        }
        MockVotingVerifierExecuteMsg::MessagesVerified { messages } => {
            for m in messages {
                let m = connection_router::state::Message::try_from(m).unwrap();
                MOCK_VOTING_VERIFIER_MESSAGES.save(deps.storage, m.id.to_string(), &true)?;
            }
            Ok(Response::new())
        }
    }
}

pub fn mark_messages_as_verified(
    app: &mut App,
    voting_verifier_address: Addr,
    msgs: Vec<connection_router::msg::Message>,
) {
    app.execute_contract(
        Addr::unchecked("relayer"),
        voting_verifier_address.clone(),
        &MockVotingVerifierExecuteMsg::MessagesVerified { messages: msgs },
        &[],
    )
    .unwrap();
}

pub fn make_mock_voting_verifier(app: &mut App) -> Addr {
    let code = ContractWrapper::new(
        mock_verifier_execute,
        |_, _, _, _: MockVotingVerifierInstantiateMsg| {
            Ok::<Response, ContractError>(Response::new())
        },
        |_, _, _: aggregate_verifier::msg::QueryMsg| to_binary(&()),
    );
    let code_id = app.store_code(Box::new(code));

    let contract_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("voting_verifier"),
            &MockVotingVerifierInstantiateMsg {},
            &[],
            "Contract",
            None,
        )
        .unwrap();
    contract_address
}
