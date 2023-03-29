use anyhow::Result as AnyResult;

use cosmwasm_std::{Addr, Binary, Uint64};
use cw_multi_test::{App, AppResponse, Executor};

use super::setup::ANY;
use crate::msg::{ActionMessage, ActionResponse, AdminOperation, ExecuteMsg};

pub fn request_worker_action(app: &mut App, service_addr: Addr) -> AnyResult<AppResponse> {
    let msg: ExecuteMsg<ActionMessage, ActionResponse, AdminOperation> =
        ExecuteMsg::RequestWorkerAction {
            message: ActionMessage::SignCommands {},
        };
    app.execute_contract(Addr::unchecked(ANY), service_addr, &msg, &[])
}

pub fn post_worker_reply(
    app: &mut App,
    worker: &str,
    service_addr: Addr,
    signing_session_id: Uint64,
    signature: Binary,
) -> AnyResult<AppResponse> {
    let msg: ExecuteMsg<ActionMessage, ActionResponse, AdminOperation> =
        ExecuteMsg::PostWorkerReply {
            reply: ActionResponse::SubmitSignature {
                signing_session_id,
                signature,
            },
        };
    app.execute_contract(Addr::unchecked(worker), service_addr, &msg, &[])
}

pub fn finalize_actions(app: &mut App, service_addr: Addr) -> AnyResult<AppResponse> {
    let msg: ExecuteMsg<ActionMessage, ActionResponse, AdminOperation> =
        ExecuteMsg::FinalizeActions {};
    app.execute_contract(Addr::unchecked(ANY), service_addr, &msg, &[])
}
