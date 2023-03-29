use anyhow::Result as AnyResult;

use cosmwasm_std::{Addr, Uint256, Uint64};
use cw_multi_test::{App, AppResponse, Executor};

use super::setup::ANY;
use crate::msg::{ActionMessage, ActionResponse, AdminOperation, ExecuteMsg};

pub fn request_worker_action(
    app: &mut App,
    service_addr: Addr,
    from_nonce: Uint256,
    to_nonce: Uint256,
) -> AnyResult<AppResponse> {
    let msg: ExecuteMsg<ActionMessage, ActionResponse, AdminOperation> =
        ExecuteMsg::RequestWorkerAction {
            message: ActionMessage::ConfirmGatewayTxs {
                from_nonce,
                to_nonce,
            },
        };
    app.execute_contract(Addr::unchecked(ANY), service_addr, &msg, &[])
}

pub fn post_worker_reply(
    app: &mut App,
    worker: &str,
    service_addr: Addr,
    poll_id: Uint64,
    calls_hash: [u8; 32],
) -> AnyResult<AppResponse> {
    let msg: ExecuteMsg<ActionMessage, ActionResponse, AdminOperation> =
        ExecuteMsg::PostWorkerReply {
            reply: ActionResponse::ConfirmGatewayTxs {
                poll_id,
                calls_hash,
            },
        };
    app.execute_contract(Addr::unchecked(worker), service_addr, &msg, &[])
}

pub fn finalize_actions(app: &mut App, service_addr: Addr) -> AnyResult<AppResponse> {
    let msg: ExecuteMsg<ActionMessage, ActionResponse, AdminOperation> =
        ExecuteMsg::FinalizeActions {};
    app.execute_contract(Addr::unchecked(ANY), service_addr, &msg, &[])
}
