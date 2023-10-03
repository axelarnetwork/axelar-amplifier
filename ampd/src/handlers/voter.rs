use axelar_wasm_std::voting::PollID;
use cosmrs::cosmwasm::MsgExecuteContract;
use error_stack::ResultExt;
use voting_verifier::msg::ExecuteMsg;

use crate::handlers::errors::Error;
use crate::queue::queued_broadcaster::BroadcasterClient;
use crate::types::TMAddress;

type Result<T> = error_stack::Result<T, Error>;

pub struct Voter<B>
where
    B: BroadcasterClient,
{
    worker: TMAddress,
    voting_verifier: TMAddress,
    broadcast_client: B,
}

impl<B> Voter<B>
where
    B: BroadcasterClient,
{
    pub fn new(worker: TMAddress, voting_verifier: TMAddress, broadcast_client: B) -> Self {
        Self {
            worker,
            voting_verifier,
            broadcast_client,
        }
    }

    pub fn worker(&self) -> &TMAddress {
        &self.worker
    }

    pub fn voting_verifier(&self) -> &TMAddress {
        &self.voting_verifier
    }

    pub async fn vote(&self, poll_id: PollID, votes: Vec<bool>) -> Result<()> {
        let msg = serde_json::to_vec(&ExecuteMsg::Vote { poll_id, votes })
            .expect("vote msg should serialize");

        let tx = MsgExecuteContract {
            sender: self.worker.as_ref().clone(),
            contract: self.voting_verifier.as_ref().clone(),
            msg,
            funds: vec![],
        };

        self.broadcast_client
            .broadcast(tx)
            .await
            .change_context(Error::Broadcaster)
    }
}
