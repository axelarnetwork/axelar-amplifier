use async_trait::async_trait;
use axelar_wasm_std::voting::PollID;
use cosmrs::cosmwasm::MsgExecuteContract;
use error_stack::ResultExt;
use mockall::automock;
use voting_verifier::msg::ExecuteMsg;

use crate::handlers::errors::Error;
use crate::queue::queued_broadcaster::BroadcasterClient;
use crate::types::TMAddress;

type Result<T> = error_stack::Result<T, Error>;

#[automock]
#[async_trait]
pub trait Voter {
    fn is_one_of(&self, participants: &[TMAddress]) -> bool;
    fn is_voting_verifier(&self, contract: &TMAddress) -> bool;
    async fn vote(&self, poll_id: PollID, votes: Vec<bool>) -> Result<()>;
}

#[async_trait]
impl<B> Voter for VotingBroadcaster<B>
where
    B: BroadcasterClient + Send + Sync,
{
    fn is_one_of(&self, participants: &[TMAddress]) -> bool {
        participants.contains(&self.worker)
    }

    fn is_voting_verifier(&self, contract: &TMAddress) -> bool {
        &self.voting_verifier == contract
    }

    async fn vote(&self, poll_id: PollID, votes: Vec<bool>) -> Result<()> {
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

pub struct VotingBroadcaster<B>
where
    B: BroadcasterClient,
{
    worker: TMAddress,
    voting_verifier: TMAddress,
    broadcast_client: B,
}

impl<B> VotingBroadcaster<B>
where
    B: BroadcasterClient,
{
    #[allow(dead_code)]
    pub fn new(worker: TMAddress, voting_verifier: TMAddress, broadcast_client: B) -> Self {
        Self {
            worker,
            voting_verifier,
            broadcast_client,
        }
    }
}

#[cfg(test)]
mod test {
    use cosmrs::cosmwasm::MsgExecuteContract;
    use tokio::test as async_test;

    use crate::handlers::voter::{Voter, VotingBroadcaster};
    use crate::queue::queued_broadcaster::MockBroadcasterClient;
    use crate::types::TMAddress;

    const PREFIX: &str = "axelar";

    #[test]
    fn voter_is_a_participant() {
        let worker = TMAddress::random(PREFIX);
        let voter = VotingBroadcaster::new(
            worker.clone(),
            TMAddress::random(PREFIX),
            MockBroadcasterClient::new(),
        );

        assert!(voter.is_one_of(&vec![worker]));
    }

    #[test]
    fn voter_is_not_a_participant() {
        let voter = VotingBroadcaster::new(
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            MockBroadcasterClient::new(),
        );

        assert!(!voter.is_one_of(&vec![TMAddress::random(PREFIX)]));
    }

    #[test]
    fn contract_is_voting_verifier() {
        let voting_verifier = TMAddress::random(PREFIX);
        let voter = VotingBroadcaster::new(
            TMAddress::random(PREFIX),
            voting_verifier.clone(),
            MockBroadcasterClient::new(),
        );

        assert!(voter.is_voting_verifier(&voting_verifier));
    }

    #[test]
    fn contract_is_not_voting_verifier() {
        let voter = VotingBroadcaster::new(
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            MockBroadcasterClient::new(),
        );

        assert!(!voter.is_voting_verifier(&TMAddress::random(PREFIX)));
    }

    #[async_test]
    async fn should_submit_vote() {
        let mut broadcaster = MockBroadcasterClient::new();

        broadcaster
            .expect_broadcast()
            .once()
            .returning(move |_: MsgExecuteContract| Ok(()));

        let voter = VotingBroadcaster::new(
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            broadcaster,
        );

        assert!(voter.vote("1".parse().unwrap(), vec![true]).await.is_ok());
    }
}
