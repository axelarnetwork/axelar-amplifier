use axelar_wasm_std::voting::Vote;
use tracing::warn;

use crate::monitoring;
use crate::monitoring::metrics::Msg;

pub fn record_vote_verification_metric(
    monitoring_client: &monitoring::Client,
    vote: &Vote,
    chain_name: &str,
) {
    if let Err(err) = monitoring_client
        .metrics()
        .record_metric(Msg::VoteVerification {
            vote_status: vote.clone(),
            chain_name: chain_name.to_string(),
        })
    {
        warn!(error = %err,
            chain_name = %chain_name,
            "failed to record vote verification metrics for vote {:?}", vote);
    };
}
