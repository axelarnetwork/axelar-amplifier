use error_stack::{report, Report, ResultExt};
use sui_rpc::proto::sui::rpc::v2::ExecutedTransaction;
use sui_sdk_types::{Digest, Event, TransactionEvents};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid transaction digest")]
    Digest,
    #[error("invalid transaction events")]
    Events,
}

/// A finalized transaction reduced to what verification needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub digest: Digest,
    /// The emitted events in order; a message id's event index is a position in this list.
    pub events: Vec<Event>,
}

impl TryFrom<ExecutedTransaction> for Transaction {
    type Error = Report<Error>;

    fn try_from(transaction: ExecutedTransaction) -> Result<Self, Self::Error> {
        let digest = transaction
            .digest
            .as_deref()
            .and_then(|digest| digest.parse().ok())
            .ok_or_else(|| report!(Error::Digest))?;
        let events = transaction
            .events
            .as_ref()
            .map(TransactionEvents::try_from)
            .transpose()
            .change_context(Error::Events)?;

        Ok(Self {
            digest,
            events: events.map(|events| events.0).unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use sui_rpc::proto::sui::rpc::v2 as proto;

    use super::*;

    fn event() -> Event {
        Event {
            package_id: sui_sdk_types::Address::TWO,
            module: sui_sdk_types::Identifier::from_static("sui"),
            sender: sui_sdk_types::Address::ZERO,
            type_: "0x2::sui::SUI".parse().unwrap(),
            contents: b"contents".to_vec(),
        }
    }

    #[test]
    fn should_convert_executed_transaction() {
        let digest = Digest::generate(rand::thread_rng());
        let transaction = ExecutedTransaction::default()
            .with_digest(digest.to_string())
            .with_events(proto::TransactionEvents::from(TransactionEvents(vec![
                event(),
            ])));

        assert_eq!(
            Transaction::try_from(transaction).unwrap(),
            Transaction {
                digest,
                events: vec![event()],
            }
        );
    }

    #[test]
    fn should_fail_on_invalid_digest() {
        let transaction = ExecutedTransaction::default().with_digest("not a digest");

        let err = Transaction::try_from(transaction).unwrap_err();
        assert!(matches!(err.current_context(), Error::Digest));
    }

    #[test]
    fn should_fail_on_invalid_events() {
        let mut missing_contents = proto::Event::from(event());
        missing_contents.contents = None;
        let transaction = ExecutedTransaction::default()
            .with_digest(Digest::generate(rand::thread_rng()).to_string())
            .with_events(proto::TransactionEvents::default().with_events(vec![missing_contents]));

        let err = Transaction::try_from(transaction).unwrap_err();
        assert!(matches!(err.current_context(), Error::Events));
    }
}
