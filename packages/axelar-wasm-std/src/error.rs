use thiserror::Error;

#[derive(Error, Debug)]
pub enum SnapshotError {
    #[error("None of the candidates was suitable to become a participant")]
    NoParticipants,

    #[error("Snapshot block height must be greater than 0")]
    ZeroHeight,

    #[error("Snapshot timestamp must be greater than 0")]
    ZeroTimestamp,
}
