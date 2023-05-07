use thiserror::Error;

#[derive(Error, Debug)]
pub enum SnapshotError {
    #[error("None of the candidates was suitable to become a participant")]
    NoParticipants,
}
