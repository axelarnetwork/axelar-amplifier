use thiserror::Error;

#[derive(Debug, Clone)]
pub enum MetricsMsg {
    IncBlockReceived,
}

#[derive(Debug, Error)]
pub enum MetricsError {
    #[error("failed to start metrics server")]
    Start,
    #[error("metrics server failed while running")]
    WhileRunning,
    #[error("failed to encode metrics")]
    EncodeError,
    #[error("failed to convert metrics to UTF-8")]
    Utf8Error,
    #[error("failed to update metric")]
    MetricUpdateFailed,
    #[error("failed to register metric")]
    MetricRegisterFailed,
    #[error("failed to spawn metric")]
    MetricSpawnFailed,
    #[error("counter not found: {0}")]
    CounterNotFound(String),
}