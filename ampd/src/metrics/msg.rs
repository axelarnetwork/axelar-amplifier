use std::fmt;
use error_stack::Context;

#[derive(Debug)]
pub enum MetricsMsg {
    IncBlockReceived,
    IncTimer,
}
// for error_stack
#[derive(Debug)]
pub enum MetricsError {
    Start,
    WhileRunning,
    EncodeError,
    Utf8Error,
    MetricUpdateFailed,
    MetricRegisterFailed,
    MetricSpawnFailed,
    CounterNotFound(String),
}

impl Context for MetricsError {}

impl fmt::Display for MetricsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetricsError::Start => write!(f, "failed to start metrics server"),
            MetricsError::WhileRunning => write!(f, "metrics server failed while running"),
            MetricsError::EncodeError => write!(f, "failed to encode metrics"),
            MetricsError::Utf8Error => write!(f, "failed to convert metrics to UTF-8"),
            MetricsError::MetricUpdateFailed => write!(f, "failed to update metric"),
            MetricsError::MetricRegisterFailed => write!(f, "failed to register metric"),
            MetricsError::MetricSpawnFailed => write!(f, "failed to spawn metric"),
            MetricsError::CounterNotFound(name) => write!(f, "counter not found: {}", name),
        }
    }
}
