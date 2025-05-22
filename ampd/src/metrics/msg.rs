
#[derive(Debug)]
pub enum MetricsMsg {
    IncBlockReceived,
}

#[derive(Debug)]
pub enum MetricsError {
    EncodeError(String),
    Utf8Error(String),
}