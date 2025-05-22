#[derive(Debug)]
pub enum MetricsMsg {
    IncBlockReceived,
}

#[derive(Debug)]
pub enum MetricsError {
    EncodeError,
    Utf8Error,
}
