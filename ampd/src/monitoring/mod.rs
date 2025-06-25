mod endpoints;
pub mod server;

#[derive(Debug, Clone)]
pub enum MetricsMsg {
    IncBlockReceived,
}
