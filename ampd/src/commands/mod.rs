use clap::Subcommand;
use valuable::Valuable;

pub mod daemon;
pub mod worker_address;

#[derive(Debug, Subcommand, Valuable)]
pub enum SubCommand {
    /// Run the ampd daemon process (default)
    Daemon,
    /// Query the worker address
    WorkerAddress,
}
