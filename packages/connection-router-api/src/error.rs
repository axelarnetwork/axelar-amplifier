use thiserror::Error;

/// A chain name must adhere to the following rules:
/// 1. it can optionally start with an uppercase letter, followed by one or more lowercase letters
/// 2. it can have an optional suffix of an optional dash and one or more digits ("1", "03", "-5" are all valid suffixes)
pub const CHAIN_NAME_REGEX: &str = "^[A-Z]?[a-z]+(-?[0-9]+)?$";

#[derive(Error, Debug)]
pub enum Error {
    #[error("chain name '{}' must adhere to the pattern '{}'", .0, CHAIN_NAME_REGEX)]
    ChainNamePatternMismatch(String),
    #[error("address must not be empty")]
    EmptyAddress,
}
