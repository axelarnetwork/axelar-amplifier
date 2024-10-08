use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("required property is empty")]
    PropertyEmpty,
}
