use serde::Deserialize;

#[derive(Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct TransactionId(pub String);

impl TransactionId {
    pub fn as_str(&self) -> &str {
        return self.0.as_str();
    }
}

#[derive(Deserialize, Debug, PartialEq)]
pub struct XRPLAddress(pub String);