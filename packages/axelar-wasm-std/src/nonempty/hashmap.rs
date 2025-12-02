use std::hash::Hash;
use std::ops::Deref;

use serde::Serialize;

use crate::nonempty::Error;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct HashMap<K: Eq + Hash, V: Eq>(std::collections::HashMap<K, V>);

impl<K: Eq + Hash, V: Eq> TryFrom<std::collections::HashMap<K, V>> for HashMap<K, V> {
    type Error = Error;

    fn try_from(value: std::collections::HashMap<K, V>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err(Error::InvalidValue("empty".to_string()))
        } else {
            Ok(HashMap(value))
        }
    }
}

impl<K: Eq + Hash, V: Eq> From<HashMap<K, V>> for std::collections::HashMap<K, V> {
    fn from(value: HashMap<K, V>) -> Self {
        value.0
    }
}

impl<K: Eq + Hash, V: Eq> AsRef<std::collections::HashMap<K, V>> for HashMap<K, V> {
    fn as_ref(&self) -> &std::collections::HashMap<K, V> {
        &self.0
    }
}

impl<K: Eq + Hash, V: Eq> Deref for HashMap<K, V> {
    type Target = std::collections::HashMap<K, V>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_empty_map_should_convert_successfully() {
        let mut map = std::collections::HashMap::new();
        map.insert("key", "value");
        assert!(HashMap::try_from(map).is_ok())
    }

    #[test]
    fn empty_map_should_fail_conversion() {
        assert_eq!(
            HashMap::<String, String>::try_from(std::collections::HashMap::new()).unwrap_err(),
            Error::InvalidValue("empty".to_string())
        )
    }
}
