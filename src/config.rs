use std::fmt::Formatter;

use deref_derive::Deref;
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer};

struct UrlVisitor;

impl<'a> Visitor<'a> for UrlVisitor {
    type Value = Url;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("a well-formed url string")
    }

    fn visit_str<E>(self, url: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        match url::Url::parse(url) {
            Ok(u) => Ok(Url(u)),
            Err(e) => Err(E::custom(e.to_string())),
        }
    }
}

#[derive(Debug, Deref)]
pub struct Url(url::Url);

impl<'a> Deserialize<'a> for Url {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        deserializer.deserialize_string(UrlVisitor)
    }
}

#[derive(Deserialize, Debug)]
#[serde(default)]
pub struct Config {
    tm_url: Url,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tm_url: Url(url::Url::parse("tcp://localhost:26657").unwrap()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn deserialize_url() {
        let expected_url = "tcp://localhost:26657";
        let cfg: Config = toml::from_str(format!("tm_url = '{expected_url}'").as_str()).unwrap();
        assert_eq!(cfg.tm_url.0.as_str(), expected_url)
    }

    #[test]
    fn fail_deserialization() {
        assert!(toml::from_str::<Config>("tm_url = 'some other string'").is_err());
        assert!(toml::from_str::<Config>("tm_url = 5").is_err());
    }
}
