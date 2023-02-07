use std::fmt::{Display, Formatter};
use std::str::FromStr;

use deref_derive::Deref;
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer};
use url::ParseError;

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

impl FromStr for Url {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        url::Url::parse(s).map(Url)
    }
}

impl Display for Url {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

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
        url.parse().map_err(|err: ParseError| E::custom(err.to_string()))
    }
}
