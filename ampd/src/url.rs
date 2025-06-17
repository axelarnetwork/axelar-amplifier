use std::fmt::{Debug, Display, Formatter};
use std::ops::Deref;

use serde::de::{Error, Visitor};
use serde::{Deserializer, Serialize, Serializer};
use url::ParseError;

#[derive(Hash, PartialEq, Eq, Clone)]
pub struct Url {
    inner: url::Url,
    is_sensitive: bool,
}

impl Deref for Url {
    type Target = url::Url;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Url {
    fn new(url: url::Url, is_sensitive: bool) -> Self {
        Self {
            inner: url,
            is_sensitive,
        }
    }

    pub fn new_sensitive(s: &str) -> Result<Self, ParseError> {
        url::Url::parse(s).map(|url| Self::new(url, true))
    }

    pub fn new_non_sensitive(s: &str) -> Result<Self, ParseError> {
        url::Url::parse(s).map(|url| Self::new(url, false))
    }

    pub fn deserialize_sensitive<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_string(UrlVisitor { is_sensitive: true })
    }

    pub fn deserialize_non_sensitive<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_string(UrlVisitor {
            is_sensitive: false,
        })
    }

    pub fn to_standard_url(&self) -> url::Url {
        self.inner.clone()
    }
}

impl Serialize for Url {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.inner.as_str())
    }
}

impl Display for Url {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.is_sensitive {
            f.write_str("[REDACTED]")
        } else {
            f.write_str(self.inner.as_str())
        }
    }
}

impl Debug for Url {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.is_sensitive {
            f.write_str("[REDACTED]")
        } else {
            f.write_str(self.inner.as_str())
        }
    }
}

struct UrlVisitor {
    is_sensitive: bool,
}
impl Visitor<'_> for UrlVisitor {
    type Value = Url;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("a well-formed url string")
    }

    fn visit_str<E>(self, url: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        if self.is_sensitive {
            Url::new_sensitive(url).map_err(|err: ParseError| E::custom(err.to_string()))
        } else {
            Url::new_non_sensitive(url).map_err(|err: ParseError| E::custom(err.to_string()))
        }
    }
}
