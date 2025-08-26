use std::fmt::{Debug, Display, Formatter};
use std::ops::Deref;

use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use url::ParseError;

use crate::types::debug::REDACTED_VALUE;

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
    pub fn new_sensitive(s: &str) -> Result<Self, ParseError> {
        url::Url::parse(s).map(|url| Self {
            inner: url,
            is_sensitive: true,
        })
    }

    pub fn new_non_sensitive(s: &str) -> Result<Self, ParseError> {
        url::Url::parse(s).map(|url| Self {
            inner: url,
            is_sensitive: false,
        })
    }

    pub fn deserialize_sensitive<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let url_str = String::deserialize(deserializer)?;
        Url::new_sensitive(&url_str).map_err(|err| D::Error::custom(err.to_string()))
    }

    pub fn deserialize_non_sensitive<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let url_str = String::deserialize(deserializer)?;
        Url::new_non_sensitive(&url_str).map_err(|err| D::Error::custom(err.to_string()))
    }

    #[allow(clippy::inherent_to_string_shadow_display)]
    /// This is an explicit shadowing of the `to_string` method to avoid confusion with the `Display` implementation.
    /// If the `Url` is sensitive, it returns a redacted value; otherwise, it returns the full URL as a string.
    /// For the unredacted URL string (even when it's marked as sensitive), use the [`url::Url::as_str()`] method instead.
    pub fn to_string(&self) -> String {
        ToString::to_string(&self)
    }
}

impl Serialize for Url {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as a string value
        let url_str = self.inner.as_str();
        url_str.serialize(serializer)
    }
}

impl Display for Url {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.is_sensitive {
            f.write_str(REDACTED_VALUE)
        } else {
            f.write_str(self.inner.as_str())
        }
    }
}

impl From<Url> for url::Url {
    fn from(value: Url) -> Self {
        value.inner
    }
}

impl Debug for Url {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[test]
    fn test_new_sensitive_and_display_debug() {
        let url = Url::new_sensitive("http://secret.api/key").unwrap();
        assert_eq!(format!("{}", url), REDACTED_VALUE);
        assert_eq!(format!("{:?}", url), REDACTED_VALUE);
    }

    #[test]
    fn test_new_non_sensitive_and_display_debug() {
        let url = Url::new_non_sensitive("http://public.api").unwrap();
        assert_eq!(format!("{}", url), "http://public.api/");
        assert_eq!(format!("{:?}", url), "http://public.api/");
    }

    #[test]
    fn test_from_trait_convert_to_url_sucessfully() {
        let original = "https://example.com";
        let url = Url::new_non_sensitive(original).unwrap();
        let inner: url::Url = url::Url::from(url);
        assert_eq!(inner.as_str(), "https://example.com/");
    }

    #[test]
    fn serialization_preserves_full_url_regardless_of_sensitivity() {
        #[derive(Serialize)]
        struct TestStruct {
            url: Url,
        }

        let url = Url::new_non_sensitive("https://serialize.test").unwrap();
        let test_struct = TestStruct { url };
        let serialized = toml::to_string_pretty(&test_struct).unwrap();
        assert!(serialized.contains("https://serialize.test"));

        let sensitive_url = Url::new_sensitive("https://sensitive.serialize.test").unwrap();
        let test_struct = TestStruct { url: sensitive_url };
        let serialized = toml::to_string_pretty(&test_struct).unwrap();
        assert!(serialized.contains("https://sensitive.serialize.test"));
    }

    #[test]
    fn deserialize_sensitive_marks_url_as_sensitive_and_redacts_display() {
        #[derive(Deserialize)]
        struct TestConfig {
            #[serde(deserialize_with = "Url::deserialize_sensitive")]
            url: Url,
        }
        let toml_str = r#"url = "https://sensitive.test""#;
        let config: TestConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(format!("{}", config.url), REDACTED_VALUE);
        assert_eq!(config.url.as_str(), "https://sensitive.test/");
    }

    #[test]
    fn deserialize_non_sensitive_shows_full_url_in_display() {
        #[derive(Deserialize)]
        struct TestConfig {
            #[serde(deserialize_with = "Url::deserialize_non_sensitive")]
            url: Url,
        }
        let toml_str = r#"url = "https://non-sensitive.test""#;
        let config: TestConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(format!("{}", config.url), "https://non-sensitive.test/");
        assert_eq!(config.url.as_str(), "https://non-sensitive.test/");
    }
}
