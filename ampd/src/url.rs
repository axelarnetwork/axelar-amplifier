use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::ops::Deref;

use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use url::ParseError;

use crate::types::debug::REDACTED_VALUE;

/// A URL wrapper that supports sensitivity-aware display and logging.
///
/// URLs often contain sensitive information like API keys, credentials, or internal
/// hostnames that should not appear in logs or error messages. This type wraps a
/// standard [`url::Url`] with a sensitivity flag that controls how the URL is displayed.
///
/// # Sensitivity Behavior
///
/// - **Sensitive URLs**: Created via [`Url::new_sensitive`] or deserialized with
///   [`Url::deserialize_sensitive`]. When displayed (via `Display` or `Debug`), these
///   show a redacted placeholder instead of the actual URL.
///
/// - **Non-sensitive URLs**: Created via [`Url::new_non_sensitive`] or deserialized with
///   [`Url::deserialize_non_sensitive`]. These display the full URL normally.
///
/// # Serialization
///
/// Serialization **always preserves the full URL** regardless of sensitivity. This ensures
/// config files are written correctly. Only display/debug output is affected by sensitivity.
///
/// # Equality
///
/// Two URLs are considered equal if their URL content matches, regardless of their
/// sensitivity flags. The sensitivity flag is metadata for display purposes, not part
/// of the URL's identity.
///
/// # Example
///
/// ```ignore
/// // In config structs, use deserialize_sensitive for URLs that may contain secrets:
/// #[derive(Deserialize)]
/// struct Config {
///     #[serde(deserialize_with = "Url::deserialize_sensitive")]
///     rpc_url: Url,  // Will show as "redacted" in logs
/// }
/// ```
#[derive(Eq, Clone)]
pub struct Url {
    inner: url::Url,
    is_sensitive: bool,
}

impl PartialEq for Url {
    fn eq(&self, other: &Self) -> bool {
        // Only compare the URL content, not the sensitivity flag.
        // The sensitivity flag is metadata for display/logging purposes,
        // not part of the URL's identity.
        self.inner == other.inner
    }
}

// Hash needs to be implemented explicitly, because the implication of url1 == url2 => hash(url1) == hash(url2) must be true
// The derived hasher would take the sensitivity flag into account so this would not be true anymore.
impl Hash for Url {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.hash(state);
    }
}

impl Deref for Url {
    type Target = url::Url;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Url {
    /// Creates a new sensitive URL that will be redacted in logs and display output.
    ///
    /// Use this for URLs that may contain API keys, credentials, or other secrets.
    pub fn new_sensitive(s: &str) -> Result<Self, ParseError> {
        url::Url::parse(s).map(|url| Self {
            inner: url,
            is_sensitive: true,
        })
    }

    /// Creates a new non-sensitive URL that will display normally.
    ///
    /// Use this for public URLs that are safe to show in logs.
    pub fn new_non_sensitive(s: &str) -> Result<Self, ParseError> {
        url::Url::parse(s).map(|url| Self {
            inner: url,
            is_sensitive: false,
        })
    }

    /// Deserializes a URL and marks it as sensitive.
    ///
    /// Use with `#[serde(deserialize_with = "Url::deserialize_sensitive")]` on config fields
    /// where the URL may contain secrets (e.g., RPC endpoints with API keys).
    pub fn deserialize_sensitive<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let url_str = String::deserialize(deserializer)?;
        Url::new_sensitive(&url_str).map_err(|err| D::Error::custom(err.to_string()))
    }

    /// Deserializes a URL and marks it as non-sensitive.
    ///
    /// Use with `#[serde(deserialize_with = "Url::deserialize_non_sensitive")]` on config fields
    /// where the URL is safe to display in logs.
    pub fn deserialize_non_sensitive<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let url_str = String::deserialize(deserializer)?;
        Url::new_non_sensitive(&url_str).map_err(|err| D::Error::custom(err.to_string()))
    }

    #[allow(clippy::inherent_to_string_shadow_display)]
    /// Converts the URL to a string, respecting sensitivity.
    ///
    /// If the URL is sensitive, returns a redacted placeholder; otherwise returns the full URL.
    /// For the unredacted URL (even when sensitive), use [`url::Url::as_str()`] via deref.
    pub fn to_string(&self) -> String {
        ToString::to_string(&self)
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
        let url = Url::new_non_sensitive("https://serialize.test").unwrap();
        let serialized = toml::to_string(&url).unwrap();
        assert!(serialized.contains("https://serialize.test"));

        let sensitive_url = Url::new_sensitive("https://sensitive.serialize.test").unwrap();
        let serialized = toml::to_string(&sensitive_url).unwrap();
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
