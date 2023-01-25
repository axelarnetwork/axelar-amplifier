use crate::url::Url;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
#[serde(default)]
pub struct Config {
    tm_url: Url,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tm_url: "tcp://localhost:26657".parse().unwrap(),
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
        assert_eq!(cfg.tm_url.as_str(), expected_url)
    }

    #[test]
    fn fail_deserialization() {
        assert!(toml::from_str::<Config>("tm_url = 'some other string'").is_err());
        assert!(toml::from_str::<Config>("tm_url = 5").is_err());
    }
}
