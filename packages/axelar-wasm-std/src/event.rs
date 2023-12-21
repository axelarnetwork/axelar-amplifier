use serde::Serialize;
use serde_json::to_string;

pub fn attribute_value<T>(v: &T) -> Result<String, serde_json::error::Error>
where
    T: ?Sized + Serialize,
{
    let json = to_string(v)?;
    // using strip_* instead of trim_matches because the latter trims any number of quotes instead of just one
    let json = json.strip_prefix('"').unwrap_or(&json);
    Ok(json.strip_suffix('"').unwrap_or(json).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct Foo {
        s: String,
    }

    #[test]
    fn attribute_value_without_quotes() {
        let foo = Foo {
            s: "hello".to_string(),
        };
        assert_eq!(attribute_value(&foo).unwrap(), r#"{"s":"hello"}"#);
    }

    #[test]
    fn attribute_value_with_quotes() {
        let foo = Foo {
            s: "\"hello\"".to_string(),
        };
        assert_eq!(attribute_value(&foo).unwrap(), r#"{"s":"\"hello\""}"#);
    }
}
