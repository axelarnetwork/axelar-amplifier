use std::ops::{Deref, DerefMut};

use schemars::gen::SchemaGenerator;
use schemars::schema::Schema;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct FlagSet<T>(flagset::FlagSet<T>)
where
    flagset::FlagSet<T>: Serialize,
    T: flagset::Flags + Serialize,
    <T as flagset::Flags>::Type: Serialize;

impl<T> From<T> for FlagSet<T>
where
    flagset::FlagSet<T>: From<T>,
    T: flagset::Flags + Serialize,
    <T as flagset::Flags>::Type: Serialize,
{
    fn from(flag: T) -> Self {
        FlagSet(flagset::FlagSet::from(flag))
    }
}

impl<T> From<flagset::FlagSet<T>> for FlagSet<T>
where
    flagset::FlagSet<T>: Serialize,
    T: flagset::Flags + Serialize,
    <T as flagset::Flags>::Type: Serialize,
{
    fn from(flag_set: flagset::FlagSet<T>) -> Self {
        FlagSet(flag_set)
    }
}

impl<T> Deref for FlagSet<T>
where
    T: flagset::Flags + Serialize,
    <T as flagset::Flags>::Type: Serialize,
{
    type Target = flagset::FlagSet<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for FlagSet<T>
where
    T: flagset::Flags + Serialize,
    <T as flagset::Flags>::Type: Serialize,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'de, T> Deserialize<'de> for FlagSet<T>
where
    T: flagset::Flags + Serialize,
    <T as flagset::Flags>::Type: Serialize + Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        flagset::FlagSet::<T>::deserialize(deserializer).map(FlagSet::from)
    }
}

impl<T> JsonSchema for FlagSet<T>
where
    T: flagset::Flags + Serialize + JsonSchema,
    <T as flagset::Flags>::Type: Serialize,
{
    fn schema_name() -> String {
        "FlagSet".to_string()
    }

    fn json_schema(gen: &mut SchemaGenerator) -> Schema {
        gen.subschema_for::<T>()
    }
}
