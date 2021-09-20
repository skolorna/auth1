use std::{fmt::Display, str::FromStr};

use diesel::{
    backend::Backend,
    sql_types,
    types::{FromSql, ToSql},
};
use serde::{de, Deserialize, Deserializer, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, AsExpression, FromSqlRow)]
#[sql_type = "diesel::sql_types::Text"]
pub struct PersonalName(String);

impl PersonalName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Error)]
pub enum ParsePersonalNameError {
    #[error("empty personal name")]
    Empty,

    #[error("invalid personal name")]
    InvalidName,

    #[error("invalid whitespace")]
    InvalidWhitespace,

    #[error("untrimmed personal name")]
    Untrimmed,
}

impl FromStr for PersonalName {
    type Err = ParsePersonalNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for c in s.chars() {
            if c.is_whitespace() && c != ' ' {
                return Err(ParsePersonalNameError::InvalidWhitespace);
            }
        }

        if s.is_empty() {
            return Err(ParsePersonalNameError::Empty);
        }

        if s.trim() != s {
            return Err(ParsePersonalNameError::Untrimmed);
        }

        Ok(Self(s.to_owned()))
    }
}

impl Display for PersonalName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<'de> Deserialize<'de> for PersonalName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(de::Error::custom)
    }
}

impl Serialize for PersonalName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<DB> ToSql<sql_types::Text, DB> for PersonalName
where
    DB: Backend,
    String: ToSql<sql_types::Text, DB>,
{
    fn to_sql<W: std::io::Write>(
        &self,
        out: &mut diesel::serialize::Output<W, DB>,
    ) -> diesel::serialize::Result {
        self.0.to_sql(out)
    }
}

impl<DB> FromSql<sql_types::Text, DB> for PersonalName
where
    DB: Backend,
    String: FromSql<sql_types::Text, DB>,
{
    fn from_sql(bytes: Option<&DB::RawValue>) -> diesel::deserialize::Result<Self> {
        String::from_sql(bytes).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::types::PersonalName;

    #[test]
    fn validation() {
        let valid_names = vec![
            "Åke Amcoff",
            "Bill Gates",
            "Фёдор Михайлович Достоевский",
            "فلانة",
            "张三",
            "X Æ A-Xii Musk",
            "🐢",
        ];

        for name in valid_names {
            assert!(PersonalName::from_str(name).is_ok());
        }

        let invalid_names = vec![
            "",
            "\t",
            "\t\t  Bobby Tables",
            "Bobby\nTables",
            "           Bobby Tables    ",
        ];

        for name in invalid_names {
            assert!(
                PersonalName::from_str(name).is_err(),
                "\"{}\" should not be considered a valid personal name",
                name
            );
        }
    }
}
