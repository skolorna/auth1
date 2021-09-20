use std::{fmt::Display, str::FromStr};

use diesel::{
    backend::Backend,
    sql_types,
    types::{FromSql, ToSql},
};
use fast_chemail::parse_email;
use serde::{de, Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, AsExpression, FromSqlRow)]
#[sql_type = "diesel::sql_types::Text"]
pub struct EmailAddress(String);

impl EmailAddress {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for EmailAddress {
    type Err = fast_chemail::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_email(s)?;
        Ok(Self(s.to_owned()))
    }
}

impl Display for EmailAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'de> Deserialize<'de> for EmailAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(de::Error::custom)
    }
}

impl Serialize for EmailAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<DB> ToSql<sql_types::Text, DB> for EmailAddress
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

impl<DB> FromSql<sql_types::Text, DB> for EmailAddress
where
    DB: Backend,
    String: FromSql<sql_types::Text, DB>,
{
    fn from_sql(bytes: Option<&DB::RawValue>) -> diesel::deserialize::Result<Self> {
        // Validating stored values might be problematic ...
        String::from_sql(bytes).map(Self)
    }
}

impl From<EmailAddress> for lettre::EmailAddress {
    fn from(addr: EmailAddress) -> Self {
        // We can unwrap because it's already checked.
        Self::new(addr.0).unwrap()
    }
}
