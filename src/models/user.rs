use crate::result::Result;
use crate::{schema::users, DbConn};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type UserId = Uuid;

#[derive(Debug, Queryable, Identifiable, Clone, Serialize)]
#[serde(into = "JsonUser")]
pub struct User {
    pub id: UserId,
    pub email: String,
    pub verified: bool,
    pub hash: String,
    pub created_at: DateTime<Utc>,
}

impl User {
    pub fn find_by_email(conn: &DbConn, email: &str) -> Result<Self> {
        use crate::schema::users::{columns, dsl::users};
        let user = users.filter(columns::email.eq(email)).first(conn)?;
        Ok(user)
    }
}

#[derive(Debug, Insertable)]
#[table_name = "users"]
pub struct NewUser<'a> {
    pub id: UserId,
    pub email: &'a str,
    pub hash: &'a str,
}

/// Public-facing version of [User], excluding sensitive data
/// such as the password hash.
#[derive(Debug, Serialize, Deserialize)]
struct JsonUser {
    id: UserId,
    email: String,
    verified: bool,
    created_at: DateTime<Utc>,
}

impl From<User> for JsonUser {
    fn from(u: User) -> Self {
        let User {
            id,
            email,
            verified,
            created_at,
            ..
        } = u;

        Self {
            id,
            email,
            verified,
            created_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::NaiveDateTime;
    use serde_json::json;

    use super::*;

    #[test]
    fn user_serialization() {
        let user = User {
            created_at: DateTime::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc),
            id: Uuid::nil(),
            email: "user@example.com".into(),
            verified: true,
            hash: "quite secret; do not share".into(),
        };

        let serialized = serde_json::to_value(&user).unwrap();
        let expected = json!({
            "id": Uuid::nil(),
            "email": "user@example.com",
            "verified": true,
            "created_at": "1970-01-01T00:00:00Z"
        });

        assert_eq!(serialized, expected);
        assert_ne!(serialized, json!({"id": 31415})); // Sanity check
    }
}
