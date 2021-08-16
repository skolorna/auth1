use crate::schema::users;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub type UserId = i32;

#[derive(Debug, Queryable, Identifiable, Clone, Serialize)]
#[serde(into = "JsonUser")]
pub struct User {
    pub id: UserId,
    pub email: String,
    pub email_verified: bool,
    pub hash: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Insertable)]
#[table_name = "users"]
pub struct NewUser<'a> {
    pub email: &'a str,
    pub hash: &'a str,
}

/// Public-facing version of [User], excluding sensitive data
/// such as the password hash.
#[derive(Debug, Serialize, Deserialize)]
struct JsonUser {
    id: UserId,
    email: String,
    email_verified: bool,
    created_at: DateTime<Utc>,
}

impl From<User> for JsonUser {
    fn from(u: User) -> Self {
        let User {
            id,
            email,
            email_verified,
            created_at,
            ..
        } = u;

        Self {
            id,
            email,
            email_verified,
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
            id: 31415,
            email: "user@example.com".into(),
            email_verified: true,
            hash: "quite secret; do not share".into(),
        };

        let serialized = serde_json::to_value(&user).unwrap();
        let expected = json!({
            "id": 31415,
            "email": "user@example.com",
            "email_verified": true,
            "created_at": "1970-01-01T00:00:00Z"
        });

        assert_eq!(serialized, expected);
        assert_ne!(serialized, json!({"id": 31415})); // Sanity check
    }
}
