use std::convert::{TryFrom, TryInto};
use std::str::FromStr;

use crate::crypto::{hash_password, verify_password};
use crate::db::postgres::PgConn;
use crate::result::{Error, Result};
use crate::schema::users;

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use lettre::EmailAddress;
use pbkdf2::password_hash::PasswordHash;
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

#[non_exhaustive]
#[derive(Debug, Deserialize)]
pub struct CreateUser {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUser {
    pub password: String,
    pub new_password: Option<String>,
}

#[derive(AsChangeset)]
#[table_name = "users"]
struct UserChangeset {
    pub hash: Option<String>,
}

impl TryFrom<UpdateUser> for UserChangeset {
    type Error = Error;

    fn try_from(u: UpdateUser) -> core::result::Result<Self, Self::Error> {
        let UpdateUser {
            password: _,
            new_password,
        } = u;

        let hash = new_password.map_or(Ok(None), |p| hash_password(p.as_bytes()).map(Some))?;

        Ok(Self { hash })
    }
}

impl User {
    pub fn find_by_email(conn: &PgConn, email: &str) -> Result<Self> {
        use crate::schema::users::{columns, dsl::users};
        users
            .filter(columns::email.eq(email))
            .first(conn)
            .map_err(|e| match e {
                diesel::result::Error::NotFound => Error::UserNotFound,
                _ => e.into(),
            })
    }

    pub fn create(conn: &PgConn, query: &CreateUser) -> Result<Self> {
        let email = EmailAddress::from_str(&query.email).map_err(|_| Error::InvalidEmail)?;
        let hash = hash_password(query.password.as_bytes())?;

        let new_user = NewUser {
            id: Uuid::new_v4(),
            email: &email.to_string(),
            hash: &hash,
        };

        let inserted_row = diesel::insert_into(users::table)
            .values(&new_user)
            .get_result(conn)
            .map_err(|err| match err {
                diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::UniqueViolation,
                    _,
                ) => Error::EmailInUse,
                _ => err.into(),
            })?;

        Ok(inserted_row)
    }

    pub fn hash(&self) -> PasswordHash {
        PasswordHash::new(&self.hash).expect("failed to parse hash")
    }

    /// Update the user while verifying that the password is correct.
    pub fn update(&self, pg: &PgConn, update: UpdateUser) -> Result<Self> {
        verify_password(update.password.as_bytes(), &self.hash())?;

        let cs: UserChangeset = update.try_into()?;

        let result = diesel::update(self).set(cs).get_result::<Self>(pg)?;

        Ok(result)
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

    use crate::{db::postgres::pg_test_conn, result::Error};

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

    #[test]
    fn get_user_by_email() {
        let conn = pg_test_conn();

        match User::find_by_email(&conn, "nonexistentuser@example.com") {
            Err(Error::UserNotFound) => {}
            Err(other_error) => panic!("incorrect error ({})", other_error),
            Ok(_) => panic!("that user should not exist"),
        }
    }
}
