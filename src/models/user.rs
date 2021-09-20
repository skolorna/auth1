use std::convert::{TryFrom, TryInto};

use crate::crypto::{hash_password, verify_password};
use crate::db::postgres::PgConn;
use crate::email::{send_verification_email, SmtpConnection};
use crate::result::{Error, Result};
use crate::schema::users;
use crate::types::{EmailAddress, PersonalName};

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use lettre_email::Mailbox;
use pbkdf2::password_hash::PasswordHash;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type UserId = Uuid;

#[derive(Debug, Queryable, Identifiable, Clone, Serialize)]
#[serde(into = "JsonUser")]
pub struct User {
    pub id: UserId,
    pub email: EmailAddress,
    pub verified: bool,
    pub hash: String,
    pub created_at: DateTime<Utc>,
    pub full_name: PersonalName,
}

#[non_exhaustive]
#[derive(Debug, Deserialize)]
pub struct CreateUser {
    pub email: EmailAddress,
    pub password: String,
    pub full_name: PersonalName,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUser {
    pub password: String,
    pub new_password: Option<String>,
    pub email: Option<EmailAddress>,
    pub full_name: Option<PersonalName>,
}

#[derive(AsChangeset, Default, PartialEq, Eq)]
#[table_name = "users"]
struct UserChangeset {
    pub hash: Option<String>,
    pub email: Option<EmailAddress>,
    pub full_name: Option<PersonalName>,
}

impl UserChangeset {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

impl TryFrom<UpdateUser> for UserChangeset {
    type Error = Error;

    fn try_from(u: UpdateUser) -> core::result::Result<Self, Self::Error> {
        let UpdateUser {
            password: _,
            new_password,
            email,
            full_name,
        } = u;

        let hash = new_password.map_or(Ok(None), |p| hash_password(p.as_bytes()).map(Some))?;

        let cs = Self {
            hash,
            email,
            full_name,
        };

        if cs.is_empty() {
            Err(Error::NoUserChanges)
        } else {
            Ok(cs)
        }
    }
}

fn map_diesel_error(err: diesel::result::Error) -> Error {
    use diesel::result::{
        DatabaseErrorKind,
        Error::{DatabaseError, NotFound},
    };

    match err {
        NotFound => Error::UserNotFound,
        DatabaseError(DatabaseErrorKind::UniqueViolation, _) => Error::EmailInUse,
        _ => err.into(),
    }
}

impl User {
    pub fn find_by_email(conn: &PgConn, email: &EmailAddress) -> Result<Self> {
        use crate::schema::users::{columns, dsl::users};
        users
            .filter(columns::email.eq(email))
            .first(conn)
            .map_err(map_diesel_error)
    }

    pub fn create(conn: &PgConn, query: &CreateUser) -> Result<Self> {
        let hash = hash_password(query.password.as_bytes())?;

        let new_user = NewUser {
            id: Uuid::new_v4(),
            email: query.email.as_str(),
            hash: &hash,
            full_name: query.full_name.as_str(),
        };

        let inserted_row = diesel::insert_into(users::table)
            .values(&new_user)
            .get_result(conn)
            .map_err(map_diesel_error)?;

        Ok(inserted_row)
    }

    pub fn hash(&self) -> PasswordHash {
        PasswordHash::new(&self.hash).expect("failed to parse hash")
    }

    /// Update the user while verifying that the password is correct.
    pub fn update(&self, smtp: &SmtpConnection, pg: &PgConn, update: UpdateUser) -> Result<Self> {
        verify_password(update.password.as_bytes(), &self.hash())?;

        let cs: UserChangeset = update.try_into()?;

        let result = diesel::update(self)
            .set(cs)
            .get_result::<Self>(pg)
            .map_err(map_diesel_error)?;

        if result.email != self.email {
            send_verification_email(smtp, &result)?;
        }

        Ok(result)
    }

    pub fn mailbox(&self) -> Mailbox {
        Mailbox::new_with_name(self.full_name.to_string(), self.email.to_string())
    }
}

#[derive(Debug, Insertable)]
#[table_name = "users"]
pub struct NewUser<'a> {
    pub id: UserId,
    pub email: &'a str,
    pub hash: &'a str,
    pub full_name: &'a str,
}

/// Public-facing version of [User], excluding sensitive data
/// such as the password hash.
#[derive(Debug, Serialize, Deserialize)]
struct JsonUser {
    id: UserId,
    email: EmailAddress,
    verified: bool,
    created_at: DateTime<Utc>,
    full_name: PersonalName,
}

impl From<User> for JsonUser {
    fn from(
        User {
            id,
            email,
            verified,
            created_at,
            full_name,
            hash: _,
        }: User,
    ) -> Self {
        Self {
            id,
            email,
            verified,
            created_at,
            full_name,
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
            email: "user@example.com".parse().unwrap(),
            verified: true,
            hash: "quite secret; do not share".into(),
            full_name: "Jay Gatsby".parse().unwrap(),
        };

        let serialized = serde_json::to_value(&user).unwrap();
        let expected = json!({
            "id": Uuid::nil(),
            "email": "user@example.com",
            "verified": true,
            "created_at": "1970-01-01T00:00:00Z",
            "full_name": "Jay Gatsby"
        });

        assert_eq!(serialized, expected);
        assert_ne!(serialized, json!({"id": 31415})); // Sanity check
    }

    #[test]
    fn get_user_by_email() {
        let conn = pg_test_conn();

        match User::find_by_email(&conn, &"nonexistentuser@example.com".parse().unwrap()) {
            Err(Error::UserNotFound) => {}
            Err(other_error) => panic!("incorrect error ({})", other_error),
            Ok(_) => panic!("that user should not exist"),
        }
    }
}
