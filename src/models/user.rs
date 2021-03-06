use std::convert::{TryFrom, TryInto};

use crate::db::postgres::PgConn;
use crate::email::Emails;
use crate::errors::{AppError, AppResult};
use crate::password::{hash_password, verify_password};
use crate::schema::users;
use crate::token::{access_token, refresh_token, TokenResponse, VerificationToken};
use crate::types::{EmailAddress, PersonalName};
use crate::x509::ca::CertificateAuthority;

use chrono::{DateTime, Utc};
use diesel::{insert_into, prelude::*};
use lettre::message::Mailbox;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::Certificate;

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
    pub jwt_secret: Vec<u8>,
}

impl User {
    pub fn find_by_email(conn: &PgConn, email: &EmailAddress) -> QueryResult<Option<Self>> {
        use crate::schema::users::{columns, dsl::users};
        let user = users
            .filter(columns::email.eq(email))
            .first(conn)
            .optional()?;

        Ok(user)
    }

    /// Update the user while verifying that the password is correct.
    pub fn update(&self, emails: &Emails, pg: &PgConn, update: UpdateUser) -> AppResult<Self> {
        verify_password(&update.password, &self.hash)?;

        let cs: UserChangeset = update.try_into()?;

        let result = diesel::update(self)
            .set(cs)
            .get_result::<Self>(pg)
            .map_err(handle_diesel_error)?;

        if result.email != self.email {
            let token = VerificationToken::generate(&result)?;
            let _ = emails.send_user_confirmation(&result, token);
        }

        Ok(result)
    }

    pub fn get_tokens(&self, pg: &PgConn, ca: &CertificateAuthority) -> AppResult<TokenResponse> {
        let cert = Certificate::for_signing(pg, ca)?;

        let access_token = access_token::sign(&cert, self.id)?;
        let refresh_token = refresh_token::sign(self.id, &self.jwt_secret)?;

        AppResult::Ok(TokenResponse {
            access_token,
            refresh_token: Some(refresh_token),
        })
    }

    pub fn mailbox(&self) -> Mailbox {
        Mailbox::new(Some(self.full_name.to_string()), self.email.clone().into())
    }
}

#[derive(Debug, Insertable)]
#[table_name = "users"]
pub struct NewUser<'a> {
    pub id: UserId,
    pub email: &'a EmailAddress,
    pub hash: String,
    pub full_name: &'a str,
    pub jwt_secret: Vec<u8>,
}

impl<'a> NewUser<'a> {
    pub fn new(query: &'a RegisterUser) -> AppResult<Self> {
        let hash = hash_password(&query.password)?;
        let mut jwt_secret = [0; refresh_token::SECRET_SIZE];
        OsRng.fill_bytes(&mut jwt_secret);

        Ok(Self {
            id: Uuid::new_v4(),
            email: &query.email,
            hash,
            full_name: query.full_name.as_str(),
            jwt_secret: jwt_secret.to_vec(),
        })
    }

    pub fn insert(&self, pg: &PgConn, emails: &Emails) -> AppResult<User> {
        pg.transaction(|| {
            let user: User = insert_into(users::table)
                .values(self)
                .get_result(pg)
                .map_err(handle_diesel_error)?;
            let token = VerificationToken::generate(&user)?;
            let _ = emails.send_user_confirmation(&user, token);

            Ok(user)
        })
    }
}

#[non_exhaustive]
#[derive(Debug, Deserialize)]
pub struct RegisterUser {
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
    pub verified: Option<bool>,
    pub full_name: Option<PersonalName>,
}

impl UserChangeset {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

impl TryFrom<UpdateUser> for UserChangeset {
    type Error = AppError;

    fn try_from(u: UpdateUser) -> Result<Self, Self::Error> {
        let UpdateUser {
            password: _,
            new_password,
            email,
            full_name,
        } = u;

        let hash = new_password.map_or(Ok(None), |p| hash_password(&p).map(Some))?;

        let cs = Self {
            hash,
            verified: if email.is_some() { Some(false) } else { None },
            email,
            full_name,
        };

        if cs.is_empty() {
            Err(AppError::BadRequest(Some("No changes specified.".into())))
        } else {
            Ok(cs)
        }
    }
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
            jwt_secret: _,
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

fn handle_diesel_error(e: diesel::result::Error) -> AppError {
    use diesel::result::{DatabaseErrorKind, Error::DatabaseError};

    match e {
        DatabaseError(DatabaseErrorKind::UniqueViolation, ref info) => {
            match info.constraint_name() {
                Some("users_email_key") => AppError::EmailInUse,
                _ => e.into(),
            }
        }
        _ => e.into(),
    }
}

#[cfg(test)]
mod tests {
    use chrono::NaiveDateTime;
    use serde_json::json;

    use crate::db::postgres::pg_test_conn;

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
            jwt_secret: vec![1, 2, 3, 4],
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

        assert!(
            User::find_by_email(&conn, &"nonexistentuser@example.com".parse().unwrap())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn update() {
        let q = UpdateUser {
            email: Some("jamesbond@example.com".parse().unwrap()),
            password: "MI6".to_string(),
            new_password: None,
            full_name: None,
        };

        assert_eq!(UserChangeset::try_from(q).unwrap().verified, Some(false));
    }
}
