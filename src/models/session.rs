use chrono::{DateTime, Duration, Utc};
use diesel::{
    dsl::{Eq, Gt},
    expression::bound::Bound,
    prelude::*,
    sql_types::{self, Timestamptz},
};
use openssl::rsa::Rsa;
use serde::Serialize;
use uuid::Uuid;

use super::user::{User, UserId};
use crate::{
    result::{Error, Result},
    schema::sessions,
    token::{refresh_token::RefreshToken, AccessToken},
    DbConn,
};

/// FIXME: In the future, it's probably better to use some sort of clock-based uuid generation:
/// otherwise, albeit extremely unlikely, cache poisoning can occur if one session with id `a`
/// is deleted followed by a new session with the same id `a` being created.
pub type SessionId = Uuid;

/// A session contains asymmetric keys used for issuing shorter-lived access tokens.
/// The private key is encrypted with the refresh token, while the public key is stored
/// in plaintext and accessible by anyone.
#[derive(Debug, Queryable, Identifiable, Associations, Serialize)]
#[belongs_to(User, foreign_key = "sub")]
pub struct Session {
    pub id: SessionId,
    pub sub: UserId,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub started: DateTime<Utc>,
    pub exp: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct CreatedSession {
    pub refresh_token: RefreshToken,
    pub access_token: AccessToken,
}

type NotExpired = Gt<sessions::columns::exp, Bound<Timestamptz, DateTime<Utc>>>;
type WithId = Eq<sessions::columns::id, Bound<sql_types::Uuid, Uuid>>;

impl Session {
    pub const RSA_BITS: u32 = 2048;

    pub fn not_expired() -> NotExpired {
        sessions::columns::exp.gt(Utc::now())
    }

    pub fn with_id(id: SessionId) -> WithId {
        sessions::columns::id.eq(id)
    }

    /// Create a new session for a specific user and insert the session into the
    /// database. A refresh token is generated and returned.
    pub fn create(conn: &DbConn, sub: UserId) -> Result<CreatedSession> {
        let id = Uuid::new_v4();
        let refresh_token = RefreshToken::generate_secret(id);

        let (public_pem, private_der) = {
            let rsa = Rsa::generate(Self::RSA_BITS).map_err(|_| Error::InternalError)?;
            (
                rsa.public_key_to_pem().map_err(|_| Error::InternalError)?,
                rsa.private_key_to_der().map_err(|_| Error::InternalError)?,
            )
        };

        let now = Utc::now();
        let new_session = NewSession {
            id,
            sub,
            started: now,
            exp: now + Duration::days(90),
            public_key: &public_pem,
            private_key: &refresh_token.encrypt(&private_der)?,
        };

        let session: Self = diesel::insert_into(sessions::table)
            .values(new_session)
            .get_result(conn)
            .map_err(|e| match e {
                diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::ForeignKeyViolation,
                    _,
                ) => Error::UserNotFound,
                _ => e.into(),
            })?;

        Ok(CreatedSession {
            refresh_token,
            access_token: refresh_token.sign_access_token(
                session.private_key,
                session.sub,
                session.exp,
            )?,
        })
    }

    /// Get the public part of a key stored in the database.
    /// Returns the raw bytes of the key as well as the subject.
    /// If the key has expired, the row will be deleted and
    /// the function will pretend that it never existed.
    /// Do note, however, that it shouldn't matter to much whether
    /// the key has expired or not as this public key is exclusively
    /// used for *validation* of access tokens that in turn have
    /// much shorter lifetimes.
    pub fn get_pubkey(conn: &DbConn, id: SessionId) -> Result<(Vec<u8>, UserId, DateTime<Utc>)> {
        use crate::schema::sessions::{columns, table};
        let (pubkey, exp, sub): (Vec<u8>, DateTime<Utc>, UserId) = table
            .select((columns::public_key, columns::exp, columns::sub))
            .find(id)
            .first(conn)
            .map_err(|_| Error::KeyNotFound)?;

        if exp > Utc::now() {
            Ok((pubkey, sub, exp))
        } else {
            diesel::delete(table.find(id)).execute(conn)?;

            Err(Error::KeyNotFound)
        }
    }
}

#[derive(Debug, Queryable, Identifiable, Associations, Serialize)]
#[belongs_to(User, foreign_key = "sub")]
#[table_name = "sessions"]
pub struct SessionInfo {
    pub id: SessionId,
    pub sub: UserId,
    pub iat: DateTime<Utc>,
    pub exp: DateTime<Utc>,
}

#[derive(Debug, Insertable)]
#[table_name = "sessions"]
struct NewSession<'a> {
    id: SessionId,
    sub: UserId,
    public_key: &'a [u8],
    private_key: &'a [u8],
    started: DateTime<Utc>,
    exp: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::{get_test_conn, result::Error};

    use super::Session;

    #[test]
    fn issue_access_token() {
        let conn = get_test_conn();

        match Session::create(&conn, Uuid::nil()) {
            Err(Error::UserNotFound) => {} // Of course there isn't a nil user
            Err(other_error) => panic!("wrong error type ({})", other_error),
            Ok(_) => panic!("this shouldn't work"),
        }
    }
}
