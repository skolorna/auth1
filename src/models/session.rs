use chrono::{DateTime, Duration, Utc};
use diesel::{
    dsl::{Eq, Gt},
    expression::bound::Bound,
    prelude::*,
    sql_types::{self, Timestamptz},
};
use openssl::{error::ErrorStack, rsa::Rsa};
use serde::Serialize;
use uuid::Uuid;

use super::user::{User, UserId};
use crate::{
    db::postgres::PgConn,
    errors::{AppError, AppResult},
    schema::sessions,
    token::{refresh_token::RefreshToken, TokenResponse},
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

type NotExpired = Gt<sessions::columns::exp, Bound<Timestamptz, DateTime<Utc>>>;
type WithId = Eq<sessions::columns::id, Bound<sql_types::Uuid, Uuid>>;

fn map_rsa_err(err: ErrorStack) -> AppError {
    AppError::InternalError { cause: err.into() }
}

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
    pub fn create(conn: &PgConn, sub: UserId) -> AppResult<TokenResponse> {
        let id = Uuid::new_v4();
        let refresh_token = RefreshToken::generate(id);

        let (public_pem, private_der) = {
            let rsa = Rsa::generate(Self::RSA_BITS).map_err(map_rsa_err)?;
            (
                rsa.public_key_to_pem().map_err(map_rsa_err)?,
                rsa.private_key_to_der().map_err(map_rsa_err)?,
            )
        };

        let now = Utc::now();
        let new_session = NewSession {
            id,
            sub,
            started: now,
            exp: now + Duration::days(90),
            public_key: &public_pem,
            private_key: &refresh_token.encrypt(&private_der).map_err(|e| {
                AppError::InternalError {
                    cause: e.to_string().into(),
                }
            })?,
        };

        let session: Self = diesel::insert_into(sessions::table)
            .values(new_session)
            .get_result(conn)?;

        Ok(TokenResponse {
            refresh_token: Some(refresh_token),
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
    pub fn get_pubkey(conn: &PgConn, id: SessionId) -> QueryResult<Option<PubKeyRes>> {
        use crate::schema::sessions::{columns, table};

        conn.transaction(|| {
            let data = table
                .select((columns::public_key, columns::exp, columns::sub))
                .find(id)
                .first::<PubKeyRes>(conn)
                .optional()?;

            if let Some(data) = data {
                if data.exp > Utc::now() {
                    return Ok(Some(data));
                } else {
                    diesel::delete(table.find(id)).execute(conn)?;
                }
            }

            Ok(None)
        })
    }
}

#[derive(Debug, Queryable, Associations)]
#[belongs_to(User, foreign_key = "sub")]
#[table_name = "sessions"]
pub struct PubKeyRes {
    pub pubkey: Vec<u8>,
    pub exp: DateTime<Utc>,
    pub sub: UserId,
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
