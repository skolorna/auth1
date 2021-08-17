use chrono::{DateTime, Duration, Utc};
use diesel::prelude::*;
use jsonwebtoken::{EncodingKey, Header};
use openssl::rsa::Rsa;
use serde::Serialize;
use uuid::Uuid;

use super::user::{User, UserId};
use crate::{
    result::{Error, Result},
    schema::sessions,
    token::{AccessToken, AccessTokenClaims, RefreshToken},
    DbConn,
};

/// FIXME: In the future, it's probably better to use some sort of clock-based uuid generation:
/// otherwise, albeit extremely unlikely, cache poisoning can occur if one session with id `a`
/// is deleted followed by a new session with the same id `a` being created.
pub type SessionId = Uuid;

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

impl Session {
    pub const RSA_BITS: u32 = 2048;

    pub fn create(conn: &DbConn, sub: UserId) -> Result<CreatedSession> {
        let refresh_token = RefreshToken::generate();

        let (public_pem, private_der) = {
            let rsa = Rsa::generate(Self::RSA_BITS).map_err(|_| Error::InternalError)?;
            (
                rsa.public_key_to_pem().map_err(|_| Error::InternalError)?,
                rsa.private_key_to_der().map_err(|_| Error::InternalError)?,
            )
        };

        let now = Utc::now();
        let new_session = NewSession {
            id: Uuid::new_v4(),
            sub,
            started: now,
            exp: now + Duration::days(90),
            public_key: &public_pem,
            private_key: &refresh_token.encrypt(&private_der)?,
        };

        let session: Self = diesel::insert_into(sessions::table)
            .values(new_session)
            .get_result(conn)?;

        Ok(CreatedSession {
            refresh_token,
            access_token: session.sign_access_token(&refresh_token)?,
        })
    }

    /// Get the public part of a key stored in the database.
    /// Returns the raw bytes of the key as well as the subject.
    /// If the key has expired, the row will be deleted and
    /// the function will pretend that it never existed.
    /// Do note, however, that it shouldn't matter to much whether
    /// the key has expired or not as this public key is exclusively
    /// used for *validation* of access tokens that themselves have
    /// much shorter lifetimes.
    pub fn get_pubkey(conn: &DbConn, kid: SessionId) -> Result<(Vec<u8>, UserId)> {
        use crate::schema::sessions::{columns, table};
        let (pubkey, exp, sub): (Vec<u8>, DateTime<Utc>, UserId) = table
            .select((columns::public_key, columns::exp, columns::sub))
            .find(kid)
            .first(conn)
            .map_err(|_| Error::KeyNotFound)?;

        if exp > Utc::now() {
            Ok((pubkey, sub))
        } else {
            diesel::delete(table.find(kid)).execute(conn)?;

            Err(Error::KeyNotFound)
        }
    }

    // TODO: ECC?
    pub fn sign_access_token(&self, refresh_token: &RefreshToken) -> Result<AccessToken> {
        let now = Utc::now();
        // The access token must not outlive the refresh token
        let exp = (now + Duration::hours(1)).min(self.exp);

        if exp < now {
            return Err(Error::InvalidCredentials);
        }

        let der = refresh_token.decrypt(&self.private_key)?;

        let encoding_key = EncodingKey::from_rsa_der(&der);
        let header = Header {
            typ: Some("JWT".into()),
            alg: AccessToken::JWT_ALG,
            cty: None,
            jku: None,
            kid: Some(self.id.to_string()),
            x5u: None,
            x5t: None,
        };
        let claims = AccessTokenClaims {
            sub: self.sub,
            exp: exp.timestamp(),
        };

        let token = jsonwebtoken::encode(&header, &claims, &encoding_key).expect("hm");

        Ok(AccessToken::new(token))
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
