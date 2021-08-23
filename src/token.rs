//! Everything tokens: access tokens, refresh tokens and even verification tokens!

use std::{fmt::Display, str::FromStr};

use crate::diesel::QueryDsl;
use base64::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use diesel::prelude::*;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    models::{session::SessionId, user::UserId, Session},
    result::{Error, Result},
    DbConn,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub sub: UserId,
    pub exp: i64,
}

const REFRESH_TOKEN_SIZE: usize = 44;

#[derive(Debug, Clone, Copy)]
pub struct RefreshToken([u8; REFRESH_TOKEN_SIZE]);

impl RefreshToken {
    #[must_use]
    pub fn new(d: [u8; REFRESH_TOKEN_SIZE]) -> Self {
        Self(d)
    }

    #[must_use]
    pub fn generate() -> Self {
        let mut token = [0_u8; REFRESH_TOKEN_SIZE];
        OsRng.fill_bytes(&mut token);
        Self::new(token)
    }

    #[must_use]
    pub fn to_base64(&self) -> String {
        base64::encode_config(self.0, URL_SAFE_NO_PAD)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; REFRESH_TOKEN_SIZE] {
        &self.0
    }

    #[must_use]
    pub fn aes_cipher(&self) -> aes_gcm::Aes256Gcm {
        use aes_gcm::aead::NewAead;
        use aes_gcm::{Aes256Gcm, Key};

        let key = Key::from_slice(&self.as_bytes()[..32]);
        Aes256Gcm::new(key)
    }

    // FIXME
    #[must_use]
    pub fn aes_nonce(&self) -> &[u8] {
        return &self.as_bytes()[32..];
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::aead::Aead;
        use aes_gcm::Nonce;

        let cipher = self.aes_cipher();
        let nonce = Nonce::from_slice(self.aes_nonce());
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())?;

        Ok(ciphertext)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::aead::Aead;
        use aes_gcm::Nonce;

        let cipher = self.aes_cipher();
        let nonce = Nonce::from_slice(self.aes_nonce());
        let plaintext = cipher.decrypt(nonce, ciphertext)?;

        Ok(plaintext)
    }
}

impl FromStr for RefreshToken {
    type Err = base64::DecodeError;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        let mut d = [0_u8; REFRESH_TOKEN_SIZE];
        base64::decode_config_slice(s, URL_SAFE_NO_PAD, &mut d)?;
        Ok(Self::new(d))
    }
}

impl Display for RefreshToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return write!(f, "{}", self.to_base64());
    }
}

impl Serialize for RefreshToken {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_base64())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessToken(String);

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Subject of the token (the user id).
    pub sub: UserId,

    /// Expiration timestamp of the token (UNIX timestamp).
    pub exp: i64,
}

impl AccessToken {
    pub const JWT_ALG: Algorithm = Algorithm::RS256;

    pub fn new<S: ToString>(s: S) -> Self {
        Self(s.to_string())
    }

    pub fn verify_and_decode(&self, conn: &DbConn) -> Result<AccessTokenClaims> {
        let header = jsonwebtoken::decode_header(&self.0)?;
        let kid: SessionId = header
            .kid
            .ok_or(Error::MalformedToken)?
            .parse()
            .map_err(|_| Error::MalformedToken)?;
        let (key, key_owner) = Session::get_pubkey(conn, kid)?;
        let key = DecodingKey::from_rsa_pem(&key)?;
        let validation = Validation::new(Self::JWT_ALG);
        let decoded = jsonwebtoken::decode::<AccessTokenClaims>(&self.0, &key, &validation)?;

        if key_owner != decoded.claims.sub {
            // Something fishy is going on.
            return Err(Error::MalformedToken);
        }

        Ok(decoded.claims)
    }
}

/// Token used for verifying (only email addresses for now).
#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationToken(String);

impl VerificationToken {
    const JWT_ALG: Algorithm = Algorithm::HS256;

    pub fn new(s: impl ToString) -> Self {
        Self(s.to_string())
    }

    pub fn generate(conn: &DbConn, email: impl ToString) -> Result<Self> {
        use crate::schema::users::{columns, table};

        let email = email.to_string();
        let hash: String = table
            .select(columns::hash)
            .filter(columns::email.eq(&email))
            .first(conn)?;
        // FIXME: Don't use the password hash as the secret. Please.
        let key = EncodingKey::from_secret(hash.as_bytes());
        let exp = Utc::now() + Duration::hours(24);
        let header = Header::new(Self::JWT_ALG);
        let claims = VerificationTokenClaims {
            email,
            exp: exp.timestamp(),
        };
        let token = jsonwebtoken::encode(&header, &claims, &key)?;

        Ok(Self::new(token))
    }

    pub fn verify(&self, conn: &DbConn) -> Result<()> {
        use crate::schema::users::{columns, table};

        let data = jsonwebtoken::dangerous_insecure_decode::<VerificationTokenClaims>(&self.0)?;
        let (hash, already_verified): (String, bool) = table
            .select((columns::hash, columns::verified))
            .filter(columns::email.eq(data.claims.email))
            .first(conn)?;

        if already_verified {
            return Err(Error::InvalidCredentials);
        }

        let key = DecodingKey::from_secret(hash.as_bytes());
        let data = jsonwebtoken::decode::<VerificationTokenClaims>(
            &self.0,
            &key,
            &Validation::new(Self::JWT_ALG),
        )?;

        diesel::update(table.filter(columns::email.eq(data.claims.email)))
            .set(columns::verified.eq(true))
            .execute(conn)?;

        Ok(())
    }
}

impl Display for VerificationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return write!(f, "{}", self.0);
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationTokenClaims {
    pub exp: i64,
    pub email: String,
}
