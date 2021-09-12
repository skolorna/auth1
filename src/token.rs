//! Everything tokens: access tokens, refresh tokens and even verification tokens!

use std::{fmt::Display, str::FromStr};

use crate::diesel::QueryDsl;
use base64::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use diesel::prelude::*;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand_core::{OsRng, RngCore};
use serde::{de, Deserialize, Serialize};
use thiserror::Error;

use crate::{
    models::{session::SessionId, user::UserId, Session},
    result::{Error, Result},
    DbConn,
};

pub type RefreshTokenSecret = [u8; RefreshToken::SECRET_SIZE];

#[derive(Debug, Clone, Copy)]
pub struct RefreshToken {
    pub session: SessionId,
    pub secret: RefreshTokenSecret,
}

impl RefreshToken {
    pub const SECRET_SIZE: usize = 44;
    const MAX_B64_SIZE: usize = 4 * (Self::SECRET_SIZE + 2) / 3;

    pub fn new(session: SessionId, secret: RefreshTokenSecret) -> Self {
        Self { session, secret }
    }

    pub fn generate_secret(session: SessionId) -> Self {
        let mut data = [0_u8; Self::SECRET_SIZE];
        OsRng.fill_bytes(&mut data);
        Self::new(session, data)
    }

    fn aes_cipher(&self) -> aes_gcm::Aes256Gcm {
        use aes_gcm::aead::NewAead;
        use aes_gcm::{Aes256Gcm, Key};

        let key = Key::from_slice(&self.secret[..32]);
        Aes256Gcm::new(key)
    }

    // FIXME
    fn aes_nonce(&self) -> &[u8] {
        &self.secret[32..]
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

    pub fn sign_access_token_simple(&self, conn: &DbConn) -> Result<AccessToken> {
        use crate::schema::sessions::{columns, table};

        let (exp, private_key, sub): (_, Vec<u8>, UserId) = table
            .select((columns::exp, columns::private_key, columns::sub))
            .find(self.session)
            .first(conn)?;

        self.sign_access_token(private_key, sub, exp)
    }

    pub fn sign_access_token(
        &self,
        private_key: Vec<u8>,
        sub: UserId,
        max_exp: DateTime<Utc>,
    ) -> Result<AccessToken> {
        let now = Utc::now();
        // The access token must not outlive the refresh token
        let exp = (now + Duration::hours(1)).min(max_exp);

        if exp < now {
            return Err(Error::InvalidCredentials);
        }

        let der = self.decrypt(&private_key)?;

        let encoding_key = EncodingKey::from_rsa_der(&der);
        let header = Header {
            typ: Some("JWT".into()),
            alg: AccessToken::JWT_ALG,
            cty: None,
            jku: None,
            kid: Some(self.session.to_string()),
            x5u: None,
            x5t: None,
        };
        let claims = AccessTokenClaims {
            sub,
            exp: exp.timestamp(),
        };

        let token = jsonwebtoken::encode(&header, &claims, &encoding_key).expect("hm");

        Ok(AccessToken::new(token))
    }
}

#[derive(Debug, Error)]
pub enum ParseRefreshTokenError {
    #[error("invalid uuid")]
    InvalidUuid(#[from] uuid::Error),

    #[error("invalid base64 encoding")]
    InvalidBase64(#[from] base64::DecodeError),

    #[error("the token is too big")]
    TooBigToken,
}

impl FromStr for RefreshToken {
    type Err = ParseRefreshTokenError;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        let mut parts = s.splitn(2, '.');

        let session = SessionId::from_str(parts.next().unwrap())?;

        let data_b64 = parts.next().unwrap();
        if data_b64.len() > Self::MAX_B64_SIZE {
            // Something fishy is going on, and I dont really want my
            // base64 decoder to panic today.
            return Err(ParseRefreshTokenError::TooBigToken);
        }
        let mut data = [0_u8; Self::SECRET_SIZE];
        base64::decode_config_slice(data_b64, URL_SAFE_NO_PAD, &mut data)?;

        Ok(Self::new(session, data))
    }
}

impl Display for RefreshToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return write!(
            f,
            "{}.{}",
            self.session,
            base64::encode_config(self.secret, URL_SAFE_NO_PAD)
        );
    }
}

impl Serialize for RefreshToken {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for RefreshToken {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(de::Error::custom)
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
        let (key, key_owner, _exp) = Session::get_pubkey(conn, kid)?;
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::models::session::SessionId;

    use super::RefreshToken;

    #[test]
    fn parse_refresh_token() {
        let wrong = vec![
            "abcdef.a.b",
            "abc",
            ".",
            "",
            "2f93d264-9f29-454d-b616-9ba57f95f9cf.🤡", // ah yes, base64
            // The following key is probably too big.
            "2f93d264-9f29-454d-b616-9ba57f95f9cf.________________________________________________________________",
        ];

        for s in wrong {
            assert!(
                RefreshToken::from_str(s).is_err(),
                "uh-oh. \"{}\" should not be considered valid.",
                s
            );
        }

        assert_eq!(
            RefreshToken::from_str("2f93d264-9f29-454d-b616-9ba57f95f9cf.ASNFZ4mrze8")
                .unwrap()
                .secret[..8],
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );

        assert_eq!(
            RefreshToken::from_str("00000000-0000-0000-0000-000000000000.")
                .unwrap()
                .session,
            SessionId::nil()
        );

        assert!(RefreshToken::from_str("2f93d264-9f29-454d-b616-9ba57f95f9cf.").is_ok());
    }

    #[test]
    fn refresh_token_crypto() {
        let token = RefreshToken::new(SessionId::nil(), [0; 44]);
        let ciphertext = token.encrypt(b"bruh").unwrap();
        assert_eq!(token.decrypt(&ciphertext).unwrap(), b"bruh");
    }
}
