//! Everything tokens: access tokens, refresh tokens and even verification tokens!

use std::{fmt::Display, str::FromStr};

use crate::{db::postgres::PgConn, diesel::QueryDsl};
use base64::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use diesel::prelude::*;
use jsonwebtoken::{EncodingKey, Header};
use rand_core::{OsRng, RngCore};
use serde::{de, Deserialize, Serialize};
use thiserror::Error;

use crate::{
    models::{session::SessionId, user::UserId},
    result::{Error, Result},
};

use super::{AccessToken, AccessTokenClaims};

type Secret = [u8; RefreshToken::SECRET_SIZE];

#[derive(Debug, Clone, Copy)]
pub struct RefreshToken {
    pub session: SessionId,
    pub secret: Secret,
}

impl RefreshToken {
    pub const SECRET_SIZE: usize = 44;
    const MAX_B64_SIZE: usize = 4 * (Self::SECRET_SIZE + 2) / 3;

    pub fn new(session: SessionId, secret: Secret) -> Self {
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

    pub fn sign_access_token_simple(&self, conn: &PgConn) -> Result<AccessToken> {
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
