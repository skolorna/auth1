//! Everything tokens: access tokens, refresh tokens and even verification tokens!

use std::{fmt::Display, str::FromStr};

use crate::{db::postgres::PgConn, diesel::QueryDsl};
use base64::URL_SAFE_NO_PAD;
use diesel::prelude::*;
use jsonwebtoken::EncodingKey;
use rand_core::{OsRng, RngCore};
use serde::{de, Deserialize, Serialize};
use thiserror::Error;

use crate::{
    errors::{AppError, AppResult},
    models::session::SessionId,
};

use super::AccessToken;

type Secret = [u8; RefreshToken::SECRET_SIZE];

#[derive(Debug, Clone, Copy)]
pub struct RefreshToken {
    pub session: SessionId,
    pub secret: Secret,
}

impl RefreshToken {
    const SECRET_SIZE: usize = 44;
    const MAX_B64_SIZE: usize = 4 * (Self::SECRET_SIZE + 2) / 3;

    pub const fn new(session: SessionId, secret: Secret) -> Self {
        Self { session, secret }
    }

    pub fn generate(session: SessionId) -> Self {
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

    fn aes_nonce(&self) -> &[u8] {
        &self.secret[32..]
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        use aes_gcm::aead::Aead;
        use aes_gcm::Nonce;

        let cipher = self.aes_cipher();
        let nonce = Nonce::from_slice(self.aes_nonce());
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())?;

        Ok(ciphertext)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        use aes_gcm::aead::Aead;
        use aes_gcm::Nonce;

        let cipher = self.aes_cipher();
        let nonce = Nonce::from_slice(self.aes_nonce());
        let plaintext = cipher.decrypt(nonce, ciphertext)?;

        Ok(plaintext)
    }

    /// Decrypt an encoding key.
    ///
    /// # Errors
    /// Fails if the decryption fails, which most likely is due to incorrect
    /// credentials.
    pub fn encoding_key(
        &self,
        ciphertext_private_key: &[u8],
    ) -> Result<EncodingKey, aes_gcm::Error> {
        let der = self.decrypt(ciphertext_private_key)?;

        Ok(EncodingKey::from_rsa_der(&der))
    }

    /// Sign an access token by querying the encrypted private key, decrypting it
    /// with the stored secret and finally signing the access token for the user
    /// associated with the session.
    pub fn access_token_ez(&self, conn: &PgConn) -> AppResult<AccessToken> {
        use crate::schema::sessions::{columns, table};

        let (exp, private_key, sub): (_, Vec<u8>, _) = table
            .select((columns::exp, columns::private_key, columns::sub))
            .find(self.session)
            .first(conn)?;

        AccessToken::sign(
            self.encoding_key(&private_key)
                .map_err(|_| AppError::InvalidRefreshToken)?,
            sub,
            self.session,
            exp,
        )
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

    fn from_str(s: &str) -> Result<Self, Self::Err> {
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
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for RefreshToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
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
