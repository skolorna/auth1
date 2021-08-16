use std::{fmt::Display, str::FromStr};

use base64::URL_SAFE_NO_PAD;
use diesel::{QueryDsl, RunQueryDsl};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    models::{key::KeyId, user::UserId},
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
    pub fn new(d: [u8; REFRESH_TOKEN_SIZE]) -> Self {
        Self(d)
    }

    pub fn generate() -> Self {
        let mut token = [0u8; REFRESH_TOKEN_SIZE];
        OsRng.fill_bytes(&mut token);
        RefreshToken::new(token)
    }

    pub fn to_base64(&self) -> String {
        base64::encode_config(self.0, URL_SAFE_NO_PAD)
    }

    pub fn as_bytes(&self) -> &[u8; REFRESH_TOKEN_SIZE] {
        &self.0
    }

    pub fn aes_cipher(&self) -> aes_gcm::Aes256Gcm {
        use aes_gcm::aead::NewAead;
        use aes_gcm::{Aes256Gcm, Key};

        let key = Key::from_slice(&self.as_bytes()[..32]);
        Aes256Gcm::new(key)
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::aead::Aead;
        use aes_gcm::Nonce;

        let cipher = self.aes_cipher();
        let nonce = Nonce::from_slice(&self.as_bytes()[32..]); // FIXME
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())?;

        Ok(ciphertext)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::aead::Aead;
        use aes_gcm::Nonce;

        let cipher = self.aes_cipher();
        let nonce = Nonce::from_slice(&self.as_bytes()[32..]);
        let plaintext = cipher.decrypt(nonce, ciphertext)?;

        Ok(plaintext)
    }
}

impl FromStr for RefreshToken {
    type Err = base64::DecodeError;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        let mut d = [0u8; REFRESH_TOKEN_SIZE];
        base64::decode_config_slice(s, URL_SAFE_NO_PAD, &mut d)?;
        Ok(Self::new(d))
    }
}

impl Display for RefreshToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base64())
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

pub const JWT_ALG: Algorithm = Algorithm::RS256;

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
    pub fn new<S: ToString>(s: S) -> Self {
        Self(s.to_string())
    }

    pub fn verify_and_decode(&self, conn: &DbConn) -> Result<AccessTokenClaims> {
        use crate::schema::keys::{columns, table};
        let header = jsonwebtoken::decode_header(&self.0)?;
        let kid: KeyId = header
            .kid
            .ok_or(Error::MalformedToken)?
            .parse()
            .map_err(|_| Error::MalformedToken)?;
        // FIXME: Check for expiration
        let (pubkey, key_owner): (Vec<u8>, UserId) = table
            .select((columns::public_key, columns::sub))
            .find(kid)
            .first(conn)?;

        let key = DecodingKey::from_rsa_pem(&pubkey).expect("bruh momento");
        let validation = Validation::new(JWT_ALG);
        let decoded =
            jsonwebtoken::decode::<AccessTokenClaims>(&self.0, &key, &validation).expect("bruh");

        if key_owner != decoded.claims.sub {
            // Something fishy is going on.
            return Err(Error::MalformedToken);
        }

        Ok(decoded.claims)
    }
}
