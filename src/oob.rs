//! Out-of-band user authentication.

use std::fmt::{Display, Write};
use std::str::FromStr;

use data_encoding::Encoding;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use serde_with::formats::Padded;
use serde_with::{
    base64::{Base64, Standard},
    serde_as,
};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use sqlx::PgExecutor;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::http::{Error, Result};
use crate::jwt::{InvalidTokenReason, JwtResultExt};

pub const TTL: Duration = Duration::minutes(5);

pub const SECRET_LEN: usize = 64;
pub const NONCE_LEN: usize = 64;

pub type Nonce = [u8; NONCE_LEN];

#[derive(Debug, Clone, Copy, SerializeDisplay, DeserializeFromStr, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Otp([u8; Self::LEN]);

impl Otp {
    pub const LEN: usize = 10;
    const ENCODING: Encoding = data_encoding::BASE32_DNSCURVE;

    fn from_key(key: &[u8], nonce: &Nonce) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(key);
        hasher.update(nonce);
        let hash = hasher.finalize();

        let mut otp = [0; Self::LEN];
        otp[..].copy_from_slice(&hash.as_bytes()[..Self::LEN]);
        Self(otp)
    }

    pub const fn new(data: [u8; Self::LEN]) -> Self {
        Self(data)
    }
}

impl Display for Otp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const LEN: usize = 16;

        debug_assert_eq!(
            Self::ENCODING.encode_len(self.0.len()),
            LEN,
            "output buffer has wrong length"
        );

        let mut output = [0; LEN];
        Self::ENCODING.encode_mut(&self.0, &mut output);

        let mut chunks = output
            .chunks(4)
            .map(|b| core::str::from_utf8(b).unwrap())
            .peekable();

        while let Some(s) = chunks.next() {
            f.write_str(s)?;
            if chunks.peek().is_some() {
                f.write_char('-')?;
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct ParseOtpError;

impl Display for ParseOtpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid otp format")
    }
}

impl From<data_encoding::DecodeError> for ParseOtpError {
    fn from(_: data_encoding::DecodeError) -> Self {
        Self
    }
}

impl FromStr for Otp {
    type Err = ParseOtpError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.replace('-', "");
        let s = s.as_bytes();
        let mut buf = [0; Self::LEN];
        if Self::ENCODING.decode_len(s.len())? == buf.len() {
            Self::ENCODING
                .decode_mut(s, &mut buf)
                .map_err(|_| ParseOtpError)?;
            Ok(Self(buf))
        } else {
            Err(ParseOtpError)
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Band {
    Email,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub exp: i64,
    pub band: Band,
    #[serde_as(as = "Base64<Standard, Padded>")]
    pub nonce: Nonce,
}

pub fn gen_secret() -> [u8; SECRET_LEN] {
    let mut buf = [0; SECRET_LEN];
    thread_rng().fill(&mut buf);
    buf
}

/// "But what's the difference between a secret and a key?" I hear you ask.
///
/// Good question.
///
/// Here, the secret constitutes *part of* the key used for encoding and decoding
/// the token.
fn gen_key(attr: &[u8], secret: &[u8]) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(attr);
    hasher.update(secret);
    hasher.finalize()
}

fn gen_nonce() -> Nonce {
    let mut nonce = [0; NONCE_LEN];
    thread_rng().fill(&mut nonce);
    nonce
}

pub fn sign(sub: Uuid, band: Band, attr: impl AsRef<[u8]>, secret: &[u8]) -> (String, Otp) {
    let nonce = gen_nonce();
    let key = gen_key(attr.as_ref(), secret);
    let key = key.as_bytes();

    let exp = OffsetDateTime::now_utc() + TTL;

    let claims = Claims {
        sub,
        exp: exp.unix_timestamp(),
        band,
        nonce,
    };

    let token =
        jsonwebtoken::encode(&Header::default(), &claims, &EncodingKey::from_secret(key)).unwrap();
    let otp = Otp::from_key(key, &nonce);

    (token, otp)
}

pub async fn verify(token: &str, otp: Otp, db: impl PgExecutor<'_>) -> Result<Claims> {
    let claims = crate::jwt::decode_insecure::<Claims>(token)
        .map_token_err(Error::InvalidOobToken)?
        .claims;

    let (attr, secret) = match claims.band {
        Band::Email => {
            sqlx::query_as::<_, (String, Option<Vec<u8>>)>(
                "SELECT email, oob_secret FROM users WHERE id = $1",
            )
            .bind(claims.sub)
            .fetch_one(db)
            .await?
        }
    };

    let secret = secret.ok_or(Error::InvalidOobToken(InvalidTokenReason::Bad))?;
    let key = gen_key(attr.as_ref(), &secret);
    let key = key.as_bytes();

    jsonwebtoken::decode::<Claims>(
        token,
        &DecodingKey::from_secret(key),
        &Validation::default(),
    )
    .map_token_err(Error::InvalidOobToken)?;

    if otp != Otp::from_key(key, &claims.nonce) {
        return Err(Error::InvalidOobToken(InvalidTokenReason::Bad));
    }

    Ok(claims)
}

pub async fn update_secret(user: Uuid, db: impl PgExecutor<'_>) -> Result<[u8; SECRET_LEN]> {
    let secret = gen_secret();

    sqlx::query!(
        "UPDATE users SET oob_secret = $1 WHERE id = $2",
        &secret,
        user
    )
    .execute(db)
    .await?;

    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::{gen_nonce, Otp};

    #[test]
    fn gen_otp() {
        Otp::from_key(&[], &gen_nonce());
    }

    #[test]
    fn otp_from_str() {
        assert!("".parse::<Otp>().is_err());
        assert!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .parse::<Otp>()
                .is_err()
        );
    }
}
