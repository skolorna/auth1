use openssl::{bn::BigNumRef, hash::DigestBytes};
use serde::{de, Deserialize, Deserializer, Serialize};

#[derive(Debug, PartialEq, Eq)]
pub struct Base64Bytes(Vec<u8>);

impl Serialize for Base64Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        base64::encode_config(&self.0, base64::STANDARD).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Base64Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let vec = base64::decode_config(s, base64::STANDARD).map_err(de::Error::custom)?;

        Ok(Self(vec))
    }
}

impl From<Vec<u8>> for Base64Bytes {
    fn from(vec: Vec<u8>) -> Self {
        Self(vec)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Base64UrlBytes(Vec<u8>);

impl Serialize for Base64UrlBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        base64::encode_config(&self.0, base64::URL_SAFE_NO_PAD).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Base64UrlBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let vec = base64::decode_config(s, base64::URL_SAFE_NO_PAD).map_err(de::Error::custom)?;

        Ok(Self(vec))
    }
}

impl From<Vec<u8>> for Base64UrlBytes {
    fn from(vec: Vec<u8>) -> Self {
        Self(vec)
    }
}

impl From<DigestBytes> for Base64UrlBytes {
    fn from(digest: DigestBytes) -> Self {
        Self(digest.to_vec())
    }
}

impl From<&BigNumRef> for Base64UrlBytes {
    fn from(bignum: &BigNumRef) -> Self {
        bignum.to_vec().into()
    }
}
