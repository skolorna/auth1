use openssl::hash::DigestBytes;
use serde::{de, Deserialize, Deserializer, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonWebKey {
    #[serde(flatten)]
    pub key: Key,

    #[serde(default, rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<KeyUse>,

    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    #[serde(flatten, skip_serializing_if = "X509Params::is_empty")]
    pub x5: X509Params,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kty")]
pub enum Key {
    RSA { e: Base64Bytes, n: Base64Bytes },
}

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct X509Params {
    #[serde(default, rename = "x5u", skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    #[serde(default, rename = "x5c", skip_serializing_if = "Option::is_none")]
    pub cert_chain: Option<Vec<Base64Bytes>>,

    #[serde(default, rename = "x5t", skip_serializing_if = "Option::is_none")]
    /// SHA-1 thumbprint (digest) of the certificate.
    pub thumbprint: Option<Base64UrlBytes>,

    #[serde(default, rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub thumbprint_sha256: Option<Base64UrlBytes>,
}

impl X509Params {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum KeyUse {
    #[serde(rename = "sig")]
    Signing,

    #[serde(rename = "enc")]
    Encryption,
}

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
