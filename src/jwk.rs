use openssl::{hash::MessageDigest, nid::Nid, pkey::Public, rsa::RsaRef, x509::X509};
use serde::{Deserialize, Serialize};
use serde_with::formats::{Padded, Unpadded};
use serde_with::{
    base64::{self, Base64},
    serde_as,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Jwk {
    #[serde(default, rename = "alg", skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<Algorithm>,

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
pub enum Algorithm {
    RS256,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kty")]
pub enum Key {
    RSA {
        #[serde_as(as = "Base64")]
        e: Vec<u8>,
        #[serde_as(as = "Base64")]
        n: Vec<u8>,
    },
}

impl Key {
    pub fn from_rsa(key: &RsaRef<Public>) -> Self {
        Self::RSA {
            e: key.e().to_vec(),
            n: key.n().to_vec(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum KeyUse {
    #[serde(rename = "sig")]
    Signing,
    #[serde(rename = "enc")]
    Encryption,
}

#[serde_as]
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct X509Params {
    #[serde(default, rename = "x5c", skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<Vec<Base64>>")]
    pub cert_chain: Option<Vec<Vec<u8>>>,

    /// SHA-1 thumbprint (digest) of the certificate.
    #[serde(default, rename = "x5t", skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<Base64<base64::UrlSafe, Unpadded>>")]
    pub thumbprint: Option<Vec<u8>>,

    #[serde(default, rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<Base64<base64::UrlSafe, Unpadded>>")]
    pub thumbprint_sha256: Option<Vec<u8>>,
}

impl X509Params {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

pub trait X509Ext {
    type Error;

    fn to_jwk(&self) -> Result<Jwk, Self::Error>;
}

impl X509Ext for X509 {
    type Error = openssl::error::ErrorStack;

    fn to_jwk(&self) -> Result<Jwk, Self::Error> {
        let sha1 = self.digest(MessageDigest::sha1())?.to_vec();
        let sha256 = self.digest(MessageDigest::sha256())?.to_vec();

        let x5 = X509Params {
            cert_chain: None,
            thumbprint: Some(sha1),
            thumbprint_sha256: Some(sha256),
        };

        let rsa = self.public_key()?.rsa()?;
        let key = Key::from_rsa(&rsa);

        Ok(Jwk {
            algorithm: Some(Algorithm::RS256),
            key,
            key_use: Some(KeyUse::Signing),
            key_id: None,
            x5,
        })
    }
}
