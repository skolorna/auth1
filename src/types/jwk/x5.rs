use openssl::{hash::MessageDigest, x509::X509};
use serde::{Deserialize, Serialize};

use super::b64::{Base64Bytes, Base64UrlBytes};

pub trait JwkX5 {
    type Err;

    fn sha1_thumbprint(&self) -> Result<Vec<u8>, Self::Err>;

    fn sha256_thumbprint(&self) -> Result<Vec<u8>, Self::Err>;
}

impl JwkX5 for X509 {
    type Err = openssl::error::ErrorStack;

    fn sha1_thumbprint(&self) -> Result<Vec<u8>, Self::Err> {
        Ok(self.digest(MessageDigest::sha1())?.to_vec())
    }

    fn sha256_thumbprint(&self) -> Result<Vec<u8>, Self::Err> {
        Ok(self.digest(MessageDigest::sha256())?.to_vec())
    }
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
