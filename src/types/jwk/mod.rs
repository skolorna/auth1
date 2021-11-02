use openssl::pkey::Public;
use serde::{Deserialize, Serialize};

use self::{b64::Base64UrlBytes, x5::X509Params};

pub mod b64;
pub mod x5;

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonWebKey {
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
#[serde(tag = "kty")]
pub enum Key {
    RSA {
        e: Base64UrlBytes,
        n: Base64UrlBytes,
    },
}

impl From<&openssl::rsa::RsaRef<Public>> for Key {
    fn from(rsa: &openssl::rsa::RsaRef<Public>) -> Self {
        Self::RSA {
            e: rsa.e().into(),
            n: rsa.n().into(),
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    HS256,
    RS256,
    ES256,
}
