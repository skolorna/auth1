use openssl::bn::BigNumContext;
use openssl::ec::{EcKeyRef, PointConversionForm};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::{hash::MessageDigest, pkey::Public, rsa::RsaRef, x509::X509};
use serde::{Deserialize, Serialize};
use serde_with::formats::Unpadded;
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
    ES256,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kty")]
pub enum Key {
    RSA {
        #[serde_as(as = "Base64<base64::UrlSafe, Unpadded>")]
        e: Vec<u8>,
        #[serde_as(as = "Base64<base64::UrlSafe, Unpadded>")]
        n: Vec<u8>,
    },
    EC {
        crv: Curve,
        #[serde_as(as = "Base64<base64::UrlSafe, Unpadded>")]
        x: Vec<u8>,
        #[serde_as(as = "Base64<base64::UrlSafe, Unpadded>")]
        y: Vec<u8>,
    },
}

impl Key {
    pub fn from_rsa(key: &RsaRef<Public>) -> Self {
        Self::RSA {
            e: key.e().to_vec(),
            n: key.n().to_vec(),
        }
    }

    pub fn from_ec_key(key: &EcKeyRef<Public>) -> Result<Self, ErrorStack> {
        match key.group().curve_name() {
            Some(Nid::X9_62_PRIME256V1) => {
                let mut ctx = BigNumContext::new()?;
                // the first byte indicates whether the byte vector is compressed
                let pk_bytes = &key.public_key().to_bytes(
                    key.group(),
                    PointConversionForm::UNCOMPRESSED,
                    &mut ctx,
                )?;
                let (x, y) = pk_bytes[1..].split_at(32);
                Ok(Self::EC {
                    crv: Curve::P256,
                    x: x.to_vec(),
                    y: y.to_vec(),
                })
            }
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Curve {
    #[serde(rename = "P-256")]
    P256,
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

        let ec = self.public_key()?.ec_key()?;
        let key = Key::from_ec_key(&ec)?;

        Ok(Jwk {
            algorithm: Some(Algorithm::ES256),
            key,
            key_use: Some(KeyUse::Signing),
            key_id: None,
            x5,
        })
    }
}
