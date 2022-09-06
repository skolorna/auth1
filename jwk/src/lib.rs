use der::asn1::BitStringRef;
use der::oid::ObjectIdentifier;
use der::{AnyRef, Encode, Sequence};
use jsonwebtoken::DecodingKey;
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
use std::io::Write;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("der error")]
    Der,

    #[error("jwt error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Set {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
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

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    RS256,
    ES256,
}

impl From<Algorithm> for jsonwebtoken::Algorithm {
    fn from(alg: Algorithm) -> Self {
        use jsonwebtoken::Algorithm as JwtAlgorithm;

        match alg {
            Algorithm::RS256 => JwtAlgorithm::RS256,
            Algorithm::ES256 => JwtAlgorithm::ES256,
        }
    }
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
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

    pub fn from_ec(key: &EcKeyRef<Public>) -> Result<Self, ErrorStack> {
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

    pub fn to_der(&self) -> Result<Vec<u8>> {
        #[derive(Debug, Sequence, Clone, Copy, PartialEq, Eq)]
        struct AlgorithmIdentifier<'a> {
            pub algorithm: ObjectIdentifier,
            pub parameters: Option<AnyRef<'a>>,
        }

        match self {
            Key::RSA { .. } => todo!(),
            Key::EC { crv, x, y } => {
                let curve_oid = match crv {
                    Curve::P256 => ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7"),
                };

                #[derive(Debug, Sequence)]
                struct Der<'a> {
                    algorithm_identifier: [ObjectIdentifier; 2],
                    public_key: BitStringRef<'a>,
                }

                let mut public_key = [0; 65];

                public_key[0] = 0x04; // uncompressed
                public_key[1..33].copy_from_slice(x);
                public_key[33..65].copy_from_slice(y);

                let key = Der {
                    algorithm_identifier: [
                        ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
                        curve_oid,
                    ],
                    public_key: BitStringRef::from_bytes(&public_key).unwrap(),
                };

                let mut out = Vec::new();

                key.encode_to_vec(&mut out).map_err(|_| Error::Der)?;

                Ok(out)
            }
        }
    }

    pub fn to_pem(&self) -> Result<Vec<u8>> {
        let der_b64 = ::base64::encode(self.to_der()?);
        let mut pem = Vec::new();

        writeln!(&mut pem, "-----BEGIN PUBLIC KEY-----").unwrap();

        const MAX_LINE_LEN: usize = 64;
        for line in der_b64.as_bytes().chunks(MAX_LINE_LEN) {
            pem.extend_from_slice(line);
            writeln!(&mut pem).unwrap();
        }

        writeln!(&mut pem, "-----END PUBLIC KEY-----").unwrap();

        Ok(pem)
    }

    pub fn to_jwt_key(&self) -> Result<DecodingKey> {
        let pem = self.to_pem()?;

        match self {
            Key::RSA { .. } => Ok(DecodingKey::from_rsa_pem(&pem)?),
            Key::EC { .. } => Ok(DecodingKey::from_ec_pem(&pem)?),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    #[serde(rename = "P-256")]
    P256,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum KeyUse {
    #[serde(rename = "sig")]
    Signing,
    #[serde(rename = "enc")]
    Encryption,
}

#[serde_as]
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Clone)]
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
        let key = Key::from_ec(&ec)?;

        Ok(Jwk {
            algorithm: Some(Algorithm::ES256),
            key,
            key_use: Some(KeyUse::Signing),
            key_id: None,
            x5,
        })
    }
}
