use std::{env, fs::File, io::Read, iter};

use openssl::{
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::X509,
};
use tracing::warn;

use crate::{util::FromEnvironment, x509::self_sign_ca};
use std::fmt::Debug;

use super::chain::X509Chain;

#[derive(Clone)]
pub struct CertificateAuthority {
    pub cert: X509,
    pub issuer_chain: X509Chain,
    pub pkey: PKey<Private>,
}

impl CertificateAuthority {
    /// Get the chain of certificates.
    pub fn get_chain(&self) -> impl Iterator<Item = &X509> {
        iter::once(&self.cert).chain(self.issuer_chain.iter())
    }

    pub fn from_files(cert_file: &str, key_file: &str) -> std::io::Result<Self> {
        let cert = {
            let mut file = File::open(cert_file)?;
            let mut pem = Vec::new();
            file.read_to_end(&mut pem)?;
            X509::from_pem(&pem)?
        };

        let pkey = {
            let mut file = File::open(key_file)?;
            let mut pem = Vec::new();
            file.read_to_end(&mut pem)?;
            PKey::private_key_from_pem(&pem)?
        };

        Ok(Self {
            cert,
            pkey,
            issuer_chain: X509Chain::new(),
        })
    }

    pub fn self_signed() -> Self {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        Self {
            cert: self_sign_ca(&pkey).unwrap(),
            issuer_chain: X509Chain::new(),
            pkey,
        }
    }
}

impl FromEnvironment for CertificateAuthority {
    fn from_env() -> Self {
        match (env::var("CERT_FILE"), env::var("KEY_FILE")) {
            (Ok(cert_file), Ok(key_file)) => Self::from_files(&cert_file, &key_file).unwrap(),
            _ => {
                warn!("falling back to a self-signed certificate");
                Self::self_signed()
            }
        }
    }
}

impl Debug for CertificateAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateAuthority")
            .field("cert", &self.cert)
            .field("issuer_chain", &self.issuer_chain)
            .finish()
    }
}
