use std::{env, fmt::Debug, fs::File, io::Read, iter};

use chrono::{DateTime, Duration, TimeZone, Utc};
use openssl::{
    asn1::Asn1Time,
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::{HasPrivate, HasPublic, PKey, PKeyRef, Private},
    rsa::Rsa,
    x509::{
        extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        X509Name, X509NameRef, X509Ref, X509,
    },
};
use tracing::warn;

use crate::util::FromEnvironment;

/// Generate a self-signed x509 certificate.
/// ```
/// use openssl::{pkey::PKey, rsa::Rsa};
/// use auth1::x509::self_sign_ca;
///
/// let rsa = Rsa::generate(2048).unwrap();
/// let pkey = PKey::from_rsa(rsa).unwrap();
/// let x509 = self_sign_ca(&pkey).unwrap();
///
/// assert_eq!(x509.issuer_name().to_der().unwrap(), x509.subject_name().to_der().unwrap());
/// ```
pub fn self_sign_ca(pkey: &PKeyRef<impl HasPrivate>) -> Result<X509, ErrorStack> {
    let mut name = X509Name::builder()?;
    name.append_entry_by_nid(Nid::COMMONNAME, "AUTH1 SELF SIGNED")?;
    let name = name.build();

    let now = Utc::now();
    let nbf = Asn1Time::from_unix(now.timestamp())?;
    let naf = Asn1Time::from_unix((now + Duration::days(365)).timestamp())?;

    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_not_before(&nbf)?;
    builder.set_not_after(&naf)?;

    let ctx = builder.x509v3_context(None, None);
    let skey = SubjectKeyIdentifier::new().critical().build(&ctx)?;
    builder.append_extension(skey)?;
    builder.set_pubkey(pkey)?;

    builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    builder.sign(pkey, MessageDigest::sha384())?;

    Ok(builder.build())
}

/// Sign an x509 certificate with a certificate authority.
///
/// ```
/// use openssl::{nid::Nid, pkey::PKey, rsa::Rsa, x509::{X509Name}};
/// use chrono::{Duration, Utc};
/// use auth1::x509::{self_sign_ca, sign_leaf};
///
/// let ca_pkey = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
/// let ca = self_sign_ca(&ca_pkey).unwrap();
///
/// let mut name = X509Name::builder().unwrap();
/// name.append_entry_by_nid(Nid::COMMONNAME, "Leaf").unwrap();
/// let name = name.build();
///
/// let leaf_pkey = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
/// let now = Utc::now();
/// let x509 = sign_leaf(&name, now, now + Duration::days(30), &leaf_pkey, &ca, &ca_pkey).unwrap();
/// ```
pub fn sign_leaf(
    subject: &X509NameRef,
    nbf: DateTime<impl TimeZone>,
    naf: DateTime<impl TimeZone>,
    pubkey: &PKeyRef<impl HasPublic>,
    ca: &X509Ref,
    ca_pkey: &PKeyRef<impl HasPrivate>,
) -> Result<X509, ErrorStack> {
    let nbf = Asn1Time::from_unix(nbf.timestamp())?;
    let naf = Asn1Time::from_unix(naf.timestamp())?;

    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_subject_name(subject)?;
    builder.set_issuer_name(ca.subject_name())?;
    builder.set_not_before(&nbf)?;
    builder.set_not_after(&naf)?;
    builder.set_pubkey(pubkey)?;

    let ctx = builder.x509v3_context(Some(ca), None);
    let skey = SubjectKeyIdentifier::new().critical().build(&ctx)?;
    let akey = AuthorityKeyIdentifier::new()
        .critical()
        .issuer(true)
        .keyid(true)
        .build(&ctx)?;
    builder.append_extension(skey)?;
    builder.append_extension(akey)?;

    builder.append_extension(BasicConstraints::new().critical().build()?)?;
    builder.append_extension(KeyUsage::new().critical().digital_signature().build()?)?;

    builder.sign(ca_pkey, MessageDigest::sha256())?;

    Ok(builder.build())
}

#[derive(Clone)]
pub struct CertificateAuthority {
    pub cert: X509,
    pub issuer_chain: Vec<X509>,
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
            issuer_chain: vec![],
        })
    }

    pub fn self_signed() -> Self {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        Self {
            cert: self_sign_ca(&pkey).unwrap(),
            issuer_chain: vec![],
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
