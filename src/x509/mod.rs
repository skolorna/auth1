use chrono::{DateTime, Duration, TimeZone, Utc};
use openssl::{
    asn1::Asn1Time,
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::{HasPrivate, HasPublic, PKeyRef},
    x509::{
        extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        X509Name, X509NameRef, X509Ref, X509,
    },
};

pub mod ca;
pub mod chain;

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
