use chrono::{Duration, Utc};
use openssl::{
    asn1::Asn1Time,
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{
        extension::{BasicConstraints, KeyUsage},
        X509Name, X509,
    },
};

/// Generate a self-signed x509 certificate.
/// ```
/// use openssl::{pkey::PKey, rsa::Rsa};
/// use auth1::x509::self_sign_x509;
///
/// let rsa = Rsa::generate(2048).unwrap();
/// let pkey = PKey::from_rsa(rsa).unwrap();
/// let x509 = self_sign_x509(&pkey).unwrap();
/// ```
pub fn self_sign_x509(pkey: &PKey<Private>) -> Result<X509, ErrorStack> {
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
    builder.set_pubkey(pkey)?;

    let basic_constraints = BasicConstraints::new().ca().critical().build()?;
    let key_usage = KeyUsage::new().key_cert_sign().crl_sign().build()?;
    builder.append_extension(basic_constraints)?;
    builder.append_extension(key_usage)?;

    builder.sign(pkey, MessageDigest::sha256())?;

    let certificate: X509 = builder.build();

    Ok(certificate)
}
