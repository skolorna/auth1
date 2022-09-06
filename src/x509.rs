use std::{fmt::Display, str::FromStr};

use base64::display::Base64Display;

use openssl::{
    asn1::Asn1Time,
    ec::{EcGroup, EcKey},
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::{HasPrivate, HasPublic, PKey, PKeyRef, Private},
    x509::{
        extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        X509Name, X509NameRef, X509Ref, X509,
    },
};
use sqlx::{
    encode::IsNull,
    error::BoxDynError,
    postgres::{PgArgumentBuffer, PgValueRef},
    Connection, PgConnection, Postgres,
};
use time::{Duration, OffsetDateTime};
use tracing::{debug, instrument};
use uuid::Uuid;

use crate::{
    http::{Error, Result},
    jwt::access_token,
};

#[derive(Debug, Default, Clone)]
pub struct Chain(Vec<X509>);

impl Chain {
    const BASE64_CONFIG: base64::Config = base64::STANDARD;

    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, cert: X509) {
        self.0.push(cert)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &X509> {
        self.0.iter()
    }

    pub fn last(&self) -> Option<&X509> {
        self.0.last()
    }

    pub fn verify(&self) -> Result<bool, openssl::error::ErrorStack> {
        let mut iter = self.0.windows(2);

        while let Some([left, right]) = iter.next() {
            if !left.verify(right.public_key()?.as_ref())? {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

impl Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for cert in &self.0 {
            let der = cert.to_der()?;
            writeln!(
                f,
                "{}",
                Base64Display::with_config(&der, Chain::BASE64_CONFIG)
            )?;
        }

        Ok(())
    }
}

impl FromIterator<X509> for Chain {
    fn from_iter<T: IntoIterator<Item = X509>>(iter: T) -> Self {
        Chain(iter.into_iter().collect())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseChainError {
    #[error("{0}")]
    Base64(#[from] base64::DecodeError),

    #[error("{0}")]
    Openssl(#[from] openssl::error::ErrorStack),
}

impl FromStr for Chain {
    type Err = ParseChainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.lines().try_fold(Self::new(), |mut chain, line| {
            let der = base64::decode_config(line, Chain::BASE64_CONFIG)?;
            chain.push(X509::from_der(&der)?);
            Ok(chain)
        })
    }
}

impl sqlx::Encode<'_, sqlx::Postgres> for Chain {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> IsNull {
        self.to_string().encode(buf)
    }
}

impl sqlx::Decode<'_, Postgres> for Chain {
    fn decode(value: PgValueRef<'_>) -> Result<Self, BoxDynError> {
        let chain = value.as_str()?.parse()?;
        Ok(chain)
    }
}

impl sqlx::Type<sqlx::Postgres> for Chain {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

#[derive(Clone)]
pub struct Authority {
    chain: Chain,
    key: PKey<Private>,
}

impl Authority {
    pub fn self_signed() -> Result<Self, ErrorStack> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = EcKey::generate(&group)?;
        let key = PKey::from_ec_key(key)?;

        let cert = gen_self_signed("AUTH1 SELF SIGNED", &key)?;
        let mut chain = Chain::new();
        chain.push(cert);

        Ok(Self { chain, key })
    }

    pub fn gen_leaf(&self) -> Result<Certificate, ErrorStack> {
        let id = Uuid::new_v4();

        let mut subject = X509Name::builder()?;
        subject.append_entry_by_nid(Nid::COMMONNAME, &id.to_string())?;
        let subject = subject.build();

        let nbf = OffsetDateTime::now_utc();
        let naf = nbf + Certificate::TTL;

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = EcKey::generate(&group)?;
        let key = PKey::from_ec_key(key)?;

        let x509 = sign_leaf(
            &subject,
            nbf,
            naf,
            &key,
            self.chain.last().unwrap(),
            &self.key,
        )?;

        Ok(Certificate {
            id,
            x509,
            chain: self.chain.clone(),
            key: key.private_key_to_pem_pkcs8()?,
            nbf,
            naf,
        })
    }

    #[instrument(skip_all)]
    async fn gen_insert_leaf(&self, db: &mut PgConnection) -> Result<(Uuid, Vec<u8>)> {
        let authority = self.clone();
        let cert = tokio::task::spawn_blocking(move || authority.gen_leaf())
            .await
            .map_err(|_| Error::internal())??;

        sqlx::query!(
          "INSERT INTO certificates (id, x509, chain, key, nbf, naf) VALUES ($1, $2, $3, $4, $5, $6)",
          cert.id,
          cert.x509.to_der()?,
          cert.chain.to_string(),
          cert.key,
          cert.nbf,
          cert.naf,
        ).execute(db).await?;

        Ok((cert.id, cert.key))
    }

    pub async fn get_sig_key(&self, db: &mut PgConnection) -> Result<(Uuid, Vec<u8>)> {
        let mut tx = db.begin().await?;

        let record = sqlx::query!(
            "SELECT id, key FROM certificates WHERE naf > $1 ORDER BY naf ASC",
            OffsetDateTime::now_utc() + access_token::TTL
        )
        .fetch_optional(&mut tx)
        .await?;

        if let Some(record) = record {
            debug!("found a valid certificate");
            return Ok((record.id, record.key));
        }

        let res = self.gen_insert_leaf(&mut tx).await?;
        tx.commit().await?;
        Ok(res)
    }

    /// Check if a signing key exists to be used `foresight` amount of time before it's
    /// needed for access token generation, in order to make sure caches are up-to-date.
    ///
    /// `foresight` is the amount of time *in addition to* the access token TTL.
    #[instrument(skip(self, db))]
    pub async fn sig_key_foresight(
        &self,
        db: &mut PgConnection,
        foresight: Duration,
    ) -> Result<()> {
        let mut tx = db.begin().await?;

        let record = sqlx::query!(
            "SELECT COUNT(1) FROM certificates WHERE naf > $1",
            OffsetDateTime::now_utc() + access_token::TTL + foresight
        )
        .fetch_one(&mut tx)
        .await?;

        if record.count.unwrap_or_default() < 1 {
            debug!("no up-to-date certificates found");

            self.gen_insert_leaf(&mut tx).await?;
        } else {
            debug!("found valid certificate");
        }

        tx.commit().await?;

        Ok(())
    }
}

pub struct Certificate {
    id: Uuid,
    x509: X509,
    chain: Chain,
    key: Vec<u8>,
    nbf: OffsetDateTime,
    naf: OffsetDateTime,
}

impl Certificate {
    pub const TTL: Duration = Duration::days(1);
}

fn gen_self_signed(cn: &str, pkey: &PKeyRef<impl HasPrivate>) -> Result<X509, ErrorStack> {
    let mut name = X509Name::builder()?;
    name.append_entry_by_nid(Nid::COMMONNAME, cn)?;
    let name = name.build();

    let now = OffsetDateTime::now_utc();
    let nbf = Asn1Time::from_unix(now.unix_timestamp())?;
    let naf = Asn1Time::from_unix((now + Duration::days(3650)).unix_timestamp())?;

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

fn sign_leaf(
    subject: &X509NameRef,
    nbf: OffsetDateTime,
    naf: OffsetDateTime,
    pubkey: &PKeyRef<impl HasPublic>,
    ca: &X509Ref,
    ca_pkey: &PKeyRef<impl HasPrivate>,
) -> Result<X509, ErrorStack> {
    let nbf = Asn1Time::from_unix(nbf.unix_timestamp())?;
    let naf = Asn1Time::from_unix(naf.unix_timestamp())?;

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
