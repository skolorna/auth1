use chrono::{DateTime, Duration, Utc};
use diesel::{dsl::Gt, expression::bound::Bound, prelude::*, sql_types};
use jsonwebtoken::EncodingKey;
use openssl::{pkey::PKey, rsa::Rsa};

use uuid::Uuid;

use crate::{
    db::postgres::PgConn, errors::AppResult, schema::certificates, token::access_token,
    types::DbX509, x509::self_sign_ca,
};

pub type CertificateId = Uuid;

#[derive(Debug, Queryable, Identifiable, Associations)]
pub struct Certificate {
    pub id: CertificateId,
    x509: DbX509,
    key: Vec<u8>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

type ValidForSig =
    Gt<certificates::columns::not_after, Bound<sql_types::Timestamptz, DateTime<Utc>>>;
type ValidForVer =
    Gt<certificates::columns::not_after, Bound<sql_types::Timestamptz, DateTime<Utc>>>;

impl Certificate {
    pub const RSA_BITS: u32 = 2048;

    pub fn ttl() -> Duration {
        Duration::seconds(86400)
    }

    pub fn valid_for_signing() -> ValidForSig {
        certificates::columns::not_after.gt(Utc::now() + Duration::seconds(access_token::TTL_SECS))
    }

    pub fn valid_for_verifying() -> ValidForVer {
        certificates::columns::not_after.gt(Utc::now())
    }

    pub fn for_signing(pg: &PgConn) -> AppResult<Self> {
        use crate::schema::certificates::{columns, table};

        pg.transaction(|| {
            let r = table
                .filter(Self::valid_for_signing())
                .order(columns::not_after.asc())
                .first(pg)
                .optional()?;

            if let Some(cert) = r {
                return Ok(cert);
            }

            let rsa = Rsa::generate(Self::RSA_BITS)?;
            let pkey = PKey::from_rsa(rsa)?;
            let x509 = self_sign_ca(&pkey)?;

            let not_before = Utc::now();
            let not_after = not_before + Duration::days(30);

            let new = NewCertificate {
                id: Uuid::new_v4(),
                x509: &x509.into(),
                key: &pkey.private_key_to_der()?,
                not_before,
                not_after,
            };

            let cert = diesel::insert_into(table).values(new).get_result(pg)?;

            Ok(cert)
        })
    }

    pub fn jwt_enc(&self) -> EncodingKey {
        EncodingKey::from_rsa_der(&self.key)
    }
}

#[derive(Debug, Insertable)]
#[table_name = "certificates"]
struct NewCertificate<'a> {
    id: CertificateId,
    x509: &'a DbX509,
    key: &'a [u8],
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}
