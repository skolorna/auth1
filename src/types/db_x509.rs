use diesel::{
    backend::Backend,
    sql_types,
    types::{FromSql, ToSql},
};
use openssl::{hash::MessageDigest, x509::X509};

use super::jwk;

#[derive(Debug, Clone, AsExpression, FromSqlRow)]
#[sql_type = "diesel::sql_types::Binary"]
pub struct DbX509(pub X509);

impl DbX509 {
    pub fn jwk_key(&self) -> Result<jwk::Key, openssl::error::ErrorStack> {
        let rsa = self.0.public_key()?.rsa()?;

        Ok(jwk::Key::RSA {
            e: rsa.e().to_vec().into(),
            n: rsa.n().to_vec().into(),
        })
    }

    pub fn jwk_x5(&self) -> Result<jwk::X509Params, openssl::error::ErrorStack> {
        let chain = vec![self.0.to_der()?.into()];

        Ok(jwk::X509Params {
            url: None,
            cert_chain: Some(chain),
            thumbprint: Some(self.0.digest(MessageDigest::sha1())?.into()),
            thumbprint_sha256: Some(self.0.digest(MessageDigest::sha256())?.into()),
        })
    }
}

impl<DB> ToSql<sql_types::Binary, DB> for DbX509
where
    DB: Backend,
    Vec<u8>: ToSql<sql_types::Binary, DB>,
{
    fn to_sql<W: std::io::Write>(
        &self,
        out: &mut diesel::serialize::Output<W, DB>,
    ) -> diesel::serialize::Result {
        let der = self.0.to_der()?;
        der.to_sql(out)
    }
}

impl<DB> FromSql<sql_types::Binary, DB> for DbX509
where
    DB: Backend,
    Vec<u8>: FromSql<sql_types::Binary, DB>,
{
    fn from_sql(bytes: Option<&DB::RawValue>) -> diesel::deserialize::Result<Self> {
        let der = Vec::<u8>::from_sql(bytes)?;
        let x509 = X509::from_der(&der)?;
        Ok(Self(x509))
    }
}

impl From<X509> for DbX509 {
    fn from(x509: X509) -> Self {
        Self(x509)
    }
}
