use diesel::{
    backend::Backend,
    sql_types,
    types::{FromSql, ToSql},
};
use openssl::x509::X509;

#[derive(Debug, Clone, AsExpression, FromSqlRow)]
#[sql_type = "diesel::sql_types::Binary"]
pub struct DbX509(pub X509);

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

impl From<DbX509> for X509 {
    fn from(x509: DbX509) -> Self {
        x509.0
    }
}
