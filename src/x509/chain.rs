use std::{fmt::Display, iter::FromIterator, str::FromStr};

use base64::display::Base64Display;
use diesel::{
    backend::Backend,
    sql_types,
    types::{FromSql, ToSql},
};
use openssl::x509::X509;
use thiserror::Error;

const B64_CONF: base64::Config = base64::STANDARD;

#[derive(Debug, Default, Clone, AsExpression, FromSqlRow)]
#[sql_type = "diesel::sql_types::Text"]
pub struct X509Chain {
    pub certs: Vec<X509>,
}

impl X509Chain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, cert: X509) {
        self.certs.push(cert);
    }

    pub fn len(&self) -> usize {
        self.certs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = &X509> {
        self.certs.iter()
    }

    /// Verify that the certificate chain is internally valid (that the certificates are
    /// ordered correctly).
    ///
    /// ```
    /// use openssl::{nid::Nid, pkey::PKey, rsa::Rsa, x509::{X509Name}};
    /// use chrono::{Duration, Utc};
    /// use auth1::x509::{chain::X509Chain, self_sign_ca, sign_leaf};
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
    /// let leaf = sign_leaf(&name, now, now + Duration::days(30), &leaf_pkey, &ca, &ca_pkey).unwrap();
    ///
    /// let mut chain = X509Chain::new();
    ///
    /// // This ordering is important
    /// chain.add(leaf);
    /// chain.add(ca);
    ///
    /// assert!(chain.verify().unwrap());
    /// ```
    ///
    /// ```
    /// use openssl::{pkey::PKey, rsa::Rsa};
    /// use auth1::x509::{chain::X509Chain, self_sign_ca};
    ///
    /// let k1 = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    /// let c1 = self_sign_ca(&k1).unwrap();
    ///
    /// let k2 = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    /// let c2 = self_sign_ca(&k2).unwrap();
    ///
    /// let mut chain = X509Chain::new();
    /// chain.add(c1);
    /// chain.add(c2);
    ///
    /// // Two self-signed certificates aren't signed by each other.
    /// assert!(!chain.verify().unwrap());
    /// ```
    pub fn verify(&self) -> Result<bool, openssl::error::ErrorStack> {
        let mut iter = self.certs.windows(2);

        while let Some([left, right]) = iter.next() {
            if !left.verify(right.public_key()?.as_ref())? {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

impl Display for X509Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for cert in &self.certs {
            let der = cert.to_der()?;
            writeln!(f, "{}", Base64Display::with_config(&der, B64_CONF))?;
        }

        Ok(())
    }
}

impl<'a> FromIterator<&'a X509> for X509Chain {
    fn from_iter<T: IntoIterator<Item = &'a X509>>(iter: T) -> Self {
        let mut c = X509Chain::new();

        for i in iter {
            c.add(i.to_owned());
        }

        c
    }
}

#[derive(Debug, Error)]
pub enum ParseX509ChainErr {
    #[error("{0}")]
    Base64(#[from] base64::DecodeError),

    #[error("{0}")]
    OpensslError(#[from] openssl::error::ErrorStack),
}

impl FromStr for X509Chain {
    type Err = ParseX509ChainErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut c = Self::new();

        for line in s.lines() {
            let der = base64::decode_config(line, B64_CONF)?;
            let x509 = X509::from_der(&der)?;

            c.add(x509);
        }

        Ok(c)
    }
}

impl<DB> ToSql<sql_types::Text, DB> for X509Chain
where
    DB: Backend,
    String: ToSql<sql_types::Text, DB>,
{
    fn to_sql<W: std::io::Write>(
        &self,
        out: &mut diesel::serialize::Output<W, DB>,
    ) -> diesel::serialize::Result {
        self.to_string().to_sql(out)
    }
}

impl<DB> FromSql<sql_types::Text, DB> for X509Chain
where
    DB: Backend,
    String: FromSql<sql_types::Text, DB>,
{
    fn from_sql(bytes: Option<&DB::RawValue>) -> diesel::deserialize::Result<Self> {
        let str = String::from_sql(bytes)?;
        let c = Self::from_str(&str)?;

        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use chrono::{Duration, Utc};
    use openssl::{nid::Nid, pkey::PKey, rsa::Rsa, x509::X509Name};

    use crate::x509::{self_sign_ca, sign_leaf};

    use super::X509Chain;

    #[test]
    fn parsing() {
        let root_pkey = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let root_cert = self_sign_ca(&root_pkey).unwrap();

        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, "Acme, Inc.")
            .unwrap();
        let name = name.build();

        let leaf_pkey = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let leaf_cert = sign_leaf(
            &name,
            Utc::now(),
            Utc::now() + Duration::hours(1),
            &leaf_pkey,
            &root_cert,
            &root_pkey,
        )
        .unwrap();

        let mut chain = X509Chain::new();
        chain.add(root_cert);
        chain.add(leaf_cert);

        let chain = X509Chain::from_str(&chain.to_string()).unwrap();
        assert_eq!(chain.len(), 2);
    }
}
