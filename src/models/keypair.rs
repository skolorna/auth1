use chrono::{DateTime, Duration, Utc};
use diesel::{dsl::Gt, expression::bound::Bound, prelude::*, sql_types};
use jsonwebtoken::EncodingKey;
use openssl::{error::ErrorStack, rsa::Rsa};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    db::postgres::PgConn,
    errors::{AppError, AppResult},
    schema::keypairs,
    token::AccessToken,
};

pub type KeypairId = Uuid;

#[derive(Debug, Queryable, Identifiable, Associations, Serialize)]
pub struct Keypair {
    pub id: KeypairId,
    public: Vec<u8>,
    private: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

type ValidForSig = Gt<keypairs::columns::created_at, Bound<sql_types::Timestamptz, DateTime<Utc>>>;
type ValidForVer = Gt<keypairs::columns::created_at, Bound<sql_types::Timestamptz, DateTime<Utc>>>;

fn map_rsa_err(err: ErrorStack) -> AppError {
    AppError::InternalError { cause: err.into() }
}

impl Keypair {
    pub const RSA_BITS: u32 = 2048;

    pub fn ttl() -> Duration {
        Duration::days(90)
    }

    pub fn valid_for_signing() -> ValidForSig {
        keypairs::columns::created_at.gt(Utc::now() - Self::ttl())
    }

    pub fn valid_for_verifying() -> ValidForVer {
        keypairs::columns::created_at.gt(Utc::now() - Self::ttl() - AccessToken::ttl())
    }

    pub fn for_signing(pg: &PgConn) -> AppResult<Self> {
        use crate::schema::keypairs::{columns, table};

        pg.transaction(|| {
            let r = table
                .filter(Self::valid_for_signing())
                .order(columns::created_at.asc())
                .first(pg)
                .optional()?;

            if let Some(keypair) = r {
                return Ok(keypair);
            }

            let id = Uuid::new_v4();

            let rsa = Rsa::generate(Self::RSA_BITS).map_err(map_rsa_err)?;

            let new = NewKeypair {
                id,
                public: &rsa.public_key_to_der().map_err(map_rsa_err)?,
                private: &rsa.private_key_to_der().map_err(map_rsa_err)?,
            };

            let keypair = diesel::insert_into(table).values(new).get_result(pg)?;

            Ok(keypair)
        })
    }

    pub fn jwt_enc(&self) -> EncodingKey {
        EncodingKey::from_rsa_der(&self.private)
    }
}

#[derive(Debug, Insertable)]
#[table_name = "keypairs"]
struct NewKeypair<'a> {
    id: KeypairId,
    public: &'a [u8],
    private: &'a [u8],
}
