use chrono::{DateTime, Duration, Utc};
use diesel::{QueryDsl, RunQueryDsl};
use jsonwebtoken::{EncodingKey, Header};
use openssl::rsa::Rsa;
use serde::Serialize;

use super::user::{User, UserId};
use crate::{
    result::{Error, Result},
    schema::keys,
    token::{AccessToken, AccessTokenClaims, RefreshToken, JWT_ALG},
    DbConn,
};

pub type KeyId = i32;

#[derive(Debug, Queryable, Identifiable, Associations, Serialize)]
#[belongs_to(User, foreign_key = "sub")]
pub struct Key {
    pub id: KeyId,
    pub sub: UserId,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub iat: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct KeyResponse {
    pub refresh_token: RefreshToken,
    pub access_token: AccessToken,
}

impl Key {
    pub fn create(conn: &DbConn, sub: UserId) -> Result<KeyResponse> {
        let refresh_token = RefreshToken::generate();

        let rsa = Rsa::generate(2048).unwrap();

        // let private_pem = ec
        // .private_key_to_pem_passphrase(Cipher::aes_256_gcm(), &refresh_token.to_openssl_passphrase())
        // .unwrap();

        // let decrypted = EcKey::private_key_from_pem_passphrase(&private_pem, &refresh_token.to_openssl_passphrase()).unwrap();

        let private_der = rsa.private_key_to_der().map_err(|_| Error::InternalError)?;

        let new_key = NewKey {
            sub,
            public_key: &rsa.public_key_to_pem().unwrap(),
            private_key: &refresh_token.encrypt(&private_der)?,
        };

        let key: Self = diesel::insert_into(keys::table)
            .values(new_key)
            .get_result(conn)?;

        Ok(KeyResponse {
            refresh_token,
            access_token: key.sign_access_token(&refresh_token)?,
        })
    }

    pub fn exp(&self) -> DateTime<Utc> {
        Utc::now() + Duration::days(90)
    }

    /// Get the public part of a key stored in the database.
    /// Returns the raw bytes of the key.
    /// FIXME: If the key has expired, the row will be deleted and
    /// the function will pretend that it never existed.
    /// Do note, however, that it shouldn't matter to much whether
    /// the key has expired or not as this public key is exclusively
    /// used for *validation* of access tokens.
    pub fn get_public(conn: &DbConn, kid: KeyId) -> Result<Vec<u8>> {
        use crate::schema::keys::{columns, table};
        let pubkey = table
            .select(columns::public_key)
            .find(kid)
            .first::<Vec<u8>>(conn)?;

        Ok(pubkey)
    }

    // TODO: ECC?
    pub fn sign_access_token(&self, refresh_token: &RefreshToken) -> Result<AccessToken> {
        let now = Utc::now();
        let exp = (now + Duration::hours(1)).min(self.exp());

        if exp < now {
            return Err(Error::InvalidCredentials);
        }

        let der = refresh_token.decrypt(&self.private_key)?;

        let encoding_key = EncodingKey::from_rsa_der(&der);
        let header = Header {
            typ: Some("JWT".into()),
            alg: JWT_ALG,
            cty: None,
            jku: None,
            kid: Some(self.id.to_string()),
            x5u: None,
            x5t: None,
        };
        let claims = AccessTokenClaims {
            sub: self.sub,
            exp: exp.timestamp(),
        };

        let token = jsonwebtoken::encode(&header, &claims, &encoding_key).expect("hm");

        Ok(AccessToken::new(token))
    }
}

#[derive(Debug, Queryable, Identifiable, Associations, Serialize)]
#[belongs_to(User, foreign_key = "sub")]
#[table_name = "keys"]
pub struct KeyInfo {
    pub id: KeyId,
    pub sub: UserId,
    pub iat: DateTime<Utc>,
}

#[derive(Debug, Insertable)]
#[table_name = "keys"]
struct NewKey<'a> {
    sub: UserId,
    public_key: &'a [u8],
    private_key: &'a [u8],
}
