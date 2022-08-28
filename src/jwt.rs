pub mod refresh_token {
    use jsonwebtoken::{EncodingKey, Header};
    use rand::{thread_rng, Rng};
    use serde::{Deserialize, Serialize};
    use time::OffsetDateTime;
    use uuid::Uuid;

    pub const TTL_SECS: i64 = 90 * 86400; // 90 days
    pub const SECRET_LEN: usize = 64;

    pub fn gen_secret() -> [u8; SECRET_LEN] {
        let mut buf = [0; SECRET_LEN];
        thread_rng().fill(&mut buf);
        buf
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Claims {
        sub: Uuid,
        exp: i64,
    }

    pub fn sign(sub: Uuid, secret: &[u8]) -> Result<String, jsonwebtoken::errors::Error> {
        let key = EncodingKey::from_secret(secret);
        let claims = Claims {
            sub,
            exp: OffsetDateTime::now_utc().unix_timestamp() + TTL_SECS,
        };

        jsonwebtoken::encode(&Header::default(), &claims, &key)
    }
}

pub mod access_token {
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
    use openssl::x509::X509;
    use serde::{Deserialize, Serialize};
    use sqlx::{Executor, PgConnection, PgExecutor, Postgres};
    use time::OffsetDateTime;
    use uuid::Uuid;

    use crate::{http::Result, x509};

    pub const ALG: Algorithm = Algorithm::RS256;
    pub const TTL_SECS: i64 = 600;

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Claims {
        pub sub: Uuid,
        pub exp: i64,
    }

    pub async fn sign(sub: Uuid, ca: &x509::Authority, db: &mut PgConnection) -> Result<String> {
        let (kid, key) = ca.get_sig_key(db).await?;
        let key = EncodingKey::from_rsa_der(&key);

        let header = Header {
            typ: Some("JWT".into()),
            alg: ALG,
            kid: Some(kid.to_string()),
            ..Header::default()
        };

        let claims = Claims {
            sub,
            exp: OffsetDateTime::now_utc().unix_timestamp() + TTL_SECS,
        };

        jsonwebtoken::encode(&header, &claims, &key).map_err(Into::into)
    }

    pub async fn verify(token: &str, db: impl PgExecutor<'_>) -> Result<Claims> {
        let header = jsonwebtoken::decode_header(token)?;
        let kid: Uuid = header.kid.unwrap().parse().unwrap();

        let record = sqlx::query!("SELECT x509 FROM certificates WHERE id = $1", kid)
            .fetch_optional(db)
            .await?
            .expect("no cert found");
        let x509 = X509::from_der(&record.x509)?;
        let pub_der = x509.public_key()?.rsa()?.public_key_to_der_pkcs1()?;
        let key = DecodingKey::from_rsa_der(&pub_der);

        let decoded = jsonwebtoken::decode::<Claims>(token, &key, &Validation::new(ALG))?;

        Ok(decoded.claims)
    }
}

pub mod verification_token {
    use jsonwebtoken::{EncodingKey, Header};
    use serde::{Deserialize, Serialize};

    fn gen_secret(email: &str, password_hash: &str) -> Vec<u8> {
        let mut secret = email.as_bytes().to_vec();
        secret.extend_from_slice(&password_hash.as_bytes());
        secret
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Claims {
        email: String,
    }

    pub fn sign(email: String, password_hash: &str) -> Result<String, jsonwebtoken::errors::Error> {
        let key = EncodingKey::from_secret(&gen_secret(&email, password_hash));
        let claims = Claims { email };

        jsonwebtoken::encode(&Header::default(), &claims, &key)
    }
}
