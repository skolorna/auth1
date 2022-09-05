pub mod refresh_token {
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
    use rand::{thread_rng, Rng};
    use serde::{Deserialize, Serialize};
    use sqlx::PgExecutor;
    use time::{Duration, OffsetDateTime};
    use tracing::instrument;
    use uuid::Uuid;

    use crate::http::{Error, Result};

    pub const TTL: Duration = Duration::days(90);
    pub const SECRET_LEN: usize = 64;
    pub const ALG: Algorithm = Algorithm::HS256;

    pub fn gen_secret() -> [u8; SECRET_LEN] {
        let mut buf = [0; SECRET_LEN];
        thread_rng().fill(&mut buf);
        buf
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Claims {
        pub sub: Uuid,
        pub iat: i64,
        pub exp: i64,
    }

    #[instrument(skip(secret))]
    pub fn sign(sub: Uuid, secret: &[u8]) -> Result<String, jsonwebtoken::errors::Error> {
        let header = Header {
            typ: Some("JWT".into()),
            alg: ALG,
            ..Header::default()
        };

        let key = EncodingKey::from_secret(secret);
        let iat = OffsetDateTime::now_utc().unix_timestamp();
        let claims = Claims {
            sub,
            iat,
            exp: iat + TTL.whole_seconds(),
        };

        jsonwebtoken::encode(&header, &claims, &key)
    }

    #[instrument(skip(db))]
    pub async fn verify(token: &str, db: impl PgExecutor<'_>) -> Result<Claims> {
        let claims: Claims = {
            let mut validation = Validation::default();
            validation.insecure_disable_signature_validation();
            jsonwebtoken::decode(token, &DecodingKey::from_secret(&[]), &validation)?.claims
        };

        let (secret,) =
            sqlx::query_as::<_, (Vec<u8>,)>("SELECT jwt_secret FROM users WHERE id = $1")
                .bind(claims.sub)
                .fetch_optional(db)
                .await?
                .ok_or_else(Error::user_not_found)?;

        let key = DecodingKey::from_secret(&secret);
        let data = jsonwebtoken::decode(token, &key, &Validation::new(ALG))?;

        Ok(data.claims)
    }
}

pub mod access_token {
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
    use openssl::x509::X509;
    use sqlx::{PgConnection, PgExecutor};
    use time::{Duration, OffsetDateTime};
    use tracing::instrument;
    use uuid::Uuid;

    use crate::{
        http::{Error, Result},
        x509,
    };

    pub const ALG: Algorithm = Algorithm::ES256;
    pub const TTL: Duration = Duration::minutes(10);

    pub type Claims = auth1_sdk::AccessTokenClaims;

    #[instrument(skip(ca, db))]
    pub async fn sign(sub: Uuid, ca: &x509::Authority, db: &mut PgConnection) -> Result<String> {
        let (kid, key) = ca.get_sig_key(db).await?;
        let key = EncodingKey::from_ec_pem(&key)?;

        let header = Header {
            typ: Some("JWT".into()),
            alg: ALG,
            kid: Some(kid.to_string()),
            ..Header::default()
        };

        let iat = OffsetDateTime::now_utc().unix_timestamp();
        let claims = Claims {
            sub,
            iat,
            exp: iat + TTL.whole_seconds(),
        };

        Ok(jsonwebtoken::encode(&header, &claims, &key)?)
    }

    #[instrument(skip(db))]
    pub async fn verify(token: &str, db: impl PgExecutor<'_>) -> Result<Claims> {
        let header = jsonwebtoken::decode_header(token)?;
        let kid: Uuid = header
            .kid
            .ok_or(Error::Unauthorized)?
            .parse()
            .map_err(|_| Error::Unauthorized)?;

        let record = sqlx::query!("SELECT x509 FROM certificates WHERE id = $1", kid)
            .fetch_optional(db)
            .await?
            .ok_or(Error::Unauthorized)?;
        let x509 = X509::from_der(&record.x509)?;
        let key = x509.public_key()?.public_key_to_pem()?;
        let key = DecodingKey::from_ec_pem(&key)?;

        let data = jsonwebtoken::decode::<Claims>(token, &key, &Validation::new(ALG))?;

        Ok(data.claims)
    }
}

pub mod verification_token {
    use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
    use serde::{Deserialize, Serialize};
    use sqlx::PgExecutor;
    use tracing::instrument;
    use uuid::Uuid;

    use crate::http::Result;

    fn gen_secret(email: &str, password_hash: &str) -> Vec<u8> {
        let mut secret = email.as_bytes().to_vec();
        secret.extend_from_slice(password_hash.as_bytes());
        secret
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Claims {
        email: String,
        sub: Uuid,
    }

    pub fn sign(
        sub: Uuid,
        email: String,
        password_hash: &str,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let key = EncodingKey::from_secret(&gen_secret(&email, password_hash));
        let claims = Claims { sub, email };

        jsonwebtoken::encode(&Header::default(), &claims, &key)
    }

    #[instrument(skip(db))]
    pub async fn verify(token: &str, db: impl PgExecutor<'_>) -> Result<()> {
        let mut validation = Validation::default();
        validation.insecure_disable_signature_validation();

        let claims: Claims =
            jsonwebtoken::decode(token, &DecodingKey::from_secret(&[0]), &validation)?.claims;

        let (email, password_hash) =
            sqlx::query_as::<_, (String, String)>("SELECT email, hash FROM users WHERE id = $1")
                .bind(claims.sub)
                .fetch_one(db)
                .await?;
        let key = DecodingKey::from_secret(&gen_secret(&email, &password_hash));

        jsonwebtoken::decode::<Claims>(token, &key, &Validation::default())?;

        Ok(())
    }
}
