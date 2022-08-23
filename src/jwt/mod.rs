use rand::{thread_rng, Rng};

pub const SECRET_LEN: usize = 64;

pub fn gen_secret() -> [u8; SECRET_LEN] {
    let mut buf = [0; SECRET_LEN];
    thread_rng().fill(&mut buf);
    buf
}

pub mod refresh_token {
    use jsonwebtoken::{EncodingKey, Header};
    use serde::{Deserialize, Serialize};
    use time::OffsetDateTime;
    use uuid::Uuid;

    pub const TTL_SECS: i64 = 90 * 86400; // 90 days

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

pub mod access_token {}
