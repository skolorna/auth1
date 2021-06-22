use serde::{Serialize, Deserialize};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, errors::Result};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
    exp: usize,
}

fn sign(claims: &Claims) -> Result<String> {
    let mut header = Header::new(Algorithm::RS512);
    header.kid = Some("blabla".to_owned());
    header.jku = Some("https://www.youtube.com/watch?v=dQw4w9WgXcQ".to_owned());
    encode(&header, claims, &EncodingKey::from_rsa_pem(include_bytes!("private.pem"))?)
}

fn main() {
    let claims = Claims {
        sub: "helo".to_owned(),
        company: "Skolorna".to_owned(),
        exp: 0,
    };

    let token = sign(&claims).expect("failed to sign token");

    println!("{}", token);
}
