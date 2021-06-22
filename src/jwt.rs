use jsonwebtoken::{
    errors::Result, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use openssl::rsa::{Padding, Rsa};
use serde::{Deserialize, Serialize};

use crate::certstore::{get_kid_and_privkey, pubkey_der_from_kid};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub company: String,
    pub exp: usize,
}

pub const JWT_ALG: Algorithm = Algorithm::RS256;

pub fn encode(claims: &Claims) -> Result<String> {
    let (kid, private_der) = get_kid_and_privkey().expect("unable to obtain private key");

    let key = EncodingKey::from_rsa_der(&private_der);
    // let key = EncodingKey::from_secret(b"bruh");

    let mut header = Header::new(JWT_ALG);
    header.kid = Some(kid);
    jsonwebtoken::encode(&header, claims, &key)
}

pub fn decode(token: &str) -> Result<TokenData<Claims>> {
    let header = jsonwebtoken::decode_header(&token)?;

    match header.kid {
        Some(kid) => {
            let der = pubkey_der_from_kid(&kid).expect("unable to read pubkey");

            let key = DecodingKey::from_rsa_der(&der);
        
            jsonwebtoken::decode::<Claims>(token, &key, &Validation::new(JWT_ALG))
        },
        _ => {
            panic!("no key id");
        }
    }

}
