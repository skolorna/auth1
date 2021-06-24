use std::{path::Path, time::Instant};

use certmanager::{CertManager, FileCertManager};
use serde::{Serialize, Deserialize};

mod certmanager;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub company: String,
    pub exp: usize,
}

fn main() {
    let claims = Claims {
        sub: "user1234".to_owned(),
        company: "Skolorna".to_owned(),
        exp: 100_000_000_000,
    };

    let cert_manager = FileCertManager::new(Path::new("certs").to_owned()).unwrap();

    let encode_start = Instant::now();

    let token = cert_manager.encode_jwt(&claims).unwrap();

    // let token = jwt::encode(&claims).expect("failed to sign token");

    println!("{}", token);
    println!("{}ms encode", encode_start.elapsed().as_millis());

    let decoded = cert_manager.decode_jwt::<Claims>(&token).unwrap();
    
    let key_id = decoded.header.kid.clone().unwrap();

    let jwk = cert_manager.get_public_jwk(&key_id).unwrap();

    println!("{}", jwk.to_string());

    // let decoded = jwt::decode(&token).expect("failed to verify token");

    println!("{:?}", decoded.header);
}
