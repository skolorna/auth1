use std::{fs::{self, OpenOptions}, io::Write, path::PathBuf};

use jsonwebkey::{ByteVec, JsonWebKey, PublicExponent};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation};
use openssl::{pkey::{Private}, rsa::Rsa};
use serde::{de::DeserializeOwned, Serialize};
use uuid::Uuid;

pub trait CertManager {
    /// Get the public JSON web key with the specified `kid` (key id).
    fn get_public_jwk(&self, kid: &str) -> std::io::Result<JsonWebKey>;

    /// Encode a JWT.
    fn encode_jwt(&self, claims: &impl Serialize) -> jsonwebtoken::errors::Result<String>;

    /// Decode (and verify) a JWT.
    fn decode_jwt<T: DeserializeOwned>(
        &self,
        token: &str,
    ) -> jsonwebtoken::errors::Result<TokenData<T>>;
}

pub struct FileCertManager {
    certs_dir: PathBuf,
}

impl FileCertManager {
    pub fn algorithm(&self) -> Algorithm {
        Algorithm::RS256
    }

    pub fn new(certs_dir: PathBuf) -> std::io::Result<Self> {
        fs::create_dir_all(&certs_dir)?;

        Ok(Self { certs_dir })
    }

    fn private_key_path(&self, key_id: &str) -> PathBuf {
        self.certs_dir.join(key_id).with_extension("pem")
    }

    fn get_private_pem(&self, key_id: &str) -> std::io::Result<Vec<u8>> {
        let key_path = self.private_key_path(key_id);
        fs::read(key_path)
    }

    fn get_private_rsa(&self, key_id: &str) -> std::io::Result<Rsa<Private>> {
        let pem = self.get_private_pem(key_id)?;
        let rsa = Rsa::private_key_from_pem(&pem)?;

        Ok(rsa)
    }

    fn get_public_pem(&self, key_id: &str) -> std::io::Result<Vec<u8>> {
        let rsa = self.get_private_rsa(key_id)?;
        let public_pem = rsa.public_key_to_pem()?;

        Ok(public_pem)
    }

    #[deprecated(note = "UUIDv4 must be replaced with something more secure.")]
    fn any_private_pem(&self) -> std::io::Result<(String, Vec<u8>)> {
        let key_id = Uuid::new_v4().to_string();
        let key_path = self.private_key_path(&key_id);

        let pem = if key_path.exists() {
            fs::read(key_path)?
        } else {
            let rsa = Rsa::generate(4096)?;
            let pem = rsa.private_key_to_pem()?;

            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(key_path)?;

            file.write_all(&pem)?;

            pem
        };

        Ok((key_id, pem))
    }
}

impl CertManager for FileCertManager {
    fn encode_jwt(&self, claims: &impl Serialize) -> jsonwebtoken::errors::Result<String> {
        let (key_id, pem) = self.any_private_pem().expect("unable to get private key");

        let mut header = Header::new(self.algorithm());
        header.kid = Some(key_id);

        let key = EncodingKey::from_rsa_pem(&pem).unwrap();

        jsonwebtoken::encode(&header, claims, &key)
    }

    fn decode_jwt<T: DeserializeOwned>(
        &self,
        token: &str,
    ) -> jsonwebtoken::errors::Result<TokenData<T>> {
        let header = jsonwebtoken::decode_header(token)?;
        let key_id = header.kid.unwrap();

        let pem = self.get_public_pem(&key_id).unwrap();
        let decoding_key = DecodingKey::from_rsa_pem(&pem).unwrap();

        let validation = Validation::new(self.algorithm());

        jsonwebtoken::decode::<T>(token, &decoding_key, &validation)
    }

    fn get_public_jwk(&self, key_id: &str) -> std::io::Result<JsonWebKey> {
        let rsa = self.get_private_rsa(key_id)?;

        let jwk_rsa = jsonwebkey::RsaPublic {
            n: ByteVec::from(rsa.n().to_vec()),
            e: PublicExponent,
        };

        let mut jwk = JsonWebKey::new(jsonwebkey::Key::RSA { public: jwk_rsa, private: None, });

        jwk.key_id = Some(key_id.to_owned());

        Ok(jwk)
    }
}
