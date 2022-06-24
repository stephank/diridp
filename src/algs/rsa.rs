use std::{path::Path, sync::Arc};

use anyhow::{Context, Error, Result};
use digest::Digest;
use rsa::{
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    Hash, PublicKeyParts, RsaPrivateKey,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::util::base64url;

use super::{Algorithm, AlgorithmMatcher, KeyHandle};

pub struct RsaMatcher;

#[derive(Deserialize)]
pub struct RsaAlg {
    #[serde(skip)]
    pub alg: String,
    #[serde(default = "default_key_size")]
    pub key_size: usize,
}

impl AlgorithmMatcher for RsaMatcher {
    fn matches_config(&self, alg: &str, _rest: &Map<String, Value>) -> bool {
        matches!(alg, "RS256" | "RS384" | "RS512")
    }

    fn create_algorithm(
        &self,
        alg: String,
        rest: Map<String, Value>,
    ) -> Result<Box<dyn Algorithm>> {
        let mut res: RsaAlg = serde_json::from_value(Value::Object(rest)).map_err(Error::new)?;
        res.alg = alg;
        Ok(Box::new(res))
    }
}

impl Algorithm for RsaAlg {
    fn load_key_pair(&self, path: &Path) -> Result<KeyHandle> {
        let key = RsaPrivateKey::read_pkcs8_pem_file(&path)
            .with_context(|| format!("Failed to read RSA key pair {path:?}"))?;
        Ok(Arc::new(key))
    }

    fn generate(&self, path: &Path) -> Result<KeyHandle> {
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, self.key_size)
            .context("Failed to generate RSA key pair")?;

        key.write_pkcs8_pem_file(&path, Default::default())
            .with_context(|| format!("Failed to write RSA key pair to {path:?}"))?;

        Ok(Arc::new(key))
    }

    fn to_jwk(&self, kid: &str, key: &KeyHandle) -> Value {
        let key = key.clone().downcast::<RsaPrivateKey>().unwrap();
        json!({
            "kid": kid,
            "use": "sig",
            "kty": "RSA",
            "alg": self.alg,
            "n": base64url(&key.n().to_bytes_be()),
            "e": base64url(&key.e().to_bytes_be()),
        })
    }

    fn create_header(&self, kid: &str, _key: &KeyHandle) -> String {
        serde_json::to_string(&json!({
            "kid": kid,
            "alg": &self.alg,
        }))
        .expect("Failed to serialize JWT header")
    }

    fn sign(&self, data: &[u8], key: &KeyHandle) -> Result<Vec<u8>> {
        let key = key.clone().downcast::<RsaPrivateKey>().unwrap();
        let (hash, hash_kind) = match self.alg.as_str() {
            "RS256" => (sha2::Sha256::digest(data).to_vec(), Hash::SHA2_256),
            "RS384" => (sha2::Sha384::digest(data).to_vec(), Hash::SHA2_384),
            "RS512" => (sha2::Sha512::digest(data).to_vec(), Hash::SHA2_512),
            _ => unreachable!(),
        };
        key.sign(
            rsa::PaddingScheme::PKCS1v15Sign {
                hash: Some(hash_kind),
            },
            &hash,
        )
        .map_err(Error::new)
    }
}

fn default_key_size() -> usize {
    2048
}
