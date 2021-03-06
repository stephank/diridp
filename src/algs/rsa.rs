use std::{path::Path, sync::Arc};

use anyhow::{Context, Error, Result};
use digest::{Digest, DynDigest};
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
        matches!(
            alg,
            "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512"
        )
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
    fn alg(&self) -> &str {
        &self.alg
    }

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

    fn sign(&self, data: &[u8], key: &KeyHandle) -> Result<Vec<u8>> {
        let key = key.clone().downcast::<RsaPrivateKey>().unwrap();

        let (mut hasher, hash_kind): (Box<dyn DynDigest>, Hash) = match self.alg.as_str() {
            "RS256" | "PS256" => (Box::new(sha2::Sha256::new()), Hash::SHA2_256),
            "RS384" | "PS384" => (Box::new(sha2::Sha384::new()), Hash::SHA2_384),
            "RS512" | "PS512" => (Box::new(sha2::Sha512::new()), Hash::SHA2_512),
            _ => unreachable!(),
        };

        // Reset the hasher in case we use PSS padding, so it can be reused, because we want the
        // MGF1 digest algorithm to match the message digest algorithm.
        hasher.update(data);
        let hash = hasher.finalize_reset();

        let padding = match self.alg.as_str() {
            "RS256" | "RS384" | "RS512" => rsa::PaddingScheme::PKCS1v15Sign {
                hash: Some(hash_kind),
            },
            "PS256" | "PS384" | "PS512" => {
                // Salt length should match message digest length.
                let salt_len = hasher.output_size();
                rsa::PaddingScheme::PSS {
                    salt_rng: Box::new(rand::thread_rng()),
                    digest: hasher,
                    salt_len: Some(salt_len),
                }
            }
            _ => unreachable!(),
        };

        key.sign(padding, &hash).map_err(Error::new)
    }
}

fn default_key_size() -> usize {
    2048
}
