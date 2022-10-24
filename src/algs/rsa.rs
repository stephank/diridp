use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Error, Result};
use digest::Digest;
use rsa::{
    pkcs1v15::SigningKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    pss::BlindedSigningKey,
    PublicKeyParts, RsaPrivateKey,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Sha256, Sha384, Sha512};
use signature::RandomizedSigner;

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

// We need to be able to take ownership. See comments in `sign()`.
type KeyContainer = Mutex<Option<RsaPrivateKey>>;

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
        Ok(Arc::new(Mutex::new(Some(key))))
    }

    fn generate(&self, path: &Path) -> Result<KeyHandle> {
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, self.key_size)
            .context("Failed to generate RSA key pair")?;

        key.write_pkcs8_pem_file(&path, Default::default())
            .with_context(|| format!("Failed to write RSA key pair to {path:?}"))?;

        Ok(Arc::new(Mutex::new(Some(key))))
    }

    fn to_jwk(&self, kid: &str, key: &KeyHandle) -> Value {
        let key = key.clone().downcast::<KeyContainer>().unwrap();
        let key = key.lock().unwrap();
        let key = key.as_ref().unwrap();
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
        let key = key.clone().downcast::<KeyContainer>().unwrap();
        let mut key = key.lock().unwrap();

        // The `rsa` crate types require wrapping the RsaPrivateKey inside a SigningKey, taking
        // ownership. This unfortunately means we have to do a little dance where we temporarily
        // take ownership of the key, then place it back when we're done.
        let owned_key = key.take().unwrap();

        // The types here make it difficult to do something like `Box<dyn Signer>`, so we
        // instead use macros to make this a little bit DRY.
        macro_rules! sign {
            ($key:expr) => {{
                let key = $key;
                let res = key.try_sign_with_rng(&mut rand::thread_rng(), data);
                (
                    key.into(),
                    res.map(|signature| signature.to_vec()).map_err(Error::new),
                )
            }};
        }

        macro_rules! sign_ps {
            ($digest:ty) => {
                sign!(BlindedSigningKey::<$digest>::new_with_salt_len(
                    owned_key,
                    // Salt length should match message digest length for PSS.
                    <$digest>::output_size(),
                ))
            };
        }

        macro_rules! sign_rs {
            ($digest:ty) => {
                sign!(SigningKey::<$digest>::new_with_prefix(owned_key))
            };
        }

        let (owned_key, res) = match self.alg.as_str() {
            "PS256" => sign_ps!(Sha256),
            "PS384" => sign_ps!(Sha384),
            "PS512" => sign_ps!(Sha512),
            "RS256" => sign_rs!(Sha256),
            "RS384" => sign_rs!(Sha384),
            "RS512" => sign_rs!(Sha512),
            _ => unreachable!(),
        };

        // Place the key back into the container.
        *key = Some(owned_key);

        res
    }
}

fn default_key_size() -> usize {
    2048
}
