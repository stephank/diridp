use std::{fs, path::Path, sync::Arc};

use anyhow::{Context, Error, Result};
use ed25519::pkcs8::{DecodePrivateKey, EncodePrivateKey, KeypairBytes};
use ed25519_dalek::{Keypair, Signer};
use serde_json::{json, Map, Value};

use crate::util::base64url;

use super::{Algorithm, AlgorithmMatcher, KeyHandle};

pub struct Ed25519Matcher;
pub struct Ed25519Alg;

impl AlgorithmMatcher for Ed25519Matcher {
    fn matches_config(&self, alg: &str, rest: &Map<String, Value>) -> bool {
        alg == "EdDSA" && rest.get("crv").and_then(Value::as_str) == Some("Ed25519")
    }

    fn create_algorithm(
        &self,
        _alg: String,
        _rest: Map<String, Value>,
    ) -> Result<Box<dyn Algorithm>> {
        Ok(Box::new(Ed25519Alg))
    }
}

impl Algorithm for Ed25519Alg {
    fn alg(&self) -> &str {
        "EdDSA"
    }

    fn load_key_pair(&self, path: &Path) -> Result<KeyHandle> {
        let pem = fs::read(path)
            .with_context(|| format!("Failed to read Ed25519 key pair at {path:?}"))?;
        let pem = String::from_utf8(pem)
            .with_context(|| format!("Failed to parse Ed25519 key pair at {path:?} as UTF-8"))?;
        let key = KeypairBytes::from_pkcs8_pem(&pem)
            .with_context(|| format!("Failed to read Ed25519 key pair {path:?}"))?;
        let key = key
            .to_bytes()
            .with_context(|| format!("Public key part missing from Ed25519 key pair {path:?}"))?;
        let key = Keypair::from_bytes(&key).unwrap();
        Ok(Arc::new(key))
    }

    fn generate(&self, path: &Path) -> Result<KeyHandle> {
        let key = Keypair::generate(&mut rand::thread_rng());
        let pem = KeypairBytes::from_bytes(&key.to_bytes())
            .to_pkcs8_pem(Default::default())
            .with_context(|| format!("Failed to serialize Ed25519 key pair"))?;
        fs::write(path, pem)
            .with_context(|| format!("Failed to write Ed25519 key pair to {path:?}"))?;
        Ok(Arc::new(key))
    }

    fn to_jwk(&self, kid: &str, key: &KeyHandle) -> Value {
        let key = key.clone().downcast::<Keypair>().unwrap();
        json!({
            "kid": kid,
            "use": "sig",
            "kty": "OKP",
            "alg": "EdDSA",
            "crv": "Ed25519",
            "x": base64url(key.public.as_bytes()),
        })
    }

    fn sign(&self, data: &[u8], key: &KeyHandle) -> Result<Vec<u8>> {
        let key = key.clone().downcast::<Keypair>().unwrap();
        match key.try_sign(data) {
            Ok(signature) => Ok(signature.as_ref().to_vec()),
            Err(err) => Err(Error::new(err)),
        }
    }
}
