use std::{fs, path::Path, sync::Arc};

use anyhow::{anyhow, ensure, Context, Result};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
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
        let (label, der) = pem_rfc7468::decode_vec(&pem)
            .with_context(|| format!("Failed to decode Ed25519 key pair at {path:?}"))?;
        ensure!(
            label == "PRIVATE KEY",
            "PEM label at {path:?} invalid for an Ed25519 key pair"
        );
        let key = Ed25519KeyPair::from_pkcs8(&der)
            .with_context(|| format!("Failed to parse Ed25519 key pair at {path:?}"))?;
        Ok(Arc::new(key))
    }

    fn generate(&self, path: &Path) -> Result<KeyHandle> {
        let der = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| anyhow!("Failed to generate Ed25519 key pair"))?;
        let key = Ed25519KeyPair::from_pkcs8(der.as_ref())
            .expect("Failed to parse generated Ed25519 key pair");

        let pem = pem_rfc7468::encode_string("PRIVATE KEY", Default::default(), der.as_ref())
            .expect("Failed to encode generated key pair as PEM");
        fs::write(path, pem)
            .with_context(|| format!("Failed to write Ed25519 key pair to {path:?}"))?;

        Ok(Arc::new(key))
    }

    fn to_jwk(&self, kid: &str, key: &KeyHandle) -> Value {
        let key = key.clone().downcast::<Ed25519KeyPair>().unwrap();
        json!({
            "kid": kid,
            "use": "sig",
            "kty": "OKP",
            "alg": "EdDSA",
            "crv": "Ed25519",
            "x": base64url(key.public_key().as_ref()),
        })
    }

    fn sign(&self, data: &[u8], key: &KeyHandle) -> Result<Vec<u8>> {
        let key = key.clone().downcast::<Ed25519KeyPair>().unwrap();
        Ok(key.sign(data).as_ref().to_vec())
    }
}
