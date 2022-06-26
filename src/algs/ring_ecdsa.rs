use std::{fs, path::Path, sync::Arc};

use anyhow::{anyhow, bail, Context, Result};
use ring::{
    rand::SystemRandom,
    signature::{self, EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair},
};
use serde_json::{json, Map, Value};

use crate::util::base64url;

use super::{Algorithm, AlgorithmMatcher, KeyHandle};

pub struct EcdsaMatcher;

pub struct EcdsaAlg {
    pub alg: String,
}

impl AlgorithmMatcher for EcdsaMatcher {
    fn matches_config(&self, alg: &str, _rest: &Map<String, Value>) -> bool {
        matches!(alg, "ES256" | "ES384")
    }

    fn create_algorithm(
        &self,
        alg: String,
        _rest: Map<String, Value>,
    ) -> Result<Box<dyn Algorithm>> {
        Ok(Box::new(EcdsaAlg { alg }))
    }
}

impl EcdsaAlg {
    fn params(&self) -> &'static EcdsaSigningAlgorithm {
        match self.alg.as_str() {
            "ES256" => &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            "ES384" => &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            _ => unreachable!(),
        }
    }

    fn crv(&self) -> &'static str {
        match self.alg.as_str() {
            "ES256" => "P-256",
            "ES384" => "P-384",
            _ => unreachable!(),
        }
    }

    fn public_components<'a>(&self, key: &'a EcdsaKeyPair) -> (&'a [u8], &'a [u8]) {
        let x_len = match self.alg.as_str() {
            "ES256" => 32,
            "ES384" => 48,
            _ => unreachable!(),
        };
        key.public_key().as_ref()[1..].split_at(x_len)
    }
}

impl Algorithm for EcdsaAlg {
    fn alg(&self) -> &str {
        &self.alg
    }

    fn load_key_pair(&self, path: &Path) -> Result<KeyHandle> {
        let alg = self.alg.as_str();
        let pem =
            fs::read(path).with_context(|| format!("Failed to read {alg} key pair at {path:?}"))?;
        let key = EcdsaKeyPair::from_pkcs8(self.params(), &pem)
            .with_context(|| format!("Failed to parse {alg} key pair at {path:?}"))?;
        Ok(Arc::new(key))
    }

    fn generate(&self, path: &Path) -> Result<KeyHandle> {
        let alg = self.alg.as_str();
        let params = self.params();
        let pem = EcdsaKeyPair::generate_pkcs8(params, &SystemRandom::new())
            .map_err(|_| anyhow!("Failed to generate {alg} key pair"))?;
        let key = EcdsaKeyPair::from_pkcs8(params, pem.as_ref())
            .expect("Failed to parse generated {alg} key pair");
        fs::write(path, pem)
            .with_context(|| format!("Failed to write {alg} key pair to {path:?}"))?;
        Ok(Arc::new(key))
    }

    fn to_jwk(&self, kid: &str, key: &KeyHandle) -> Value {
        let key = key.clone().downcast::<EcdsaKeyPair>().unwrap();
        let (x, y) = self.public_components(&key);
        json!({
            "kid": kid,
            "use": "sig",
            "kty": "EC",
            "alg": self.alg,
            "crv": self.crv(),
            "x": base64url(x),
            "y": base64url(y),
        })
    }

    fn create_header(&self, kid: &str, _key: &KeyHandle) -> String {
        serde_json::to_string(&json!({
            "kid": kid,
            "alg": self.alg,
        }))
        .expect("Failed to serialize JWT header")
    }

    fn sign(&self, data: &[u8], key: &KeyHandle) -> Result<Vec<u8>> {
        let key = key.clone().downcast::<EcdsaKeyPair>().unwrap();
        let alg = self.alg.as_str();
        match key.sign(&SystemRandom::new(), data) {
            Ok(signature) => Ok(signature.as_ref().to_vec()),
            Err(_) => bail!("Failed to sign with {alg}"),
        }
    }
}
