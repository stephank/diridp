use std::{fs, path::Path, sync::Arc};

use anyhow::{Context, Result};
use digest::Digest;
use p256::{
    ecdsa::{signature::DigestSigner, SigningKey},
    elliptic_curve::sec1::{Coordinates, ToEncodedPoint},
    SecretKey,
};
use serde_json::{json, Map, Value};

use crate::util::base64url;

use super::{Algorithm, AlgorithmMatcher, KeyHandle};

pub struct Es256Matcher;

pub struct Es256Alg;

impl AlgorithmMatcher for Es256Matcher {
    fn matches_config(&self, alg: &str, _rest: &Map<String, Value>) -> bool {
        alg == "ES256"
    }

    fn create_algorithm(
        &self,
        _alg: String,
        _rest: Map<String, Value>,
    ) -> Result<Box<dyn Algorithm>> {
        Ok(Box::new(Es256Alg))
    }
}

impl Algorithm for Es256Alg {
    fn load_key_pair(&self, path: &Path) -> Result<KeyHandle> {
        let pem = fs::read(path)
            .with_context(|| format!("Failed to read P-256 secret key at {path:?}"))?;
        let pem = String::from_utf8(pem)
            .with_context(|| format!("Failed to parse P-256 secret key at {path:?} as UTF-8"))?;
        let key = SecretKey::from_sec1_pem(&pem)
            .with_context(|| format!("Failed to parse P-256 secret key at {path:?}"));
        Ok(Arc::new(key))
    }

    fn generate(&self, path: &Path) -> Result<KeyHandle> {
        let mut rng = rand::thread_rng();
        let key = SecretKey::random(&mut rng);

        let pem = key
            .to_pem(Default::default())
            .context("Failed to encode P-256 secret key for storage")?;
        fs::write(path, pem)
            .with_context(|| format!("Failed to write P-256 secret key to {path:?}"))?;

        Ok(Arc::new(key))
    }

    fn to_jwk(&self, kid: &str, key: &KeyHandle) -> Value {
        let key = key.clone().downcast::<SecretKey>().unwrap();
        let point = key.public_key().to_encoded_point(false);
        let (x, y) = match point.coordinates() {
            Coordinates::Uncompressed { x, y } => (x, y),
            _ => panic!("Could not encode P-256 coordinates"),
        };
        json!({
            "kid": kid,
            "use": "sig",
            "kty": "EC",
            "alg": "ES256",
            "crv": "P-256",
            "x": base64url(x),
            "y": base64url(y),
        })
    }

    fn create_header(&self, kid: &str, _key: &KeyHandle) -> String {
        serde_json::to_string(&json!({
            "kid": kid,
            "alg": "ES256",
        }))
        .expect("Failed to serialize JWT header")
    }

    fn sign(&self, data: &[u8], key: &KeyHandle) -> Result<Vec<u8>> {
        let key = key.clone().downcast::<SecretKey>().unwrap();

        let mut digest = sha2::Sha256::new();
        digest.update(data);

        let signature = SigningKey::from(&*key)
            .try_sign_digest(digest)
            .context("Failed to sign with P-256")?;
        Ok(signature.to_vec())
    }
}
