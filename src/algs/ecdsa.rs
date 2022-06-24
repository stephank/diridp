use std::{fs, path::Path, sync::Arc};

use anyhow::{Context, Result};
use digest::Digest;
use ecdsa::{signature::DigestSigner, SigningKey};
use elliptic_curve::{
    sec1::{Coordinates, ToEncodedPoint},
    SecretKey,
};
use serde_json::{json, Map, Value};

use crate::util::base64url;

use super::{Algorithm, AlgorithmMatcher, KeyHandle};

macro_rules! define_ecdsa_alg {
    ($matcher_struct:ident, $alg_struct:ident, $curve:ty, $digest:ty, $alg:literal, $crv:literal) => {
        pub struct $matcher_struct;
        pub struct $alg_struct;

        impl AlgorithmMatcher for $matcher_struct {
            fn matches_config(&self, alg: &str, _rest: &Map<String, Value>) -> bool {
                alg == $alg
            }

            fn create_algorithm(
                &self,
                _alg: String,
                _rest: Map<String, Value>,
            ) -> Result<Box<dyn Algorithm>> {
                Ok(Box::new($alg_struct))
            }
        }

        impl Algorithm for $alg_struct {
            fn load_key_pair(&self, path: &Path) -> Result<KeyHandle> {
                let alg = $alg;
                let pem = fs::read(path)
                    .with_context(|| format!("Failed to read {alg} secret key at {path:?}"))?;
                let pem = String::from_utf8(pem)
                    .with_context(|| format!("Failed to parse {alg} secret key at {path:?} as UTF-8"))?;
                let key = SecretKey::<$curve>::from_sec1_pem(&pem)
                    .with_context(|| format!("Failed to parse {alg} secret key at {path:?}"))?;
                Ok(Arc::new(key))
            }

            fn generate(&self, path: &Path) -> Result<KeyHandle> {
                let alg = $alg;
                let key = SecretKey::<$curve>::random(&mut rand::thread_rng());
                let pem = key
                    .to_pem(Default::default())
                    .with_context(|| format!("Failed to serialize {alg} secret key"))?;
                fs::write(path, pem)
                    .with_context(|| format!("Failed to write {alg} secret key to {path:?}"))?;
                Ok(Arc::new(key))
            }

            fn to_jwk(&self, kid: &str, key: &KeyHandle) -> Value {
                let alg = $alg;
                let key = key.clone().downcast::<SecretKey<$curve>>().unwrap();
                let point = key.public_key().to_encoded_point(false);
                let (x, y) = match point.coordinates() {
                    Coordinates::Uncompressed { x, y } => (x, y),
                    _ => panic!("Could not encode {alg} public key coordinates"),
                };
                json!({
                    "kid": kid,
                    "use": "sig",
                    "kty": "EC",
                    "alg": alg,
                    "crv": $crv,
                    "x": base64url(x),
                    "y": base64url(y),
                })
            }

            fn create_header(&self, kid: &str, _key: &KeyHandle) -> String {
                serde_json::to_string(&json!({
                    "kid": kid,
                    "alg": $alg,
                }))
                .expect("Failed to serialize JWT header")
            }

            fn sign(&self, data: &[u8], key: &KeyHandle) -> Result<Vec<u8>> {
                let alg = $alg;
                let key = key.clone().downcast::<SecretKey<$curve>>().unwrap();

                let mut digest = <$digest>::new();
                digest.update(data);

                let signature = SigningKey::from(&*key)
                    .try_sign_digest(digest)
                    .with_context(|| format!("Failed to sign with {alg}"))?;
                Ok(signature.to_vec())
            }
        }
    };
}

define_ecdsa_alg!(
    Es256Matcher,
    Es256Alg,
    p256::NistP256,
    sha2::Sha256,
    "ES256",
    "P-256"
);

define_ecdsa_alg!(
    Es384Matcher,
    Es384Alg,
    p384::NistP384,
    sha2::Sha384,
    "ES384",
    "P-384"
);

define_ecdsa_alg!(
    Es256kMatcher,
    Es256kAlg,
    k256::Secp256k1,
    sha2::Sha256,
    "ES256K",
    "secp256k1"
);
