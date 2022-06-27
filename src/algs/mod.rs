#[cfg(feature = "rsa")]
mod rsa;

#[cfg(feature = "ring")]
mod ring_ecdsa;
#[cfg(feature = "ring")]
mod ring_ed25519;

#[cfg(feature = "rustcrypto")]
mod rustcrypto_ecdsa;
#[cfg(feature = "rustcrypto")]
mod rustcrypto_ed25519;

use std::{any::Any, path::Path, sync::Arc};

use anyhow::Result;
use serde_json::{Map, Value};

#[cfg(feature = "rsa")]
pub use self::rsa::*;

#[cfg(feature = "ring")]
pub use self::ring_ecdsa::*;
#[cfg(feature = "ring")]
pub use self::ring_ed25519::*;

#[cfg(feature = "rustcrypto")]
pub use self::rustcrypto_ecdsa::*;
#[cfg(feature = "rustcrypto")]
pub use self::rustcrypto_ed25519::*;

/// Trait object used to find the correct algorithm matching a key configuration.
pub trait AlgorithmMatcher {
    /// Check if the given key configuration matches this algorithm.
    fn matches_config(&self, alg: &str, rest: &Map<String, Value>) -> bool;

    /// Create the Algorithm impl from key configuration.
    fn create_algorithm(&self, alg: String, rest: Map<String, Value>)
        -> Result<Box<dyn Algorithm>>;
}

/// Trait object that holds algorithm parameters and implements algorithm details.
pub trait Algorithm: Send + Sync {
    /// Return the JWS `alg` value.
    fn alg(&self) -> &str;

    /// Load an existing key pair from a file based on the index entry.
    fn load_key_pair(&self, path: &Path) -> Result<KeyHandle>;

    /// Generate a new key pair and write it to a file.
    fn generate(&self, path: &Path) -> Result<KeyHandle>;

    /// Serialize a key to JWK format.
    fn to_jwk(&self, kid: &str, key: &KeyHandle) -> Value;

    /// Sign data using the given key.
    fn sign(&self, data: &[u8], key: &KeyHandle) -> Result<Vec<u8>>;
}

/// Handle to a key.
pub type KeyHandle = Arc<dyn Any + Send + Sync>;

/// List of all AlgorithmMatchers.
pub const MATCHERS: &[&dyn AlgorithmMatcher] = &[
    #[cfg(feature = "rsa")]
    &RsaMatcher,
    #[cfg(feature = "ring")]
    &EcdsaMatcher,
    #[cfg(feature = "rustcrypto")]
    &Es256Matcher,
    #[cfg(feature = "rustcrypto")]
    &Es384Matcher,
    #[cfg(feature = "rustcrypto")]
    &Es256kMatcher,
    #[cfg(any(feature = "ring", feature = "rustcrypto"))]
    &Ed25519Matcher,
];
