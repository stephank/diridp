mod ecdsa;
mod ed25519;
mod rsa;

use std::{any::Any, path::Path, sync::Arc};

use anyhow::Result;
use serde_json::{Map, Value};

pub use self::ecdsa::*;
pub use self::ed25519::*;
pub use self::rsa::*;

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
    /// Load an existing key pair from a file based on the index entry.
    fn load_key_pair(&self, path: &Path) -> Result<KeyHandle>;

    /// Generate a new key pair and write it to a file.
    fn generate(&self, path: &Path) -> Result<KeyHandle>;

    /// Serialize a key to JWK format.
    fn to_jwk(&self, kid: &str, key: &KeyHandle) -> Value;

    /// Build a header for a JWT with the given key ID.
    fn create_header(&self, kid: &str, key: &KeyHandle) -> String;

    /// Sign data using the given key.
    fn sign(&self, data: &[u8], key: &KeyHandle) -> Result<Vec<u8>>;
}

/// Handle to a key.
pub type KeyHandle = Arc<dyn Any + Send + Sync>;

/// List of all AlgorithmMatchers.
pub const MATCHERS: &[&dyn AlgorithmMatcher] =
    &[&Es256Matcher, &Es384Matcher, &Ed25519Matcher, &RsaMatcher];
