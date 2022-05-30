use std::{
    collections::HashMap,
    iter,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};

use rsa::{PublicKeyParts, RsaPrivateKey};
use serde_json::{json, Value};

/// Internal state of the application.
pub struct Top {
    pub providers: Vec<Provider>,
}

pub struct Provider {
    pub name: String,
    pub tokens: Vec<Token>,
    pub keys_dir: PathBuf,
    pub index_path: PathBuf,
    pub key_lifespan: Duration,
    pub key_publish_margin: Duration,
    pub oidc_config_path: PathBuf,
    pub jwks_path: PathBuf,
    pub jwks_uri: String,
    pub current: Arc<KeyPair>,
    pub next: Option<Arc<KeyPair>>,
    pub old: Vec<Arc<KeyPair>>,
}

pub struct KeyPair {
    pub id: String,
    pub path: PathBuf,
    pub inner: RsaPrivateKey,
    pub expires: SystemTime,
}

pub struct Token {
    pub path: TokenPath,
    pub claims: HashMap<String, Value>,
    pub lifespan: Duration,
    pub refresh: Duration,
    pub nbf_margin: Duration,
}

pub use crate::config::TokenPath;
use crate::util::base64url;

impl Provider {
    pub fn iter_keys(&self) -> impl Iterator<Item = &KeyPair> {
        iter::once(&*self.current)
            .chain(self.next.iter().map(|key_pair| &**key_pair))
            .chain(self.old.iter().map(|key_pair| &**key_pair))
    }
}

impl KeyPair {
    pub fn to_jwk(&self) -> Value {
        json!({
            "kid": self.id,
            "use": "sig",
            "kty": "RSA",
            "alg": "RS256",
            "n": base64url(&self.inner.n().to_bytes_be()),
            "e": base64url(&self.inner.e().to_bytes_be()),
        })
    }
}
