use std::{
    collections::HashMap,
    iter,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};

use serde_json::Value;

use crate::algs::{Algorithm, KeyHandle};

/// Internal state of the application.
pub struct Top {
    pub providers: Vec<Provider>,
}

pub struct Provider {
    pub name: String,
    pub oidc_config_path: PathBuf,
    pub jwks_path: PathBuf,
    pub jwks_uri: String,
    pub keys: HashMap<String, KeyChain>,
    pub tokens: Vec<Token>,
}

pub struct KeyChain {
    pub name: String,
    pub keys_dir: PathBuf,
    pub index_path: PathBuf,
    pub lifespan: Duration,
    pub publish_margin: Duration,
    pub alg: Box<dyn Algorithm>,
    pub current: Arc<KeyPair>,
    pub next: Option<Arc<KeyPair>>,
    pub old: Vec<Arc<KeyPair>>,
}

pub struct KeyPair {
    pub id: String,
    pub path: PathBuf,
    pub expires: SystemTime,
    pub inner: KeyHandle,
}

pub struct Token {
    pub path: TokenPath,
    pub key_name: String,
    pub lifespan: Duration,
    pub refresh: Duration,
    pub nbf_margin: Duration,
    pub claims: HashMap<String, Value>,
}

pub use crate::config::TokenPath;

impl KeyChain {
    pub fn iter(&self) -> impl Iterator<Item = &KeyPair> {
        iter::once(&*self.current)
            .chain(self.next.iter().map(|key_pair| &**key_pair))
            .chain(self.old.iter().map(|key_pair| &**key_pair))
    }
}

impl KeyPair {
    #[inline]
    pub fn to_jwk(&self, alg: &dyn Algorithm) -> Value {
        alg.to_jwk(&self.id, &self.inner)
    }
}
