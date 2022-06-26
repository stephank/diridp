use std::{
    collections::{hash_map::Entry, HashMap},
    fmt,
    marker::PhantomData,
    path::{Component, PathBuf},
};

use serde::{
    de::{Error, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{Map, Value};

use crate::algs::{Algorithm, MATCHERS};

/// Format of the `diridp.yaml` file.
#[derive(Deserialize)]
pub struct Top {
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    #[serde(deserialize_with = "deserialize_map_or_list")]
    pub providers: HashMap<String, Provider>,
}

#[derive(Deserialize)]
pub struct Provider {
    pub issuer: String,

    pub webroot: Option<PathBuf>,
    #[serde(deserialize_with = "deserialize_web_path")]
    #[serde(default = "default_provider_jwks_path")]
    pub jwks_path: String,
    pub jwks_uri: Option<String>,

    #[serde(deserialize_with = "deserialize_map_or_list")]
    pub keys: HashMap<String, KeyChain>,

    #[serde(default)]
    pub claims: HashMap<String, Value>,

    #[serde(default)]
    pub tokens: Vec<Token>,
}

#[derive(Deserialize)]
pub struct KeyChain {
    pub dir: Option<PathBuf>,
    #[serde(default = "default_provider_key_lifespan")]
    pub lifespan: u64,
    pub publish_margin: Option<u64>,
    #[serde(flatten, deserialize_with = "deserialize_algorithm")]
    pub alg: Box<dyn Algorithm>,
}

#[derive(Deserialize)]
pub struct Token {
    pub path: TokenPath,
    pub key_name: Option<String>,
    #[serde(default = "default_token_lifespan")]
    pub lifespan: u64,
    pub refresh: Option<u64>,
    #[serde(default = "default_token_nbf_margin")]
    pub nbf_margin: u64,
    #[serde(default)]
    pub claims: HashMap<String, Value>,
}

pub enum TokenPath {
    SingleFile {
        path: PathBuf,
    },
    Directories {
        parent_dir: PathBuf,
        claim_name: String,
        filename: String,
    },
}

fn default_state_dir() -> PathBuf {
    "/var/lib/diridp".into()
}

fn default_provider_key_lifespan() -> u64 {
    86400
}

fn default_provider_jwks_path() -> String {
    "/jwks.json".into()
}

fn default_token_lifespan() -> u64 {
    3600
}

fn default_token_nbf_margin() -> u64 {
    5
}

/// Deserialize an absolute path inside the webroot, and deny special components.
fn deserialize_web_path<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let path = PathBuf::deserialize(deserializer)?;
    let mut parts = path.components();
    if parts.next() != Some(Component::RootDir) {
        return Err(D::Error::custom(
            "path must be an absolute path inside the webroot",
        ));
    }
    for part in parts {
        if !matches!(part, Component::Normal(_)) {
            return Err(D::Error::custom(
                "path must not contain relative components",
            ));
        }
    }
    let path = path
        .to_str()
        .ok_or_else(|| D::Error::custom("path must be valid UTF-8"))?;
    Ok(path.to_string())
}

impl<'de> Deserialize<'de> for TokenPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let path = PathBuf::deserialize(deserializer)?;
        let parts: Vec<_> = path
            .components()
            .map(|part| part.as_os_str().to_string_lossy().into_owned())
            .collect();

        let mut indices = parts
            .iter()
            .enumerate()
            .filter(|(_, part)| part.starts_with(':'))
            .map(|(idx, _)| idx);
        if let Some(idx) = indices.next() {
            let expect_idx = parts.len() - 2;
            if idx != expect_idx || indices.next().is_some() {
                return Err(D::Error::custom(
                    "only one parameter, in the next-to-last position, is supported",
                ));
            }

            Ok(TokenPath::Directories {
                parent_dir: parts[..idx].iter().collect(),
                claim_name: parts[idx][1..].to_string(),
                filename: parts.last().unwrap().to_string(),
            })
        } else {
            Ok(TokenPath::SingleFile { path })
        }
    }
}

fn deserialize_algorithm<'de, D>(deserializer: D) -> Result<Box<dyn Algorithm>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct AlgConfig {
        alg: String,
        #[serde(flatten)]
        rest: Map<String, Value>,
    }
    let config = AlgConfig::deserialize(deserializer)?;

    let matched = MATCHERS
        .iter()
        .find(|matcher| matcher.matches_config(&config.alg, &config.rest))
        .ok_or_else(|| D::Error::custom("did not match any algorithm implementation"))?;

    matched
        .create_algorithm(config.alg, config.rest)
        .map_err(D::Error::custom)
}

/// Provides a default name for the list case in `deserialize_map_or_list`.
trait DefaultName {
    fn default_name(&self) -> String;
}

impl DefaultName for Provider {
    fn default_name(&self) -> String {
        crate::util::issuer_slug(&self.issuer)
    }
}

impl DefaultName for KeyChain {
    fn default_name(&self) -> String {
        self.alg.alg().into()
    }
}

/// Accept either a map or list, and decode either to a map.
///
/// When a list is found, the DefaultName trait is used to determine keys in the map.
fn deserialize_map_or_list<'de, D, T>(deserializer: D) -> Result<HashMap<String, T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + DefaultName,
{
    struct MapOrListVisitor<T> {
        _phantom: PhantomData<T>,
    }

    impl<'de, T> Visitor<'de> for MapOrListVisitor<T>
    where
        T: Deserialize<'de> + DefaultName,
    {
        type Value = HashMap<String, T>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a map or list")
        }

        fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut map = HashMap::with_capacity(access.size_hint().unwrap_or(0));
            while let Some((key, value)) = access.next_entry()? {
                match map.entry(key) {
                    Entry::Vacant(entry) => {
                        entry.insert(value);
                    }
                    Entry::Occupied(entry) => {
                        return Err(A::Error::custom(format!("duplicate key `{}`", entry.key())))
                    }
                }
            }
            Ok(map)
        }

        fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut map = HashMap::with_capacity(access.size_hint().unwrap_or(0));
            while let Some(value) = access.next_element::<T>()? {
                let key = value.default_name();
                match map.entry(key) {
                    Entry::Vacant(entry) => {
                        entry.insert(value);
                    }
                    Entry::Occupied(entry) => {
                        return Err(A::Error::custom(format!("duplicate key `{}`", entry.key())))
                    }
                }
            }
            Ok(map)
        }
    }

    deserializer.deserialize_any(MapOrListVisitor {
        _phantom: PhantomData,
    })
}
