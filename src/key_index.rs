use serde::{Deserialize, Serialize};

/// Format of the `keys/index.json` file.
#[derive(Deserialize, Serialize)]
pub struct Top {
    pub current: Option<Entry>,
    pub next: Option<Entry>,
    #[serde(default)]
    pub old: Vec<Entry>,
}

#[derive(Deserialize, Serialize)]
pub struct Entry {
    pub id: String,
    pub expires: u64,
}
