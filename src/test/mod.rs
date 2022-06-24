use std::{collections::HashMap, sync::atomic::Ordering};

use anyhow::{ensure, Context, Result};

use crate::{algs, config, log};

#[test]
fn test_rsa() -> Result<()> {
    log::LEVEL.store(log::LEVEL_DEBUG, Ordering::Relaxed);

    let work_dir = tempfile::tempdir().context("Failed to create tempdir")?;
    let state_dir = {
        let mut path = work_dir.path().to_path_buf();
        path.push("state");
        path
    };
    let token_path = {
        let mut path = work_dir.path().to_path_buf();
        path.push("token");
        path
    };
    let jwks_path = {
        let mut path = state_dir.clone();
        path.push("main");
        path.push("webroot");
        path.push("jwks.json");
        path
    };

    let mut cfg = config::Top {
        state_dir,
        providers: HashMap::with_capacity(1),
    };
    let mut provider = config::Provider {
        issuer: "https://example.com".into(),
        webroot: None,
        jwks_path: "/jwks.json".into(),
        jwks_uri: None,
        keys: HashMap::with_capacity(1),
        claims: HashMap::new(),
        tokens: Vec::with_capacity(1),
    };
    let key_chain = config::KeyChain {
        dir: None,
        lifespan: 86400,
        publish_margin: None,
        alg: Box::new(algs::RsaAlg { key_size: 2048 }),
    };
    let mut token = config::Token {
        path: config::TokenPath::SingleFile {
            path: token_path.clone(),
        },
        key_name: None,
        lifespan: 3600,
        refresh: None,
        nbf_margin: 5,
        claims: HashMap::with_capacity(1),
    };
    token.claims.insert("aud".into(), "test-suite".into());
    provider.keys.insert("main".into(), key_chain);
    provider.tokens.push(token);
    cfg.providers.insert("main".into(), provider);

    let mut next_keys_check = None;
    let mut next_tokens_check = None;
    crate::init_state(cfg, &mut None, &mut next_keys_check, &mut next_tokens_check)
        .context("Failed to init state")?;

    let status = std::process::Command::new("./src/test/helper/main.js")
        .arg(&token_path)
        .arg(&jwks_path)
        .status()?;
    ensure!(status.success(), "Verification helper failed");

    Ok(())
}
