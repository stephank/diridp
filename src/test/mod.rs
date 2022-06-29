use std::{fs, sync::atomic::Ordering};

use anyhow::{ensure, Context, Result};

use crate::log;

fn run_alg_test(alg: &str, extra: Option<&str>) -> Result<()> {
    log::LEVEL.store(log::LEVEL_DEBUG, Ordering::Relaxed);

    let work_dir = tempfile::tempdir().context("Failed to create tempdir")?;
    let config_path = {
        let mut path = work_dir.path().to_path_buf();
        path.push("diridp.yaml");
        path
    };
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
        path.push("example.com");
        path.push("webroot");
        path.push("jwks.json");
        path
    };
    let key_index_path = {
        let mut path = state_dir.clone();
        path.push("example.com");
        path.push("keys");
        path.push(alg);
        path.push("index.json");
        path
    };

    let key_config = if let Some(extra) = extra {
        format!("{{ alg: {alg}, {extra} }}")
    } else {
        format!("{{ alg: {alg} }}")
    };
    fs::write(
        &config_path,
        format!(
            "\
state_dir: {state_dir:?}
providers:
  - issuer: 'https://example.com'
    keys:
      - {key_config}
    tokens:
      - path: {token_path:?}
        claims:
          aud: test-suite
"
        ),
    )
    .context("Failed to write config")?;

    // This is equivalent to a single update (`--once`).
    let mut next_keys_check = None;
    let mut next_tokens_check = None;
    let cfg = crate::read_config(&config_path)?;
    crate::init_state(cfg, &mut None, &mut next_keys_check, &mut next_tokens_check)?;

    // Tests against a foreign implementation.
    let status = std::process::Command::new("./src/test/helper/main.js")
        .arg(&token_path)
        .arg(&jwks_path)
        .status()?;
    ensure!(status.success(), "Verification helper failed");

    // Perform another update to test reloading, and ensure keys were not changed.
    let key_index_before =
        fs::read(&key_index_path).context("Failed to read key index (before check)")?;

    let mut next_keys_check = None;
    let mut next_tokens_check = None;
    let cfg = crate::read_config(&config_path)?;
    crate::init_state(cfg, &mut None, &mut next_keys_check, &mut next_tokens_check)?;

    let key_index_after =
        fs::read(&key_index_path).context("Failed to read key index (before check)")?;
    ensure!(
        key_index_before == key_index_after,
        "Keys unexpectedly changed after reload"
    );

    Ok(())
}

#[cfg(feature = "rsa")]
#[test]
fn rs256() -> Result<()> {
    run_alg_test("RS256", None)
}

#[cfg(feature = "rsa")]
#[test]
fn rs384() -> Result<()> {
    run_alg_test("RS384", None)
}

#[cfg(feature = "rsa")]
#[test]
fn rs512() -> Result<()> {
    run_alg_test("RS512", None)
}

#[cfg(feature = "rsa")]
#[test]
fn ps256() -> Result<()> {
    run_alg_test("PS256", None)
}

#[cfg(feature = "rsa")]
#[test]
fn ps384() -> Result<()> {
    run_alg_test("PS384", None)
}

#[cfg(feature = "rsa")]
#[test]
fn ps512() -> Result<()> {
    run_alg_test("PS512", None)
}

#[cfg(any(feature = "ring", feature = "rustcrypto"))]
#[test]
fn es256() -> Result<()> {
    run_alg_test("ES256", None)
}

#[cfg(any(feature = "ring", feature = "rustcrypto"))]
#[test]
fn es384() -> Result<()> {
    run_alg_test("ES384", None)
}

#[cfg(feature = "rustcrypto")]
#[test]
fn es256k() -> Result<()> {
    run_alg_test("ES256K", None)
}

#[cfg(any(feature = "ring", feature = "rustcrypto"))]
#[test]
fn ed25519() -> Result<()> {
    run_alg_test("EdDSA", Some("crv: Ed25519"))
}
