use std::{fs, sync::atomic::Ordering};

use anyhow::{ensure, Context, Result};

use crate::log;

fn run_alg_test(alg: String) -> Result<()> {
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

    fs::write(
        &config_path,
        format!(
            "\
state_dir: {state_dir:?}
providers:
  - issuer: 'https://example.com'
    keys:
      - {alg}
    tokens:
      - path: {token_path:?}
        claims:
          aud: test-suite
"
        ),
    )
    .context("Failed to write config")?;

    let mut next_keys_check = None;
    let mut next_tokens_check = None;
    let cfg = crate::read_config(&config_path)?;
    crate::init_state(cfg, &mut None, &mut next_keys_check, &mut next_tokens_check)?;

    let status = std::process::Command::new("./src/test/helper/main.js")
        .arg(&token_path)
        .arg(&jwks_path)
        .status()?;
    ensure!(status.success(), "Verification helper failed");

    Ok(())
}

#[cfg(feature = "rsa")]
#[test]
fn rs256() -> Result<()> {
    run_alg_test("{ alg: RS256 }".into())
}

#[cfg(feature = "rsa")]
#[test]
fn rs384() -> Result<()> {
    run_alg_test("{ alg: RS384 }".into())
}

#[cfg(feature = "rsa")]
#[test]
fn rs512() -> Result<()> {
    run_alg_test("{ alg: RS512 }".into())
}

#[cfg(feature = "rsa")]
#[test]
fn ps256() -> Result<()> {
    run_alg_test("{ alg: PS256 }".into())
}

#[cfg(feature = "rsa")]
#[test]
fn ps384() -> Result<()> {
    run_alg_test("{ alg: PS384 }".into())
}

#[cfg(feature = "rsa")]
#[test]
fn ps512() -> Result<()> {
    run_alg_test("{ alg: PS512 }".into())
}

#[cfg(any(feature = "ring", feature = "rustcrypto"))]
#[test]
fn es256() -> Result<()> {
    run_alg_test("{ alg: ES256 }".into())
}

#[cfg(any(feature = "ring", feature = "rustcrypto"))]
#[test]
fn es384() -> Result<()> {
    run_alg_test("{ alg: ES384 }".into())
}

#[cfg(feature = "rustcrypto")]
#[test]
fn es256k() -> Result<()> {
    run_alg_test("{ alg: ES256K }".into())
}

#[cfg(any(feature = "ring", feature = "rustcrypto"))]
#[test]
fn ed25519() -> Result<()> {
    run_alg_test("{ alg: EdDSA, crv: Ed25519 }".into())
}
