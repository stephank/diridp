use std::{
    collections::HashMap,
    fs,
    io::ErrorKind,
    path::Path,
    time::{Duration, Instant, SystemTime},
};

use anyhow::{Context, Error, Result};
use digest::Digest;
use rsa::Hash;
use serde::Serialize;
use serde_json::Value;

use crate::{
    log, state,
    util::{atomic_write, base64url, min_opt, unix_time},
};

/// Check if any tokens need to be refreshed.
///
/// The`filter_parent_dir` parameter allows limiting the check to just a single directory. The
/// `next_check` parameter is filled with the next time to call `check`.
pub fn check(
    state: &state::Top,
    next_check: &mut Option<Instant>,
    filter_parent_dir: Option<&Path>,
) {
    match filter_parent_dir {
        Some(dir) => {
            log::debug!("Checking tokens in: {dir:?}");
        }
        None => {
            log::debug!("Checking all tokens");
            // On a timer event, we need to determine our next timeout from scratch. (Or we'll go
            // in a busy loop because we're stuck at zero.)
            *next_check = None;
        }
    }

    for provider in &state.providers {
        for token in &provider.tokens {
            match token.path {
                state::TokenPath::SingleFile { ref path } => {
                    // If filtering on configs that involve a certain parent directory, single-file
                    // tokens will never match.
                    if filter_parent_dir.is_some() {
                        continue;
                    }

                    if let Err(err) =
                        check_token(path, provider, token, next_check, || token.claims.clone())
                    {
                        log::error!("Failed to check token {path:?}: {err}");
                    }
                }
                state::TokenPath::Directories {
                    ref parent_dir,
                    ref claim_name,
                    ref filename,
                } => {
                    // If filtering on configs that involve a certain parent directory, make sure
                    // this one matches before we go ahead.
                    if let Some(filter_parent_dir) = filter_parent_dir {
                        if parent_dir != filter_parent_dir {
                            continue;
                        }
                    }

                    // Scan subdirectories to find tokens that need an update.
                    let iter = match fs::read_dir(parent_dir) {
                        Ok(iter) => iter,
                        Err(err) => {
                            log::error!("Could not read directory {parent_dir:?}: {err}");
                            continue;
                        }
                    };

                    for entry in iter {
                        let entry = match entry {
                            Ok(entry) => entry,
                            Err(err) => {
                                log::error!("Could not iterate directory {parent_dir:?}: {err}");
                                break;
                            }
                        };

                        let token_dir = entry.path();
                        let meta = match entry.metadata() {
                            Ok(meta) => meta,
                            Err(err) => {
                                log::warning!(
                                    "Could not stat directory entry {token_dir:?}: {err}"
                                );
                                continue;
                            }
                        };

                        if meta.is_dir() {
                            let mut token_file = token_dir.clone();
                            token_file.push(filename);

                            if let Err(err) =
                                check_token(&token_file, provider, token, next_check, || {
                                    let claim_value = token_dir
                                        .file_name()
                                        .unwrap()
                                        .to_string_lossy()
                                        .into_owned();

                                    let mut claims = token.claims.clone();
                                    claims.insert(claim_name.clone(), Value::String(claim_value));
                                    claims
                                })
                            {
                                log::error!("Failed to check token {token_file:?}: {err}");
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Check if a token needs to be refreshed.
fn check_token<F>(
    token_file: &Path,
    provider: &state::Provider,
    token: &state::Token,
    next_check: &mut Option<Instant>,
    claims_fn: F,
) -> Result<()>
where
    F: FnOnce() -> HashMap<String, Value>,
{
    // Check if a token exists and it has not yet expired.
    let now_instant = Instant::now();
    let now = SystemTime::now();
    match fs::metadata(&token_file) {
        Ok(meta) => {
            let age = now
                .duration_since(meta.created().with_context(|| {
                    format!("Modification time not available for {token_file:?}")
                })?)
                .unwrap_or(Duration::ZERO);
            if age < token.refresh {
                // Expires in the future. Update our timer if necessary.
                min_opt(next_check, now_instant + (token.refresh - age));
                return Ok(());
            }
            log::info!("Updating token: {token_file:?}");
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            log::info!("Creating new token: {token_file:?}");
        }
        Err(err) => {
            return Err(Error::new(err).context(format!("Could not stat token {token_file:?}")))
        }
    }

    let key_pair = provider.current.clone();

    // Build the JWT.
    #[derive(Serialize)]
    struct Header<'a> {
        kid: &'a str,
        alg: &'a str,
    }
    let header = serde_json::to_string(&Header {
        kid: &key_pair.id,
        alg: "RS256",
    })
    .expect("Failed to serialize JWT header");

    let mut payload = claims_fn();
    payload.insert("iat".to_string(), unix_time(now).into());
    payload.insert("exp".to_string(), unix_time(now + token.lifespan).into());
    payload.insert("nbf".to_string(), unix_time(now - token.nbf_margin).into());
    let payload = serde_json::to_string(&payload).expect("Failed to serialize JWT payload");

    let mut data = String::new();
    data.push_str(&base64url(header.as_bytes()));
    data.push('.');
    data.push_str(&base64url(payload.as_bytes()));
    let sig = key_pair
        .inner
        .sign(
            rsa::PaddingScheme::PKCS1v15Sign {
                hash: Some(Hash::SHA2_256),
            },
            &sha2::Sha256::digest(data.as_bytes()),
        )
        .context("Failed to sign JWT")?;
    data.push('.');
    data.push_str(&base64url(&sig));

    // Use atomic write, because the intention is for other processes to read these.
    atomic_write(token_file, data.as_bytes())?;

    // Update our timer for the new expiry time, if necessary.
    min_opt(next_check, now_instant + token.refresh);

    Ok(())
}
