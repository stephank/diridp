use std::{
    cmp::min,
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};

use anyhow::{Context, Result};
use rand::Rng;
use serde_json::json;

use crate::{
    algs::Algorithm,
    key_index, log, state,
    util::{atomic_write, min_opt, unix_time},
};

/// Check if any provider signing keys need to be rotated.
pub fn check(state: &mut state::Top, next_check: &mut Option<SystemTime>) {
    *next_check = None;
    for provider in &mut state.providers {
        let mut keys_changed = false;
        for key_chain in provider.keys.values_mut() {
            if let Err(err) =
                check_key_chain(&provider.name, key_chain, &mut keys_changed, next_check)
            {
                log::error!(
                    "Failed to update key '{}' / '{}': {}",
                    provider.name,
                    key_chain.name,
                    err
                );
            }
        }

        if keys_changed {
            if let Err(err) = write_jwks(provider) {
                log::error!(
                    "Failed to write JWKs document {:?}: {}",
                    provider.jwks_path,
                    err,
                );
            }
        }
    }
}

/// Check if a provider's signing keys need to be rotated.
/// Returns the next update time.
pub fn check_key_chain(
    provider_name: &str,
    key_chain: &mut state::KeyChain,
    keys_changed: &mut bool,
    next_check: &mut Option<SystemTime>,
) -> Result<()> {
    let now = SystemTime::now();

    // Remove an expired next key first, to simplify remaining checks.
    // This can happen if we load a very old state.
    if key_chain
        .next
        .as_ref()
        .filter(|key_chain| now > key_chain.expires)
        .is_some()
    {
        // Possibly cleaned up later on.
        key_chain.old.push(key_chain.next.take().unwrap());
        *keys_changed = true;
    }

    // Replace an expired current key.
    if now > key_chain.current.expires {
        // Possibly cleaned up later on, if very old.
        key_chain.old.push(key_chain.current.clone());

        if let Some(next) = key_chain.next.take() {
            key_chain.current = next;
            log::info!(
                "Rotated '{}' / '{}' current key to '{}'",
                provider_name,
                key_chain.name,
                key_chain.current.id,
            );
        } else {
            key_chain.current = Arc::new(generate(
                "current",
                provider_name,
                &key_chain.name,
                &*key_chain.alg,
                &key_chain.keys_dir,
                now + key_chain.lifespan,
            )?);
        }

        *keys_changed = true;
    }

    // Check if we need to generate a new next key.
    if key_chain.next.is_none() && now > (key_chain.current.expires - key_chain.publish_margin) {
        key_chain.next = Some(Arc::new(generate(
            "next",
            provider_name,
            &key_chain.name,
            &*key_chain.alg,
            &key_chain.keys_dir,
            // Relative to the expiry of our current key pair.
            key_chain.current.expires + key_chain.lifespan,
        )?));

        *keys_changed = true;
    }

    // Truncate old keys.
    let cutoff = now - key_chain.publish_margin;
    key_chain.old.retain(|key_pair| {
        if key_pair.expires > cutoff {
            true
        } else {
            let path = &key_pair.path;
            if let Err(err) = fs::remove_file(path) {
                if err.kind() != ErrorKind::NotFound {
                    log::warning!("Failed to delete old key pair {path:?}: {err}");
                }
            } else {
                log::info!(
                    "Deleted old key pair '{}' / '{}' / '{}'",
                    provider_name,
                    key_chain.name,
                    key_pair.id,
                );
            }
            *keys_changed = true;
            false
        }
    });

    // Write new index. Use atomic write, so if we are interrupted at an unfortunate moment, at
    // most we have some lingering key files that will be unused.
    fn make_index_entry(key_pair: &Arc<state::KeyPair>) -> key_index::Entry {
        key_index::Entry {
            id: key_pair.id.clone(),
            expires: unix_time(key_pair.expires),
        }
    }
    let index = serde_json::to_vec(&key_index::Top {
        current: Some(make_index_entry(&key_chain.current)),
        next: key_chain.next.as_ref().map(make_index_entry),
        old: key_chain.old.iter().map(make_index_entry).collect(),
    })
    .expect("Failed to serialize key index");
    atomic_write(&key_chain.index_path, &index)
        .with_context(|| format!("Failed to write index file {:?}", key_chain.index_path))?;
    log::debug!("Wrote index file {:?}", key_chain.index_path);

    // Determine next check time.
    min_opt(next_check, {
        let mut next_check = key_chain.current.expires;
        if key_chain.next.is_none() {
            next_check -= key_chain.publish_margin;
        }
        key_chain.old.iter().fold(next_check, |acc, key_pair| {
            min(acc, key_pair.expires + key_chain.publish_margin)
        })
    });

    Ok(())
}

// Write the JWKs JSON for a provider.
pub fn write_jwks(provider: &state::Provider) -> Result<()> {
    // Use atomic write, because a webserver may be serving these.
    let jwks: Vec<_> = provider
        .keys
        .values()
        .flat_map(|key_chain| key_chain.iter().map(|key| key.to_jwk(&*key_chain.alg)))
        .collect();

    atomic_write(
        &provider.jwks_path,
        serde_json::to_string_pretty(&json!({ "keys": jwks }))
            .expect("Failed to serialize JWKs document")
            .as_bytes(),
    )?;
    log::debug!("Wrote JWKs document {:?}", provider.jwks_path);

    Ok(())
}

/// Generate a new key pair and write it to a file.
pub fn generate(
    purpose: &str,
    provider_name: &str,
    key_name: &str,
    alg: &dyn Algorithm,
    keys_dir: &Path,
    expires: SystemTime,
) -> Result<state::KeyPair> {
    let mut rng = rand::thread_rng();
    let id = {
        let bytes: [u8; 8] = rng.gen();
        format!("{:x}", u64::from_be_bytes(bytes))
    };

    let path = path_for_key_id(keys_dir, &id);
    let inner = alg.generate(&path)?;

    log::info!(
        "Generated new key pair '{}' / '{}' / '{}' ({})",
        provider_name,
        key_name,
        id,
        purpose
    );

    Ok(state::KeyPair {
        id,
        path,
        inner,
        expires,
    })
}

pub fn path_for_key_id(keys_dir: &Path, kid: &str) -> PathBuf {
    let mut path = keys_dir.to_path_buf();
    path.push(format!("key-{}.pem", kid));
    path
}
