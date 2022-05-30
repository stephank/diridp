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
use rsa::{pkcs8::EncodePrivateKey, RsaPrivateKey};
use serde_json::json;

use crate::{
    key_index, log, state,
    util::{atomic_write, min_opt, unix_time},
};

/// Check if any provider signing keys need to be rotated.
pub fn check(state: &mut state::Top, next_check: &mut Option<SystemTime>) {
    *next_check = None;
    for provider in &mut state.providers {
        match check_provider(provider) {
            Ok(time) => min_opt(next_check, time),
            Err(err) => {
                log::error!("Failed to update provider '{}': {}", provider.name, err);
            }
        }
    }
}

/// Check if a provider's signing keys need to be rotated.
/// Returns the next update time.
pub fn check_provider(provider: &mut state::Provider) -> Result<SystemTime> {
    let now = SystemTime::now();

    // Remove an expired next key first, to simplify remaining checks.
    // This can happen if we load a very old state.
    if provider
        .next
        .as_ref()
        .filter(|key_chain| now > key_chain.expires)
        .is_some()
    {
        // Possibly cleaned up later on.
        provider.old.push(provider.next.take().unwrap());
    }

    // Replace an expired current key.
    if now > provider.current.expires {
        // Possibly cleaned up later on, if very old.
        provider.old.push(provider.current.clone());

        if let Some(next) = provider.next.take() {
            provider.current = next;
            log::info!(
                "Rotated current key to '{}' for provider '{}'",
                provider.current.id,
                provider.name
            );
        } else {
            provider.current = Arc::new(generate(
                "current",
                &provider.name,
                &provider.keys_dir,
                now + provider.key_lifespan,
            )?);
        }
    }

    // Check if we need to generate a new next key.
    if provider.next.is_none() && now > (provider.current.expires - provider.key_publish_margin) {
        provider.next = Some(Arc::new(generate(
            "next",
            &provider.name,
            &provider.keys_dir,
            // Relative to the expiry of our current key pair.
            provider.current.expires + provider.key_lifespan,
        )?));
    }

    // Truncate old keys.
    let cutoff = now - provider.key_publish_margin;
    provider.old.retain(|key_pair| {
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
                    "Deleted old key '{}' for provider '{}'",
                    key_pair.id,
                    provider.name
                );
            }
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
        current: Some(make_index_entry(&provider.current)),
        next: provider.next.as_ref().map(make_index_entry),
        old: provider.old.iter().map(make_index_entry).collect(),
    })
    .expect("Failed to serialize key index");
    atomic_write(&provider.index_path, &index)
        .with_context(|| format!("Failed to write index file {:?}", provider.index_path))?;
    log::debug!("Wrote index file {:?}", provider.index_path);

    // Write JWKs. Use atomic write, because a webserver may be serving these.
    let jwks: Vec<_> = provider.iter_keys().map(state::KeyPair::to_jwk).collect();
    atomic_write(
        &provider.jwks_path,
        serde_json::to_string_pretty(&json!({ "keys": jwks }))
            .expect("Failed to serialize JWKs document")
            .as_bytes(),
    )
    .with_context(|| format!("Failed to write JWKs document {:?}", provider.jwks_path))?;
    log::debug!("Wrote JWKs document {:?}", provider.jwks_path);

    // Determine next check time.
    let mut next_check = provider.current.expires;
    if provider.next.is_none() {
        next_check -= provider.key_publish_margin;
    }
    Ok(provider.old.iter().fold(next_check, |acc, key_pair| {
        min(acc, key_pair.expires + provider.key_publish_margin)
    }))
}

/// Generate a new key pair and write it to a file.
pub fn generate(
    purpose: &str,
    provider_name: &str,
    keys_dir: &Path,
    expires: SystemTime,
) -> Result<state::KeyPair> {
    let mut rng = rand::thread_rng();

    let inner = RsaPrivateKey::new(&mut rng, 2048).context("Failed to generate RSA key pair")?;
    let id = {
        let bytes: [u8; 8] = rng.gen();
        format!("{:x}", u64::from_be_bytes(bytes))
    };

    let path = path_for_key_id(keys_dir, &id);
    inner
        .write_pkcs8_pem_file(&path, Default::default())
        .with_context(|| format!("Failed to write RSA key pair to {path:?}"))?;

    log::info!("Generated new RSA key pair '{id}', {purpose} key for provider '{provider_name}'");

    Ok(state::KeyPair {
        id,
        path,
        inner,
        expires,
    })
}

/// Build the file path for a key pair.
pub fn path_for_key_id(keys_dir: &Path, id: &str) -> PathBuf {
    let mut path = keys_dir.to_path_buf();
    path.push(format!("key-{id}.pem"));
    path
}
