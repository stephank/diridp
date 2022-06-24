#![forbid(unsafe_code)]

mod algs;
mod config;
mod key_index;
mod log;
mod state;
mod update_keys;
mod update_tokens;
mod util;

#[cfg(test)]
mod test;

use std::{
    fs::{self, Permissions},
    io::ErrorKind,
    os::unix::prelude::PermissionsExt,
    path::{Path, PathBuf},
    sync::{
        atomic::Ordering,
        mpsc::{self, RecvTimeoutError},
        Arc, RwLock,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use algs::Algorithm;
use anyhow::{bail, ensure, Context, Result};
use clap::Parser;
use notify::{RecommendedWatcher, Watcher};
use serde_json::json;
use update_keys::path_for_key_id;
use util::atomic_write;

#[derive(Parser)]
#[clap(about, version)]
struct Args {
    /// Config file.
    config: PathBuf,
    /// Perform a single update, then exit.
    #[clap(short, long)]
    once: bool,
    /// Enable verbose logging.
    #[clap(short, long)]
    verbose: bool,
    /// Enable debug logging. Implies `--verbose`.
    #[clap(short, long)]
    debug: bool,
    /// Add a syslog prefix to stderr output.
    #[clap(short, long)]
    syslog: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Apply logging settings.
    if args.debug {
        log::LEVEL.store(log::LEVEL_DEBUG, Ordering::Relaxed);
    } else if args.verbose {
        log::LEVEL.store(log::LEVEL_INFO, Ordering::Relaxed);
    }
    if args.syslog {
        log::FMT_SYSLOG.store(true, Ordering::Relaxed);
    }

    // Watcher used to watch directories when token paths contain parameters. The watcher is an
    // Option so we can skip creating it when `--once` is specified. This prevents allocating
    // resources and maybe even helps diridp function when those resources are restricted.
    let (tx, rx) = mpsc::channel();
    let mut watcher = (!args.once)
        .then(|| notify::recommended_watcher(tx).context("Failed to create watcher"))
        .transpose()?;

    // Sleep timers for loops.
    let mut next_keys_check = None;
    let mut next_tokens_check = None;

    // Build initial state from config.
    let cfg =
        fs::read(&args.config).with_context(|| format!("Failed to read {:?}", args.config))?;
    let cfg: config::Top = serde_yaml::from_slice(&cfg)
        .with_context(|| format!("Failed to parse {:?}", args.config))?;
    let state = Arc::new(RwLock::new(init_state(
        cfg,
        &mut watcher,
        &mut next_keys_check,
        &mut next_tokens_check,
    )?));

    // Exit success here if `--once` was specified.
    if args.once {
        log::info!("Diridp update complete");
        std::process::exit(0);
    }

    // Start a thread to update keys periodically.
    thread::Builder::new().name("update_keys".into()).spawn({
        let state = state.clone();
        move || loop {
            let sleep_dur = match next_keys_check {
                Some(next) => next
                    .duration_since(SystemTime::now())
                    .unwrap_or(Duration::ZERO),
                None => {
                    // This only happens if there are no providers configured at all.
                    return;
                }
            };
            log::debug!("Next keys check in {:?}", sleep_dur);
            thread::sleep(sleep_dur);
            update_keys::check(&mut *state.write().unwrap(), &mut next_keys_check);
        }
    })?;

    log::info!("Diridp is running");

    // Main event loop.
    loop {
        // Wait for the watcher or the next timeout.
        let res = match next_tokens_check {
            Some(deadline) => {
                let timeout = deadline.saturating_duration_since(Instant::now());
                log::debug!("Watching tokens for {timeout:?}");
                rx.recv_timeout(timeout)
            }
            None => {
                log::debug!("Watching tokens indefinitely");
                rx.recv().map_err(|e| e.into())
            }
        };
        let event = match res {
            Ok(event) => event?,
            Err(RecvTimeoutError::Timeout) => {
                // We currently don't track what is associated with the timer event, so just
                // recheck everything.
                update_tokens::check(&*state.read().unwrap(), &mut next_tokens_check, None);
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => {
                bail!("Watch channel disconnected");
            }
        };

        // We only care about the user creating subdirectories of one of our watched parent
        // directories. Only act on events that involve a subdirectory.
        for path in event.paths {
            let parent_dir = match path.parent() {
                Some(dir) => dir,
                None => continue,
            };

            // Check if the directory exists at all.
            match fs::metadata(&path) {
                Ok(meta) if meta.is_dir() => {}
                Ok(_) => continue,
                Err(err) if err.kind() == ErrorKind::NotFound => continue,
                Err(err) => {
                    log::error!("Could not stat {path:?}: {err}");
                    continue;
                }
            }

            // We can limit our scan to configuration that involves this parent directory.
            update_tokens::check(
                &*state.read().unwrap(),
                &mut next_tokens_check,
                Some(parent_dir),
            );
        }
    }
}

/// Build state from config and perform a full initial check on keys and tokens.
pub fn init_state(
    cfg: config::Top,
    watcher: &mut Option<RecommendedWatcher>,
    next_keys_check: &mut Option<SystemTime>,
    next_tokens_check: &mut Option<Instant>,
) -> Result<state::Top> {
    if cfg.providers.is_empty() {
        log::info!("No providers configured, nothing to do!");
    }

    let providers = cfg
        .providers
        .into_iter()
        .map(|(name, provider_cfg)| {
            init_provider(
                &name,
                provider_cfg,
                &cfg.state_dir,
                watcher,
                next_keys_check,
            )
            .with_context(|| format!("Failed to initialize provider '{name}'"))
        })
        .collect::<Result<Vec<_>>>()?;

    let state = state::Top { providers };

    // Initialize with a full check.
    update_tokens::check(&state, next_tokens_check, None);

    Ok(state)
}

/// Build provider state from config and initialize directories and tokens.
fn init_provider(
    name: &str,
    cfg: config::Provider,
    state_dir: &Path,
    watcher: &mut Option<RecommendedWatcher>,
    next_keys_check: &mut Option<SystemTime>,
) -> Result<state::Provider> {
    // Prepare directories and paths.
    let default_base_dir = {
        let mut dir = state_dir.to_path_buf();
        dir.push(&name);
        dir
    };
    let default_keys_base_dir = {
        let mut dir = default_base_dir.clone();
        dir.push("keys");
        dir
    };

    let webroot = cfg.webroot.unwrap_or_else(|| {
        let mut dir = default_base_dir.clone();
        dir.push("webroot");
        dir
    });
    let oidc_config_path = {
        let mut path = webroot.clone();
        path.push(".well-known");
        fs::create_dir_all(&path)
            .with_context(|| format!("Failed to create web directory {path:?}"))?;
        path.push("openid-configuration");
        path
    };
    let jwks_path = {
        let mut path = webroot;
        path.push(&cfg.jwks_path[1..]);
        let parent_dir = path
            .parent()
            .with_context(|| format!("Failed to determine parent directory of {path:?}"))?;
        fs::create_dir_all(parent_dir)
            .with_context(|| format!("Failed to create web directory {parent_dir:?}"))?;
        path
    };
    let jwks_uri = cfg
        .jwks_uri
        .unwrap_or_else(|| format!("{}{}", cfg.issuer, cfg.jwks_path));

    // Initialize all keys.
    let mut keys_changed = false;
    let keys = cfg
        .keys
        .into_iter()
        .map(|(key_name, key_cfg)| {
            let key_chain = init_key_chain(
                name,
                &key_name,
                key_cfg,
                &default_keys_base_dir,
                &mut keys_changed,
                next_keys_check,
            )
            .with_context(|| format!("Failed to initialize key '{name}' / '{key_name}'"))?;
            Ok((key_name, key_chain))
        })
        .collect::<Result<_>>()?;

    // Write OpenID Connect discovery document.
    // Use atomic write, because a webserver may be serving this.
    atomic_write(
        &oidc_config_path,
        serde_json::to_string_pretty(&json!({
            // Some fields required per OpenID Connect Discovery 1.0 are omitted here, because they
            // are not useful for us (e.g. `authorization_endpoint`) and there is precedent for
            // leaving these out (e.g. GitHub Actions).
            "issuer": cfg.issuer,
            "jwks_uri": jwks_uri,
            "scopes_supported": ["openid"],
            "response_types_supported": ["id_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }))
        .expect("Failed to serialize discovery document")
        .as_bytes(),
    )
    .with_context(|| format!("Failed to write discovery document {oidc_config_path:?}"))?;
    log::debug!("Wrote discovery document {oidc_config_path:?}");

    let mut provider = state::Provider {
        name: name.to_string(),
        tokens: vec![],
        oidc_config_path,
        jwks_path,
        jwks_uri,
        keys,
    };

    // Write a the JWKs file. Even if keys didn't change, we do a write here to check the path is
    // writable at startup, so we can fail early if it is not.
    update_keys::write_jwks(&provider)
        .with_context(|| format!("Failed to write JWKs document {:?}", provider.jwks_path))?;

    // Prepare claims with `iss` included.
    let mut provider_claims = cfg.claims;
    provider_claims
        .entry("iss".to_string())
        .or_insert_with(|| cfg.issuer.into());

    provider.tokens.reserve(cfg.tokens.len());
    for mut cfg in cfg.tokens {
        let key_name = match cfg.key_name {
            Some(name) => name,
            None if provider.keys.len() == 1 => provider.keys.values().next().unwrap().name.clone(),
            None if provider.keys.is_empty() => bail!("No keys configured"),
            None => bail!("Multiple keys configured, but no `key_name` specified for token"),
        };

        let key_chain = provider
            .keys
            .get(&key_name)
            .with_context(|| format!("Token specifies unknown key name '{key_name}'"))?;

        // No need to store these separately in state.
        // Combine provider + token claims here, during init.
        let mut claims = provider_claims.clone();
        claims.extend(cfg.claims.into_iter());

        // Apply defaults for various timings.
        let refresh = cfg.refresh.unwrap_or(cfg.lifespan * 3 / 4);
        ensure!(
            refresh <= cfg.lifespan,
            "Token refresh cannot exceed lifespan"
        );
        ensure!(
            cfg.lifespan <= key_chain.lifespan.as_secs(),
            "Token lifespan cannot exceed provider key lifespan"
        );

        // Setup watcher for parent directory.
        if let config::TokenPath::Directories {
            ref mut parent_dir, ..
        } = cfg.path
        {
            // Canonicalize even if there is no watcher (`--once`). For consistency, and because
            // this fails if the directory does not exist, for example.
            *parent_dir = parent_dir
                .canonicalize()
                .with_context(|| format!("Failed to canonicalize path {parent_dir:?}"))?;

            if let Some(ref mut watcher) = watcher {
                watcher
                    .watch(parent_dir, notify::RecursiveMode::NonRecursive)
                    .with_context(|| format!("Failed to install watcher for {parent_dir:?}"))?;
            }
        }

        provider.tokens.push(state::Token {
            path: cfg.path,
            key_name,
            claims,
            lifespan: Duration::from_secs(cfg.lifespan),
            refresh: Duration::from_secs(refresh),
            nbf_margin: Duration::from_secs(cfg.nbf_margin),
        })
    }

    Ok(provider)
}

/// Build a key chain from config.
fn init_key_chain(
    provider_name: &str,
    name: &str,
    cfg: config::KeyChain,
    default_keys_base_dir: &Path,
    keys_changed: &mut bool,
    next_keys_check: &mut Option<SystemTime>,
) -> Result<state::KeyChain> {
    let lifespan = Duration::from_secs(cfg.lifespan);
    let publish_margin = cfg.publish_margin.unwrap_or(cfg.lifespan / 4);
    let publish_margin = Duration::from_secs(publish_margin);
    ensure!(
        publish_margin < lifespan,
        "Key publish margin cannot exceed lifespan"
    );

    // Prepare directories and paths.
    let keys_dir = cfg.dir.unwrap_or_else(|| {
        let mut dir = default_keys_base_dir.to_path_buf();
        dir.push(&name);
        dir
    });

    fs::create_dir_all(&keys_dir)
        .with_context(|| format!("Failed to create keys directory {keys_dir:?}"))?;
    // TODO: Should we try to chown as well? Currently not possible in Rust stdlib.
    // https://github.com/rust-lang/rust/issues/88989
    #[cfg(unix)]
    fs::set_permissions(&keys_dir, Permissions::from_mode(0o700))
        .with_context(|| format!("Failed to set keys directory {keys_dir:?} permissions"))?;

    // Read the index and prepare signing keys.
    let mut index_path = keys_dir.clone();
    index_path.push("index.json");
    let index = fs::read(&index_path)
        .or_else(|err| match err.kind() {
            ErrorKind::NotFound => Ok(b"{}".to_vec()),
            _ => Err(err),
        })
        .with_context(|| format!("Failed to read key index {index_path:?}"))?;
    let index: key_index::Top = serde_json::from_slice(&index)
        .with_context(|| format!("Failed to parse key index {index_path:?}"))?;

    let now = SystemTime::now();

    let current = Arc::new(match index.current {
        Some(entry) => load_key_pair(&*cfg.alg, &keys_dir, entry)?,
        None => {
            let key_pair = update_keys::generate(
                "current",
                provider_name,
                name,
                &*cfg.alg,
                &keys_dir,
                now + lifespan,
            )?;
            *keys_changed = true;
            key_pair
        }
    });

    let next = index
        .next
        .map(|entry| load_key_pair(&*cfg.alg, &keys_dir, entry))
        .transpose()?
        .map(Arc::new);

    let old = index
        .old
        .into_iter()
        .map(|entry| load_key_pair(&*cfg.alg, &keys_dir, entry).map(Arc::new))
        .collect::<Result<_>>()?;

    let mut key_chain = state::KeyChain {
        name: name.to_string(),
        keys_dir,
        index_path,
        lifespan,
        publish_margin,
        alg: cfg.alg,
        current,
        next,
        old,
    };

    // Initial update, in case we loaded expired keys.
    update_keys::check_key_chain(provider_name, &mut key_chain, keys_changed, next_keys_check)?;

    Ok(key_chain)
}

/// Load an existing key pair from a file based on the index entry.
fn load_key_pair(
    alg: &dyn Algorithm,
    keys_dir: &Path,
    entry: key_index::Entry,
) -> Result<state::KeyPair> {
    let path = path_for_key_id(keys_dir, &entry.id);
    let inner = alg.load_key_pair(&path)?;
    Ok(state::KeyPair {
        id: entry.id,
        path,
        inner,
        expires: UNIX_EPOCH + Duration::from_secs(entry.expires),
    })
}
