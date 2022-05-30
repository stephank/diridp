#![forbid(unsafe_code)]

mod config;
mod key_index;
mod log;
mod state;
mod update_keys;
mod update_tokens;
mod util;

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

use anyhow::{bail, ensure, Context, Result};
use clap::Parser;
use notify::Watcher;
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
use serde_json::json;
use util::atomic_write;

use crate::util::min_opt;

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
    let state = Arc::new(RwLock::new({
        let cfg =
            fs::read(&args.config).with_context(|| format!("Failed to read {:?}", args.config))?;
        let cfg: config::Top = serde_yaml::from_slice(&cfg)
            .with_context(|| format!("Failed to parse {:?}", args.config))?;

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
                    watcher.as_mut(),
                    &mut next_keys_check,
                )
                .with_context(|| format!("Failed to initialize provider '{name}'"))
            })
            .collect::<Result<Vec<_>>>()?;

        let state = state::Top { providers };

        // Initialize with a full check.
        update_tokens::check(&state, &mut next_tokens_check, None);

        state
    }));

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

/// Initialize a provider, loading the index and existing keys, and generating missing keys.
fn init_provider(
    name: &str,
    cfg: config::Provider,
    state_dir: &Path,
    mut watcher: Option<&mut impl Watcher>,
    next_keys_check: &mut Option<SystemTime>,
) -> Result<state::Provider> {
    let key_lifespan = Duration::from_secs(cfg.key_lifespan);
    let key_publish_margin = cfg.key_publish_margin.unwrap_or(cfg.key_lifespan / 4);
    let key_publish_margin = Duration::from_secs(key_publish_margin);
    ensure!(
        key_publish_margin < key_lifespan,
        "Provider key publish margin cannot exceed lifespan"
    );

    // Prepare directories and paths.
    let default_base_dir = {
        let mut dir = state_dir.to_path_buf();
        dir.push(&name);
        dir
    };
    let keys_dir = cfg.keys_dir.unwrap_or_else(|| {
        let mut dir = default_base_dir.clone();
        dir.push("keys");
        dir
    });

    fs::create_dir_all(&keys_dir)
        .with_context(|| format!("Failed to create keys directory {keys_dir:?}"))?;
    // TODO: Should we try to chown as well? Currently not possible in Rust stdlib.
    // https://github.com/rust-lang/rust/issues/88989
    #[cfg(unix)]
    fs::set_permissions(&keys_dir, Permissions::from_mode(0o700))
        .with_context(|| format!("Failed to set keys directory {keys_dir:?} permissions"))?;

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
        Some(entry) => load_key_pair(&keys_dir, entry)?,
        None => update_keys::generate("current", name, &keys_dir, now + key_lifespan)?,
    });

    let next = index
        .next
        .map(|entry| load_key_pair(&keys_dir, entry))
        .transpose()?
        .map(Arc::new);

    let old = index
        .old
        .into_iter()
        .map(|entry| load_key_pair(&keys_dir, entry).map(Arc::new))
        .collect::<Result<_>>()?;

    let mut provider = state::Provider {
        name: name.to_string(),
        tokens: vec![],
        keys_dir,
        oidc_config_path,
        jwks_path,
        jwks_uri,
        index_path,
        key_lifespan,
        key_publish_margin,
        current,
        next,
        old,
    };

    // Initial update, in case we loaded expired keys.
    min_opt(next_keys_check, update_keys::check_provider(&mut provider)?);

    // Prepare claims with `iss` included.
    let mut provider_claims = cfg.claims;
    provider_claims
        .entry("iss".to_string())
        .or_insert_with(|| cfg.issuer.into());

    provider.tokens.reserve(cfg.tokens.len());
    for mut cfg in cfg.tokens {
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
            cfg.lifespan <= provider.key_lifespan.as_secs(),
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
            claims,
            lifespan: Duration::from_secs(cfg.lifespan),
            refresh: Duration::from_secs(refresh),
            nbf_margin: Duration::from_secs(cfg.nbf_margin),
        })
    }

    Ok(provider)
}

/// Load an existing key pair from a file based on the index entry.
fn load_key_pair(keys_dir: &Path, entry: key_index::Entry) -> Result<state::KeyPair> {
    let path = update_keys::path_for_key_id(keys_dir, &entry.id);
    let key_pair = RsaPrivateKey::read_pkcs8_pem_file(&path)
        .with_context(|| format!("Failed to read RSA key pair {path:?}"))?;

    Ok(state::KeyPair {
        id: entry.id,
        path,
        inner: key_pair,
        expires: UNIX_EPOCH + Duration::from_secs(entry.expires),
    })
}
