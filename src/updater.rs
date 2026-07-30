use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const REPO_OWNER: &str = "Moxin1044";
const REPO_NAME: &str = "Pscan";
const BIN_NAME: &str = "pscan";
const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Serialize, Deserialize)]
struct UpdateCache {
    checked_at: u64,
    latest_version: String,
    /// Version the user explicitly declined; skip auto-prompt while equal.
    skipped_version: Option<String>,
}

/// Compare two semver-ish version strings.
///
/// Trims a leading `v` and compares dot-separated integer components. Returns
/// true when `remote` is strictly newer than `local`. Non-numeric segments
/// force lexicographic fallback to keep behaviour predictable for release
/// candidates or pre-release tags.
pub fn is_newer(local: &str, remote: &str) -> bool {
    let local = local.trim_start_matches('v');
    let remote = remote.trim_start_matches('v');
    let parse = |value: &str| -> Vec<u64> {
        value
            .split('.')
            .filter_map(|part| part.parse::<u64>().ok())
            .collect()
    };
    let local_parts = parse(local);
    let remote_parts = parse(remote);
    if local_parts.is_empty() || remote_parts.is_empty() {
        return remote > local;
    }
    let len = local_parts.len().max(remote_parts.len());
    for i in 0..len {
        let l = local_parts.get(i).copied().unwrap_or(0);
        let r = remote_parts.get(i).copied().unwrap_or(0);
        if r > l {
            return true;
        }
        if l > r {
            return false;
        }
    }
    false
}

fn cache_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?;
    Some(base.join("pscan").join("update.json"))
}

fn load_cache() -> Option<UpdateCache> {
    let path = cache_path()?;
    let content = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

fn save_cache(cache: &UpdateCache) -> io::Result<()> {
    let Some(path) = cache_path() else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string(cache).unwrap_or_default();
    fs::write(path, content)
}

fn cache_is_fresh(cache: &UpdateCache) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    now.saturating_sub(cache.checked_at) < CACHE_TTL.as_secs()
}

/// Query GitHub Releases for the latest tag and return `Some(tag)` when
/// newer than the current build, otherwise `None`. Network or parsing errors
/// return `Ok(None)` so update checks never fail the primary CLI action.
pub fn fetch_latest_version() -> Result<String, self_update::Error> {
    let releases = self_update::backends::github::ReleaseList::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .build()?
        .fetch()?;
    releases
        .latest()
        .map(|release| release.version().to_owned())
        .ok_or_else(self_update::Error::no_release_found)
}

pub struct CheckOutcome {
    pub current: String,
    pub latest: String,
    pub is_newer: bool,
}

pub fn check_now() -> Result<CheckOutcome, self_update::Error> {
    let current = env!("CARGO_PKG_VERSION").to_string();
    let latest = fetch_latest_version()?;
    Ok(CheckOutcome {
        is_newer: is_newer(&current, &latest),
        current,
        latest,
    })
}

/// Non-blocking startup nudge. Reads the cache; if a newer version was
/// recorded and the user has not declined that exact version, prints a hint
/// to stderr and asks whether to update now. When declined we record the
/// version so the same prompt does not fire on the next run.
pub fn maybe_prompt_from_cache() {
    let Some(mut cache) = load_cache() else {
        return;
    };
    let current = env!("CARGO_PKG_VERSION");
    if !is_newer(current, &cache.latest_version) {
        return;
    }
    if cache.skipped_version.as_deref() == Some(cache.latest_version.as_str()) {
        return;
    }
    eprintln!(
        "pscan: new version {} available (current {}). Run `pscan --update` to install now, or `pscan --check-update` for details.",
        cache.latest_version, current
    );
    if !is_stderr_interactive() {
        return;
    }
    eprint!("pscan: update now? [y/N/skip] ");
    let _ = io::stderr().flush();
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err() {
        return;
    }
    let answer = answer.trim().to_ascii_lowercase();
    match answer.as_str() {
        "y" | "yes" => {
            if let Err(error) = install_latest() {
                eprintln!("pscan: update failed: {error}");
            }
        }
        "s" | "skip" => {
            cache.skipped_version = Some(cache.latest_version.clone());
            let _ = save_cache(&cache);
        }
        _ => {}
    }
}

pub fn refresh_cache_in_background() {
    std::thread::spawn(|| {
        if let Ok(latest) = fetch_latest_version() {
            let previous_skip = load_cache().and_then(|cache| cache.skipped_version);
            let cache = UpdateCache {
                checked_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|duration| duration.as_secs())
                    .unwrap_or(0),
                latest_version: latest,
                skipped_version: previous_skip,
            };
            let _ = save_cache(&cache);
        }
    });
}

/// Whether the last cache entry is still within the TTL window. When true
/// the caller should skip refreshing to keep startup silent and fast.
pub fn should_skip_check() -> bool {
    load_cache().is_some_and(|cache| cache_is_fresh(&cache))
}

pub fn install_latest() -> Result<self_update::VersionStatus, self_update::Error> {
    let status = self_update::backends::github::Update::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .bin_name(BIN_NAME)
        .current_version(env!("CARGO_PKG_VERSION"))
        .show_download_progress(true)
        .show_output(false)
        .no_confirm(true)
        .build()?
        .update()?;
    Ok(status)
}

fn is_stderr_interactive() -> bool {
    #[cfg(unix)]
    unsafe {
        libc::isatty(libc::STDERR_FILENO) == 1
    }
    #[cfg(not(unix))]
    {
        true
    }
}
