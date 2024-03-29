use std::{
    ffi::OsString,
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use base64ct::Encoding;

/// Returns a Unix timestamp in seconds for the given `SystemTime`.
///
/// Panics if the input time is before Unix epoch.
pub fn unix_time(input: SystemTime) -> u64 {
    input
        .duration_since(UNIX_EPOCH)
        .expect("Encountered timestamp before Unix epoch")
        .as_secs()
}

/// Returns a JWT-compatible base64url encoding of some data.
#[inline]
pub fn base64url(data: &[u8]) -> String {
    base64ct::Base64UrlUnpadded::encode_string(data)
}

/// Update a value to the lower of two values. A `None` is treated as infinity.
pub fn min_opt<T: Ord>(value: &mut Option<T>, other: T) {
    match value {
        Some(ref mut value) if *value > other => {
            *value = other;
        }
        Some(_) => {}
        None => {
            *value = Some(other);
        }
    }
}

/// Performs an atomic write of a file.
///
/// Atomic here means other processes don't accidentally see an intermediate state (partially
/// written file). This is accomplished by writing a temporary file, then replacing the original
/// with a rename/move.
///
/// The temporary file has a fixed name based on the input path, so if we ever leave a file
/// lingering, it'll be replaced the next time we do an atomic write. This way, there is never any
/// significant buildup of temporary files.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .with_context(|| format!("Failed to determine file name of {path:?} for atomic write"))?;

    // Derive a temporary file name from the original file name.
    const PREFIX: &str = ".";
    const SUFFIX: &str = ".diridp.tmp";
    let mut tmp_file_name = OsString::with_capacity(PREFIX.len() + file_name.len() + SUFFIX.len());
    tmp_file_name.push(PREFIX);
    tmp_file_name.push(file_name);
    tmp_file_name.push(SUFFIX);

    // We must use the same directory for the temporary file. It is the easiest way to guarantee
    // the file is on the same mount point.
    let mut tmp_path = path
        .parent()
        .with_context(|| {
            format!("Failed to determine parent directory of {path:?} for atomic write")
        })?
        .to_path_buf();
    tmp_path.push(tmp_file_name);

    fs::write(&tmp_path, data).with_context(|| {
        format!("Failed to write to temporary file {tmp_path:?} for atomic write of {path:?}")
    })?;

    fs::rename(&tmp_path, &path)
        .with_context(|| format!("Failed to move temporary file {tmp_path:?} in place at {path:?}"))
}

/// Slugify to create a default provider name from its issuer.
pub fn issuer_slug(input: &str) -> String {
    // Common case: HTTPS origin. Use just the hostname in that case.
    let shortened = if let Some(host) = input
        .strip_prefix("https://")
        .filter(|host| !host.contains('/'))
    {
        host
    } else {
        input
    };

    // Basic slugify.
    shortened
        .split(|c: char| !c.is_alphanumeric() && !matches!(c, '.' | '-' | '_'))
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_start_matches(|c| matches!(c, '.' | '-')))
        .collect::<Vec<_>>()
        .join("_")
}

#[cfg(test)]
mod test {
    #[test]
    fn test_issuer_slug() {
        for (input, output) in [
            ("https://example.com", "example.com"),
            ("https://example.com:8080", "example.com_8080"),
            ("http://example.com", "http_example.com"),
            ("TEST  1 2 3 @@", "TEST_1_2_3"),
            ("nøn-äscíì", "nøn-äscíì"),
            ("--try-flag", "try-flag"),
            (".try hidden", "try_hidden"),
        ] {
            assert_eq!(super::issuer_slug(input), output);
        }
    }
}
