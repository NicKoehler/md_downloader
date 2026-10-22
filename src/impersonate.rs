//! Browser TLS impersonation fallback transport.
//!
//! When Cloudflare (in front of MediaFire) challenges the regular `reqwest`
//! client with an HTTP 403 interstitial, this module falls back to a
//! [`curl-impersonate`](https://github.com/lexiforest/curl-impersonate)
//! binary, which emits a byte-exact Chrome TLS ClientHello + HTTP/2
//! fingerprint that passes the challenge.
//!
//! The binary is resolved in this order:
//! 1. `curl-impersonate` (or a `curl_chrome*` wrapper) already on `PATH`
//! 2. A previously downloaded copy in the user cache directory
//! 3. Downloaded on demand from the curl-impersonate GitHub releases
//!    (pinned version, all supported platforms including Windows)
//!
//! No native code is linked: the binary is spawned as a subprocess.

use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

/// Pinned curl-impersonate release used for on-demand downloads.
const IMPI_VERSION: &str = "2.3.0";
/// Chrome profile requested from a raw `curl-impersonate` binary.
const CHROME_PROFILE: &str = "chrome146";
/// Cache subdirectory under the user cache dir.
const CACHE_SUBDIR: &str = "mdrs/bin";

/// Errors raised while setting up or running the impersonation fallback.
#[derive(Debug)]
pub enum ImpersonateError {
    /// No usable binary found and the on-demand download failed / is not
    /// available for this platform.
    Unavailable(String),
    /// The subprocess failed or returned an unusable response.
    RequestFailed(String),
}

impl std::fmt::Display for ImpersonateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(msg) => write!(f, "impersonation unavailable: {msg}"),
            Self::RequestFailed(msg) => write!(f, "impersonated request failed: {msg}"),
        }
    }
}

impl std::error::Error for ImpersonateError {}

/// A resolved `curl-impersonate` binary capable of Chrome impersonation.
pub struct Impersonator {
    bin: PathBuf,
    /// Profile flag for a raw `curl-impersonate` binary; `None` when the
    /// binary is already a version-pinned `curl_chrome*` wrapper.
    profile: Option<&'static str>,
}

impl Impersonator {
    /// Resolves (and if needed downloads) an impersonation binary.
    ///
    /// # Errors
    ///
    /// [`ImpersonateError::Unavailable`] if no binary can be obtained for
    /// the current platform.
    pub async fn new(client: &reqwest::Client) -> Result<Self, ImpersonateError> {
        // 1a. Raw `curl-impersonate` on PATH.
        for name in ["curl-impersonate", "curl-impersonate.exe"] {
            if let Some(path) = which(name) {
                return Ok(Self {
                    bin: path,
                    profile: Some(CHROME_PROFILE),
                });
            }
        }

        // 1b. A `curl_chrome*` wrapper on PATH (already pins a profile).
        if let Some(path) = which_prefix("curl_chrome") {
            return Ok(Self {
                bin: path,
                profile: None,
            });
        }

        // 2/3. User cache dir; download on first use.
        let dir = cache_dir().ok_or(ImpersonateError::Unavailable(
            "could not determine a user cache directory".into(),
        ))?;
        let bin = dir.join(binary_name());
        if !bin.exists() {
            download_and_extract(client, &dir).await?;
        }

        Ok(Self {
            bin,
            profile: Some(CHROME_PROFILE),
        })
    }

    /// Performs a GET request with a Chrome TLS/HTTP2 fingerprint.
    ///
    /// Returns the HTTP status code and the (decompressed) response body.
    ///
    /// # Errors
    ///
    /// [`ImpersonateError::RequestFailed`] if the subprocess fails or the
    /// response cannot be parsed.
    pub async fn get(&self, url: &str) -> Result<(u16, Vec<u8>), ImpersonateError> {
        let mut cmd = tokio::process::Command::new(&self.bin);
        if let Some(profile) = self.profile {
            cmd.args(["--compressed", "--impersonate", profile]);
        }
        cmd.args(["-sL", "--max-time", "120", "-w", "\n%{http_code}", url])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let output = cmd
            .spawn()
            .map_err(|e| ImpersonateError::RequestFailed(e.to_string()))?
            .wait_with_output()
            .await
            .map_err(|e| ImpersonateError::RequestFailed(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ImpersonateError::RequestFailed(format!(
                "exit {} ({})",
                output.status,
                stderr.trim()
            )));
        }

        // stdout = body + "\n" + status_code
        let stdout = output.stdout;
        let pos = stdout
            .iter()
            .rposition(|&b| b == b'\n')
            .ok_or(ImpersonateError::RequestFailed(
                "malformed subprocess output".into(),
            ))?;
        let code: u16 = stdout[pos + 1..]
            .iter()
            .map(|&b| b as char)
            .collect::<String>()
            .trim()
            .parse()
            .map_err(|_| ImpersonateError::RequestFailed("bad status code".into()))?;

        Ok((code, stdout[..pos].to_vec()))
    }
}

/// Finds `name` on `PATH`.
fn which(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Finds the first file on `PATH` whose name starts with `prefix`
/// (skipping Windows `.bat` wrappers, which cannot be spawned directly).
fn which_prefix(prefix: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(prefix) && !name.ends_with(".bat") && entry.path().is_file() {
                return Some(entry.path());
            }
        }
    }
    None
}

/// User cache directory for the downloaded binary.
fn cache_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    let base = if cfg!(target_os = "windows") {
        std::env::var_os("LOCALAPPDATA")?.into()
    } else if cfg!(target_os = "macos") {
        Path::new(&home).join("Library/Caches")
    } else {
        std::env::var_os("XDG_CACHE_HOME").map(Into::into).unwrap_or_else(|| {
            Path::new(&home)
                .join(".cache")
                .into()
        })
    };
    Some(base.join(CACHE_SUBDIR))
}

/// Name of the raw binary inside a release tarball / on disk.
fn binary_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "curl-impersonate.exe"
    } else {
        "curl-impersonate"
    }
}

/// Maps the current target to a curl-impersonate release asset name.
fn asset_name() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("x86_64-linux-gnu"),
        ("linux", "aarch64") => Some("aarch64-linux-gnu"),
        ("macos", "x86_64") => Some("x86_64-macos"),
        ("macos", "aarch64") => Some("arm64-macos"),
        ("windows", "x86_64") => Some("x86_64-win32"),
        ("windows", "x86") => Some("i686-win32"),
        _ => None,
    }
}

/// Downloads the pinned release tarball and extracts the binary into `dir`.
async fn download_and_extract(
    client: &reqwest::Client,
    dir: &Path,
) -> Result<(), ImpersonateError> {
    let triple = asset_name().ok_or(ImpersonateError::Unavailable(
        "no prebuilt curl-impersonate binary for this platform; \
         install one manually and put it on PATH"
            .into(),
    ))?;

    let url = format!(
        "https://github.com/lexiforest/curl-impersonate/releases/download/v{IMPI_VERSION}/curl-impersonate-v{IMPI_VERSION}.{triple}.tar.gz"
    );

    std::fs::create_dir_all(dir).map_err(|e| {
        ImpersonateError::Unavailable(format!("cannot create cache dir: {e}"))
    })?;

    let tarball_path = dir.join(format!("curl-impersonate-v{IMPI_VERSION}.tar.gz.part"));

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| ImpersonateError::Unavailable(e.to_string()))?;
    if !response.status().is_success() {
        return Err(ImpersonateError::Unavailable(format!(
            "HTTP {} downloading {url}",
            response.status()
        )));
    }

    let mut file = tokio::fs::File::create(&tarball_path)
        .await
        .map_err(|e| ImpersonateError::Unavailable(e.to_string()))?;
    let bytes = response
        .bytes()
        .await
        .map_err(|e| ImpersonateError::Unavailable(e.to_string()))?;
    file.write_all(&bytes)
        .await
        .map_err(|e| ImpersonateError::Unavailable(e.to_string()))?;
    file.flush()
        .await
        .map_err(|e| ImpersonateError::Unavailable(e.to_string()))?;
    drop(file);

    extract_tarball(&tarball_path, dir)?;
    let _ = std::fs::remove_file(&tarball_path);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let bin = dir.join(binary_name());
        if let Ok(meta) = std::fs::metadata(&bin) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(&bin, perms);
        }
    }

    Ok(())
}

/// Extracts the raw binary from a release tarball into `dest`.
fn extract_tarball(tarball: &Path, dest: &Path) -> Result<(), ImpersonateError> {
    use flate2::read::GzDecoder;
    use std::io::BufReader;

    let file =
        std::fs::File::open(tarball).map_err(|e| ImpersonateError::Unavailable(e.to_string()))?;
    let decoder = GzDecoder::new(BufReader::new(file));
    let mut archive = tar::Archive::new(decoder);

    let wanted = binary_name();
    let mut found = false;
    for entry in archive
        .entries()
        .map_err(|e| ImpersonateError::Unavailable(e.to_string()))?
    {
        let mut entry =
            entry.map_err(|e| ImpersonateError::Unavailable(e.to_string()))?;
        let name = entry
            .path()
            .map_err(|e| ImpersonateError::Unavailable(e.to_string()))?
            .file_name()
            .map(|n| n.to_string_lossy().into_owned());
        if name.as_deref() == Some(wanted) {
            let out_path = dest.join(wanted);
            let mut out = std::fs::File::create(&out_path)
                .map_err(|e| ImpersonateError::Unavailable(e.to_string()))?;
            std::io::copy(&mut entry, &mut out)
                .map_err(|e| ImpersonateError::Unavailable(e.to_string()))?;
            found = true;
            break;
        }
    }

    if !found {
        return Err(ImpersonateError::Unavailable(
            "binary not found inside release tarball".into(),
        ));
    }
    Ok(())
}
