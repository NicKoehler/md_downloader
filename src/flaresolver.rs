//! Integration with a self-hosted
//! [FlareSolverr](https://github.com/FlareSolverr/FlareSolverr) instance.
//!
//! FlareSolverr is a proxy server that solves Cloudflare (and DDoS-GUARD)
//! challenges using a real headless browser. When MediaFire serves a
//! bot-challenged download page, [`FlareSolver::get_page`] asks the local
//! instance to open the URL in its browser and returns the resulting HTML,
//! from which the CDN link can be extracted.
//!
//! This is an opt-in alternative to the built-in `curl-impersonate`
//! fallback: it is stronger against JavaScript-heavy challenges, at the
//! cost of requiring a separately running server (Docker or precompiled
//! binary) and a slower solve time (~10-30 s per challenge).

use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

/// Maximum time (ms) given to FlareSolverr to solve the challenge.
const DEFAULT_MAX_TIMEOUT_MS: u64 = 60_000;

/// Overall HTTP timeout for the request against the FlareSolverr API:
/// browser launch plus challenge solving can take a while.
const API_TIMEOUT: Duration = Duration::from_secs(120);

/// Errors returned by [`FlareSolver`].
#[derive(Debug)]
pub enum FlareSolverError {
    /// The configured base URL is not a valid `http(s)` URL.
    InvalidUrl(String),
    /// The request against the FlareSolverr API failed or returned an
    /// unusable response.
    RequestFailed(String),
}

impl std::fmt::Display for FlareSolverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl(msg) => write!(f, "invalid FlareSolverr URL: {msg}"),
            Self::RequestFailed(msg) => write!(f, "FlareSolverr request failed: {msg}"),
        }
    }
}

impl std::error::Error for FlareSolverError {}

/// Top-level FlareSolverr API response.
#[derive(Deserialize)]
struct FsResponse {
    status: String,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    solution: Option<FsSolution>,
}

/// The `solution` object of a successful FlareSolverr API response.
#[derive(Deserialize)]
struct FsSolution {
    status: u16,
    /// Final HTML of the page after the challenge was solved.
    #[serde(default)]
    response: Option<String>,
}

/// Client for a self-hosted FlareSolverr instance.
///
/// Cheap to clone (wraps an `Arc`-backed `reqwest::Client`).
#[derive(Debug, Clone)]
pub struct FlareSolver {
    base_url: String,
    client: Client,
}

impl FlareSolver {
    /// Creates a new [`FlareSolver`] pointing at `base_url`
    /// (e.g. `"http://127.0.0.1:8191"`).
    ///
    /// # Errors
    ///
    /// Returns [`FlareSolverError::InvalidUrl`] if the URL is not a valid
    /// `http(s)` URL with a host.
    pub fn new(base_url: impl Into<String>, client: &Client) -> Result<Self, FlareSolverError> {
        let url = reqwest::Url::parse(&base_url.into())
            .map_err(|e| FlareSolverError::InvalidUrl(e.to_string()))?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(FlareSolverError::InvalidUrl(format!(
                "expected an http(s) URL, got `{url}`"
            )));
        }
        // Normalize: strip a trailing slash so `{base}/v1` is always valid.
        let mut base_url = url.as_str().to_string();
        while base_url.ends_with('/') {
            base_url.pop();
        }
        Ok(Self {
            base_url,
            client: client.clone(),
        })
    }

    /// Asks the FlareSolverr instance to open `url` in its headless browser
    /// and returns `(http_status, html)` of the resulting page.
    ///
    /// # Errors
    ///
    /// Returns [`FlareSolverError::RequestFailed`] if the API call fails,
    /// the response cannot be parsed, FlareSolverr reports a failure, or no
    /// page body is present in the solution.
    pub async fn get_page(&self, url: &str) -> Result<(u16, String), FlareSolverError> {
        let payload = serde_json::json!({
            "cmd": "request.get",
            "url": url,
            "maxTimeout": DEFAULT_MAX_TIMEOUT_MS,
        });

        let response = self
            .client
            .post(format!("{}/v1", self.base_url))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(payload.to_string())
            .timeout(API_TIMEOUT)
            .send()
            .await
            .map_err(|e| FlareSolverError::RequestFailed(e.to_string()))?;

        let http_status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| FlareSolverError::RequestFailed(e.to_string()))?;

        let fs: FsResponse = serde_json::from_str(&text).map_err(|e| {
            FlareSolverError::RequestFailed(format!(
                "invalid FlareSolverr response (HTTP {http_status}): {e}"
            ))
        })?;

        if !fs.status.eq_ignore_ascii_case("ok") {
            return Err(FlareSolverError::RequestFailed(format!(
                "FlareSolverr reported failure: {}",
                fs.message.unwrap_or_else(|| "no message".into())
            )));
        }

        let solution = fs.solution.ok_or_else(|| {
            FlareSolverError::RequestFailed("FlareSolverr response has no `solution`".into())
        })?;
        let html = solution.response.ok_or_else(|| {
            FlareSolverError::RequestFailed(
                "FlareSolverr solution has no page body (`response`)".into(),
            )
        })?;

        Ok((solution.status, html))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_invalid_urls() {
        let client = Client::new();
        assert!(FlareSolver::new("not-a-url", &client).is_err());
        assert!(FlareSolver::new("ftp://host:1234", &client).is_err());
    }

    #[test]
    fn new_strips_trailing_slash() {
        let client = Client::new();
        let fs = FlareSolver::new("http://127.0.0.1:8191///", &client).unwrap();
        assert_eq!(fs.base_url, "http://127.0.0.1:8191");
    }

    #[test]
    fn new_accepts_https() {
        let client = Client::new();
        assert!(FlareSolver::new("https://solver.example.com", &client).is_ok());
    }

    /// Mock FlareSolverr API response with a solvable page body.
    const MOCK_BODY: &str = r#"{"status":"ok","message":"","solution":{"status":200,"response":"<html><a href=\"https://cdn.mediafile.com/dl/123\">dl</a></html>"}}"#;

    /// Spins up a minimal single-purpose HTTP server answering every
    /// request with the canned FlareSolverr response.
    async fn spawn_mock_server() -> std::net::SocketAddr {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(_) => return,
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    MOCK_BODY.len(),
                    MOCK_BODY
                );
                if socket.write_all(response.as_bytes()).await.is_err() {
                    return;
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn get_page_parses_solution() {
        let addr = spawn_mock_server().await;
        let client = Client::new();
        let fs = FlareSolver::new(format!("http://{addr}"), &client).unwrap();

        let (status, html) = fs.get_page("https://www.mediafire.com/file/abc").await.unwrap();
        assert_eq!(status, 200);
        assert!(html.contains("cdn.mediafile.com/dl/123"));
    }
}
