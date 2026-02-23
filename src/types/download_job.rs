use crate::utils::{
    extract_ukey, try_extract_link_from_normal_html, try_extract_security_token_from_malware_html,
};
use futures::StreamExt;
use md_api::Api;
use reqwest::header::RANGE;
use reqwest::{Client, Response, StatusCode};
use ring::digest::{Context, SHA256};
use std::path::PathBuf;
use tokio::fs::{File, create_dir_all, metadata, remove_file};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::types::{DownloadError, DownloadProgress};
use md_api::types::ApiError;

/// Represents a single downloadable file and all metadata required
/// to download, resume, verify, and sort it.
///
/// A `DownloadJob` encapsulates:
/// - File identity (name and path)
/// - Expected size and hash for integrity validation
/// - The download URL
/// - Sorting behavior
/// - The HTTP client used to perform requests
///
/// The struct supports resumable downloads, progress reporting,
/// HTML redirect resolution, and post-download hash verification.
#[derive(Debug, Clone)]
pub struct DownloadJob {
    pub filename: String,
    pub path: PathBuf,
    pub size: u64,
    pub download_link: String,
    pub hash: String,
    reverse: bool,
    api_client: Api,
    download_client: Client,
}

impl DownloadJob {
    /// Creates a new [`DownloadJob`].
    ///
    /// # Parameters
    ///
    /// - `filename`: Logical or display name of the file.
    /// - `path`: Full filesystem path where the file will be written.
    /// - `size`: Expected file size in bytes.
    /// - `download_link`: Direct URL used to download the file.
    /// - `hash`: Expected file checksum (MD5 = 32 hex chars, SHA-256 = 64 hex chars).
    /// - `reverse`: Determines sorting order when comparing jobs by size.
    ///   If `true`, sorting is ascending; otherwise descending.
    /// - `client`: Configured `reqwest::Client` used for HTTP requests.
    ///
    /// # Returns
    ///
    /// A fully initialized `DownloadJob`.
    pub fn new(
        filename: String,
        path: PathBuf,
        size: u64,
        download_link: String,
        hash: String,
        reverse: bool,
        api_client: Api,
        download_client: Client,
    ) -> Self {
        Self {
            filename,
            path,
            size,
            download_link,
            hash,
            reverse,
            api_client,
            download_client,
        }
    }

    /// Downloads the file while reporting progress updates.
    ///
    /// This method behaves the same as [`download`], but allows the caller
    /// to receive progress notifications via a callback.
    ///
    /// # Type Parameters
    ///
    /// - `F`: A closure that receives [`DownloadProgress`] updates.
    ///
    /// # Parameters
    ///
    /// - `progress`: A callback invoked during different phases:
    ///   - Resume attempt
    ///   - Link retrieval
    ///   - Download progress (bytes downloaded / total size)
    ///   - Hash verification
    ///   - Completion
    ///
    /// # Errors
    ///
    /// Returns `DownloadError` if:
    /// - A network request fails
    /// - File I/O fails
    /// - Hash verification fails
    /// - The download link cannot be resolved
    pub async fn download_with_progress<F>(self: &Self, progress: F) -> Result<(), DownloadError>
    where
        F: Fn(DownloadProgress),
    {
        self._download(progress).await
    }

    /// Downloads the file without reporting progress.
    ///
    /// This is a convenience wrapper around [`download_with_progress`]
    /// using a no-op progress callback.
    ///
    /// # Errors
    ///
    /// Returns `DownloadError` under the same conditions as
    /// [`download_with_progress`].
    pub async fn download(self: &Self) -> Result<(), DownloadError> {
        self._download(|_| {}).await
    }

    async fn _download<F>(&self, progress: F) -> Result<(), DownloadError>
    where
        F: Fn(DownloadProgress),
    {
        progress(DownloadProgress::TryResuming);
        self.create_path_if_not_exists().await?;

        let (should_resume, start_bytes) = match self.prepare_resume(&progress).await {
            None => {
                progress(DownloadProgress::Done);
                return Ok(());
            }
            Some(info) => info,
        };

        progress(DownloadProgress::GettingLink);
        let (response, status) = self.handle_request(should_resume, start_bytes).await?;

        let (mut file, downloaded_bytes) =
            self.open_file(should_resume, start_bytes, status).await?;

        self.stream_to_file(response, &mut file, downloaded_bytes, &progress)
            .await?;

        progress(DownloadProgress::CheckingHash);

        match self.check_hash().await {
            Ok(()) => {
                progress(DownloadProgress::Done);
                Ok(())
            }
            Err(e) => {
                remove_file(&self.path).await.ok();
                Err(e)
            }
        }
    }

    async fn prepare_resume<F>(self: &Self, progress: F) -> Option<(bool, u64)>
    where
        F: Fn(DownloadProgress),
    {
        let meta = metadata(&self.path).await;
        match meta {
            Ok(meta) => {
                let file_size = meta.len();
                if file_size == self.size {
                    progress(DownloadProgress::CheckingHash);
                    if self.check_hash().await.is_ok() {
                        return None;
                    } else {
                        Some((false, 0))
                    }
                } else {
                    Some((file_size > 0, file_size))
                }
            }
            Err(_) => Some((false, 0)),
        }
    }

    /// Verifies the integrity of the downloaded file against the expected hash.
    ///
    /// The hashing algorithm is inferred from the length of `self.hash`:
    /// - 32 hex characters → MD5
    /// - 64 hex characters → SHA-256
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the computed hash matches the expected hash.
    /// - `Err(DownloadError::HashMismatch)` if the hash differs.
    /// - `Err(DownloadError::UnknownHash)` if the hash format is unsupported.
    /// - `Err(DownloadError::IoError)` if the file cannot be read.
    ///
    /// # Errors
    ///
    /// Fails if:
    /// - The file cannot be opened
    /// - The file cannot be read
    /// - The hash format is invalid
    /// - The computed hash does not match
    pub async fn check_hash(&self) -> Result<(), DownloadError> {
        let mut file = File::open(&self.path)
            .await
            .map_err(|_| DownloadError::IoError)?;

        let mut buffer = [0u8; 8192];

        let actual_hash_hex = match self.hash.len() {
            32 => {
                // MD5
                let mut context = md5::Context::new();
                loop {
                    let count = file
                        .read(&mut buffer)
                        .await
                        .map_err(|_| DownloadError::IoError)?;
                    if count == 0 {
                        break;
                    }
                    context.consume(&buffer[..count]);
                }
                format!("{:x}", context.finalize())
            }
            64 => {
                // SHA-256
                let mut context = Context::new(&SHA256);
                loop {
                    let count = file
                        .read(&mut buffer)
                        .await
                        .map_err(|_| DownloadError::IoError)?;
                    if count == 0 {
                        break;
                    }
                    context.update(&buffer[..count]);
                }
                hex::encode(context.finish().as_ref())
            }
            _ => {
                return Err(DownloadError::UnknownHash);
            }
        };

        if actual_hash_hex != self.hash {
            return Err(DownloadError::HashMismatch);
        }

        Ok(())
    }

    async fn create_path_if_not_exists(self: &Self) -> Result<(), DownloadError> {
        if let Some(parent) = self.path.parent() {
            if metadata(parent).await.is_err() {
                create_dir_all(parent)
                    .await
                    .map_err(|_| DownloadError::IoError)?;
            }
        }
        Ok(())
    }

    async fn handle_request(
        &self,
        should_resume: bool,
        start_bytes: u64,
    ) -> Result<(Response, StatusCode), DownloadError> {
        let mut request = self.download_client.get(&self.download_link);

        if should_resume {
            request = request.header(RANGE, format!("bytes={}-", start_bytes));
        }

        let response = request
            .send()
            .await
            .map_err(|e| DownloadError::ApiError(ApiError::NetworkError(e.to_string())))?;

        let response = self
            .resolve_html_redirect(response, should_resume, start_bytes)
            .await?
            .error_for_status()
            .map_err(|e| DownloadError::ApiError(ApiError::NetworkError(e.to_string())))?;

        let status = response.status();

        Ok((response, status))
    }

    async fn resolve_html_redirect(
        &self,
        response: Response,
        should_resume: bool,
        start_bytes: u64,
    ) -> Result<Response, DownloadError> {
        let is_html = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.starts_with("text/html"))
            .unwrap_or(false);

        let headers = response.headers().clone();

        if !is_html {
            return Ok(response);
        }

        let html = response
            .text()
            .await
            .map_err(|e| DownloadError::ApiError(ApiError::NetworkError(e.to_string())))?;

        let mut request = match try_extract_link_from_normal_html(&html) {
            Some(link) => self.download_client.get(link),
            None => {
                let ukey = extract_ukey(&headers).ok_or(DownloadError::LinkExtractionError)?;
                let (security_token, pass) = try_extract_security_token_from_malware_html(&html)
                    .ok_or(DownloadError::LinkExtractionError)?;
                let link = self
                    .api_client
                    .resolve_malware_url(&ukey, &security_token)
                    .await
                    .map_err(|e| DownloadError::ApiError(e))?
                    .download_url;
                self.download_client.post(link).body(format!("pass={pass}"))
            }
        };

        if should_resume {
            request = request.header(RANGE, format!("bytes={}-", start_bytes));
        }

        let redirected = request
            .send()
            .await
            .map_err(|e| DownloadError::ApiError(ApiError::NetworkError(e.to_string())))?;

        Ok(redirected)
    }

    async fn open_file(
        &self,
        should_resume: bool,
        start_bytes: u64,
        status: StatusCode,
    ) -> Result<(File, u64), DownloadError> {
        if should_resume && status == StatusCode::PARTIAL_CONTENT {
            let file = File::options()
                .append(true)
                .open(&self.path)
                .await
                .map_err(|_| DownloadError::IoError)?;

            Ok((file, start_bytes))
        } else {
            let file = File::create(&self.path)
                .await
                .map_err(|_| DownloadError::IoError)?;

            Ok((file, 0))
        }
    }

    async fn stream_to_file<F>(
        &self,
        response: Response,
        file: &mut File,
        mut downloaded_bytes: u64,
        progress: &F,
    ) -> Result<(), DownloadError>
    where
        F: Fn(DownloadProgress),
    {
        let mut stream = response.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let data = chunk
                .map_err(|e| DownloadError::ApiError(ApiError::NetworkError(e.to_string())))?;

            file.write_all(&data)
                .await
                .map_err(|_| DownloadError::IoError)?;

            downloaded_bytes += data.len() as u64;

            progress(DownloadProgress::Downloading(downloaded_bytes, self.size));
        }

        file.flush().await.map_err(|_| DownloadError::IoError)?;

        Ok(())
    }
}

impl Eq for DownloadJob {}

impl PartialEq for DownloadJob {
    fn eq(&self, other: &Self) -> bool {
        self.filename == other.filename
            && self.path == other.path
            && self.size == other.size
            && self.download_link == other.download_link
    }
}

impl PartialOrd for DownloadJob {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if self.reverse {
            self.size.partial_cmp(&other.size)
        } else {
            other.size.partial_cmp(&self.size)
        }
    }
}

impl Ord for DownloadJob {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.reverse {
            self.size.cmp(&other.size)
        } else {
            other.size.cmp(&self.size)
        }
    }
}
