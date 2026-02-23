use crate::types::{DownloadError, DownloadJob};
use md_api::Api;
use md_api::types::{InfoType, Key};
use md_api::utils::get_client_builder;
use reqwest::{Client, Proxy};
use std::collections::BinaryHeap;
use std::path::PathBuf;

pub mod types;
pub mod utils;

/// High-level downloader responsible for:
/// - Communicating with the MediaFire API
/// - Resolving files and folders into downloadable jobs
/// - Configuring HTTP clients and proxies
/// - Building a prioritized download queue
///
/// This struct separates:
/// - API operations (metadata, folder traversal)
/// - Actual file downloading (handled by `DownloadJob`)
///
/// It supports recursive folder traversal, chunked folder pagination,
/// proxy configuration, and configurable job ordering.
pub struct MediafireDownloader {
    api_client: Api,
    download_client: Client,
    reverse_downloads: bool,
}

impl MediafireDownloader {
    /// Creates a new `MediafireDownloader`.
    ///
    /// # Parameters
    ///
    /// - `max_retries`: Maximum number of retry attempts used by the API client
    ///   for failed API requests.
    ///
    /// # Returns
    ///
    /// - `Ok(Self)` if initialization succeeds.
    /// - `Err(DownloadError::ApiError)` if API client creation fails.
    /// - `Err(DownloadError::ClientInitError)` if the HTTP client cannot be built.
    ///
    /// # Behavior
    ///
    /// Initializes:
    /// - An `Api` client configured with retry logic.
    /// - A default `reqwest::Client` for file downloads.
    /// - Default download ordering (largest files first).
    pub fn new(max_retries: u64) -> Result<Self, DownloadError> {
        Ok(Self {
            api_client: Api::new(max_retries).map_err(|e| DownloadError::ApiError(e))?,
            download_client: get_client_builder()
                .build()
                .map_err(|_| DownloadError::ClientInitError)?,
            reverse_downloads: false,
        })
    }

    /// Sets the sorting direction of generated download jobs.
    ///
    /// # Parameters
    ///
    /// - `value`:
    ///     - `true` → sort jobs in ascending order by file size
    ///     - `false` → sort jobs in descending order by file size (default)
    ///
    /// # Returns
    ///
    /// A new `MediafireDownloader` instance with updated sorting behavior.
    ///
    /// # Notes
    ///
    /// This method consumes `self` and returns a modified instance.
    pub fn reverse_downloads(self, value: bool) -> Self {
        Self {
            reverse_downloads: value,
            ..self
        }
    }

    /// Configures HTTP proxies for API calls and optionally for downloads.
    ///
    /// # Parameters
    ///
    /// - `proxies`: Optional list of proxy URLs (e.g. `"http://127.0.0.1:8080"`).
    /// - `proxy_downloads`:
    ///     - `true` → proxies are applied to both API and file downloads
    ///     - `false` → proxies are applied only to API calls
    ///
    /// # Returns
    ///
    /// - `Ok(Self)` with updated proxy configuration.
    /// - `Err(DownloadError::InvalidProxy)` if a proxy URL is invalid.
    /// - `Err(DownloadError::ClientInitError)` if the download client fails to build.
    /// - `Err(DownloadError::ApiError)` if the API client proxy setup fails.
    ///
    /// # Notes
    ///
    /// This method consumes `self` and returns a modified instance.
    pub fn set_proxies(
        self,
        proxies: Option<Vec<String>>,
        proxy_downloads: bool,
    ) -> Result<Self, DownloadError> {
        match proxies {
            Some(proxies) => {
                let download_client = {
                    if proxy_downloads {
                        let mut client = Client::builder();
                        for proxy in &proxies {
                            client = client.proxy(
                                Proxy::all(proxy.clone())
                                    .map_err(|_| DownloadError::InvalidProxy(proxy.clone()))?,
                            );
                        }
                        client.build().map_err(|_| DownloadError::ClientInitError)?
                    } else {
                        self.download_client
                    }
                };

                Ok(Self {
                    api_client: self
                        .api_client
                        .with_proxies(proxies)
                        .map_err(|e| DownloadError::ApiError(e))?,
                    download_client: download_client,
                    ..self
                })
            }
            None => Ok(self),
        }
    }

    /// Resolves a list of MediaFire URLs into a prioritized download queue.
    ///
    /// # Parameters
    ///
    /// - `urls`: List of MediaFire file or folder URLs.
    /// - `output_path`: Base directory where files should be saved.
    ///
    /// # Returns
    ///
    /// A `BinaryHeap<DownloadJob>` containing all resolved files,
    /// ordered according to the configured sorting direction.
    ///
    /// # Errors
    ///
    /// Returns `DownloadError` if:
    /// - URL key extraction fails
    /// - API metadata requests fail
    /// - Folder traversal fails
    ///
    /// # Behavior
    ///
    /// - Extracts API keys from URLs.
    /// - Recursively resolves folders.
    /// - Builds a queue of `DownloadJob`s.
    pub async fn get_download_jobs(
        self: &Self,
        urls: &Vec<String>,
        output_path: PathBuf,
    ) -> Result<BinaryHeap<DownloadJob>, DownloadError> {
        let mut download_queue: BinaryHeap<DownloadJob> = BinaryHeap::new();
        for key in self
            .api_client
            .extract_keys_from_url(urls)
            .map_err(|e| DownloadError::ApiError(e))?
        {
            download_queue.extend(
                self.fetch_items(key, 1, output_path.clone(), &|_| {})
                    .await?,
            );
        }
        Ok(download_queue)
    }

    /// Same as [`get_download_jobs`] but provides progress updates.
    ///
    /// # Type Parameters
    ///
    /// - `F`: A closure that receives folder names as they are processed.
    ///
    /// # Parameters
    ///
    /// - `urls`: List of MediaFire file or folder URLs.
    /// - `output_path`: Base directory for downloads.
    /// - `progress`: Callback invoked with folder names during traversal.
    ///
    /// # Returns
    ///
    /// A `BinaryHeap<DownloadJob>` of resolved jobs.
    ///
    /// # Errors
    ///
    /// Returns `DownloadError` under the same conditions as
    /// [`get_download_jobs`].
    pub async fn get_download_jobs_with_progress<F>(
        self: &Self,
        urls: &Vec<String>,
        output_path: PathBuf,
        progress: F,
    ) -> Result<BinaryHeap<DownloadJob>, DownloadError>
    where
        F: Fn(String),
    {
        let mut download_queue: BinaryHeap<DownloadJob> = BinaryHeap::new();
        for key in self
            .api_client
            .extract_keys_from_url(urls)
            .map_err(|e| DownloadError::ApiError(e))?
        {
            download_queue.extend(
                self.fetch_items(key, 1, output_path.clone(), &progress)
                    .await?,
            );
        }
        Ok(download_queue)
    }

    /// Internal recursive folder/file resolver.
    ///
    /// Traverses MediaFire folders using a stack-based approach
    /// to avoid deep recursion.
    ///
    /// # Type Parameters
    ///
    /// - `F`: A closure invoked with folder names during traversal.
    ///
    /// # Parameters
    ///
    /// - `key`: API key representing a file or folder.
    /// - `chunk`: Pagination index for folder contents.
    /// - `output_path`: Current filesystem path corresponding to this key.
    /// - `progress`: Callback invoked when entering folders.
    ///
    /// # Returns
    ///
    /// A `BinaryHeap<DownloadJob>` containing all discovered files
    /// under the given key.
    ///
    /// # Behavior
    ///
    /// - If `key` refers to a file → creates a single `DownloadJob`.
    /// - If `key` refers to a folder:
    ///     - Fetches folder contents (files + subfolders).
    ///     - Pushes file jobs into the queue.
    ///     - Adds subfolders to the traversal stack.
    ///     - Handles paginated folder chunks.
    ///
    /// # Errors
    ///
    /// Returns `DownloadError::ApiError` if any API request fails.
    async fn fetch_items<F>(
        self: &Self,
        key: Key,
        chunk: u64,
        output_path: PathBuf,
        progress: &F,
    ) -> Result<BinaryHeap<DownloadJob>, DownloadError>
    where
        F: Fn(String),
    {
        let mut download_queue: BinaryHeap<DownloadJob> = BinaryHeap::new();
        let mut folder_stack: Vec<(Key, PathBuf, u64)> = vec![(key, output_path, chunk)];

        while let Some((current_key, current_output_path, current_chunk)) = folder_stack.pop() {
            let data_type = self
                .api_client
                .get_info(&current_key)
                .await
                .map_err(|e| DownloadError::ApiError(e))?;

            match data_type {
                InfoType::File(file_info) => {
                    download_queue.push(DownloadJob::new(
                        file_info.filename.clone(),
                        current_output_path.join(&file_info.filename),
                        file_info.size,
                        file_info.links.normal_download,
                        file_info.hash,
                        self.reverse_downloads,
                        self.api_client.clone(),
                        self.download_client.clone(),
                    ));
                }
                InfoType::Folder(folder_info) => {
                    progress(folder_info.name.clone());
                    let folder_content = self
                        .api_client
                        .get_folder_and_file_content(&current_key, current_chunk)
                        .await
                        .map_err(|e| DownloadError::ApiError(e))?
                        .folder_content;

                    if let Some(files) = folder_content.files {
                        for file in files {
                            download_queue.push(DownloadJob::new(
                                file.filename.clone(),
                                current_output_path
                                    .join(&folder_info.name)
                                    .join(&file.filename),
                                file.size,
                                file.links.normal_download,
                                file.hash,
                                self.reverse_downloads,
                                self.api_client.clone(),
                                self.download_client.clone(),
                            ));
                        }
                    }

                    if let Some(folders) = folder_content.folders {
                        for folder in folders {
                            let subfolder_key = Key::Folder(folder.folderkey);
                            let subfolder_output = current_output_path.join(&folder_info.name);
                            folder_stack.push((subfolder_key, subfolder_output, 1));
                        }
                    }

                    if folder_content.more_chunks == "yes" {
                        folder_stack.push((current_key, current_output_path, current_chunk + 1));
                    }
                }
            }
        }

        Ok(download_queue)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::LazyLock;

    use crate::{MediafireDownloader, types::DownloadError};
    const URL: LazyLock<Vec<String>> =
        LazyLock::new(|| vec!["https://www.mediafire.com/folder/akjcex4b8dgui".to_string()]);
    static DOWNLOADER: LazyLock<MediafireDownloader> =
        LazyLock::new(|| MediafireDownloader::new(5).unwrap());

    #[tokio::test]
    async fn files() -> Result<(), DownloadError> {
        let jobs = DOWNLOADER
            .get_download_jobs_with_progress(&URL, PathBuf::from("."), |job| println!("{job}"))
            .await?;
        assert!(jobs.len() == 136);
        Ok(())
    }

    #[tokio::test]
    async fn download() -> Result<(), DownloadError> {
        let mut jobs = DOWNLOADER
            .get_download_jobs(&URL, PathBuf::from("."))
            .await?;

        if let Some(job) = jobs.pop() {
            println!("{job:?}");
            job.download_with_progress(|status| println!("{status:?}"))
                .await?
        }

        Ok(())
    }

    #[tokio::test]
    async fn malware_detected_urls() -> Result<(), DownloadError> {
        let urls = vec![
            "https://www.mediafire.com/file/7f8x0azhs3pb1wm".to_string(),
            "https://www.mediafire.com/file/fauj29155dj6ol6".to_string(),
        ];

        let mut jobs = DOWNLOADER
            .get_download_jobs(&urls, PathBuf::from("."))
            .await?;

        while let Some(job) = jobs.pop() {
            println!("{job:?}");
            job.download_with_progress(|status| println!("{status:?}"))
                .await?
        }

        Ok(())
    }
}
