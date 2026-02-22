# Mediafire Downloader

High-level Rust library for downloading files and folders from **MediaFire** with recursive traversal, proxy support, and prioritized download queues.

## Features
- Communicates with MediaFire API for metadata & folder traversal
- Resolves files/folders into `DownloadJob`s
- Recursive folder downloading with optional progress updates
- Proxy support for API and downloads
- Configurable download order (largest-first or smallest-first)
- Async operations with `tokio`

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
mediafire_downloader = "0.1.0"
```

## Usage

Basic example:

```Rust
use mediafire_downloader::MediafireDownloader;
use std::path::PathBuf;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let downloader = MediafireDownloader::new(5)?;
    let urls = vec!["https://www.mediafire.com/folder/yourfolderkey".to_string()];
    let output_path = PathBuf::from("downloads");

    let jobs = downloader.get_download_jobs(&urls, output_path).await?;
    println!("Found {} files to download.", jobs.len());
    Ok(())
}
```

With progress updates:

```Rust
let jobs = downloader
    .get_download_jobs_with_progress(&urls, output_path, |folder| {
        println!("Processing folder: {}", folder);
    })
    .await?;
```

## API Highlights
- Initialize a `MediafireDownloader` with retry support: `MediafireDownloader::new(max_retries)`
- Resolve files and folders into `DownloadJob`s with:
  - `get_download_jobs(&urls, output_path).await`
  - `get_download_jobs_with_progress(&urls, output_path, |folder_name| {})`
- Configure download order: `reverse_downloads(true/false)`
- Set HTTP proxies for API and downloads: `set_proxies(Some(vec!["http://proxy:port"]), true/false)`
- Handles recursive folders, paginated folder contents, and prioritized download queues
- Async file downloading with progress callbacks

## Requirements
- Rust 1.75+  
- `tokio` async runtime  
- Optional: proxies require valid HTTP/S proxy URLs  
- Internet access to MediaFire

## License
Licensed under MIT
