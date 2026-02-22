use md_api::types::ApiError;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum DownloadError {
    IoError,
    UnknownHash,
    HashMismatch,
    ClientInitError,
    LinkExtractionError,
    ApiError(ApiError),
    InvalidProxy(String),
}

impl fmt::Display for DownloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DownloadError::ApiError(e) => write!(f, "ApiError: {e}"),
            DownloadError::IoError => write!(f, "IoError"),
            DownloadError::LinkExtractionError => write!(f, "LinkExtractionError"),
            DownloadError::HashMismatch => write!(f, "HashMismatch"),
            DownloadError::UnknownHash => write!(f, "UnknownHash"),
            DownloadError::InvalidProxy(e) => write!(f, "InvalidProxy: {e}"),
            DownloadError::ClientInitError => write!(f, "ClientInitError"),
        }
    }
}

impl Error for DownloadError {}
