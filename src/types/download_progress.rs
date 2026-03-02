#[derive(Debug, Clone)]
pub enum DownloadProgress {
    Done,
    GettingLink,
    TryResuming,
    CheckingHash,
    Downloading(u64, u64),
}
