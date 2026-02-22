#[derive(Debug)]
pub enum DownloadProgress {
    Done,
    GettingLink,
    TryResuming,
    CheckingHash,
    Downloading(u64, u64),
}
