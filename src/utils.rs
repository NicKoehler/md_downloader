/// Attempts to extract a download link from an HTML string.
///
/// Looks for a section of HTML between:
///     aria-label="Download file"
/// and:
///     id="downloadButton"
///
/// If found, it cleans the extracted substring and returns it as `Some(String)`.
/// Otherwise, returns `None`.
pub fn try_extract_link(html: String) -> Option<String> {
    if let Some(s) = html.split("aria-label=\"Download file\"").nth(1) {
        if let Some(s) = s.split("id=\"downloadButton\"").nth(0) {
            return Some(s.trim().replace("href=", "").replace("\"", ""));
        }
    }
    None
}
