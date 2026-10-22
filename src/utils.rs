use regex::Regex;
use reqwest::header::{HeaderMap, SET_COOKIE};
use std::sync::LazyLock;

/// Matches direct MediaFire CDN download links (e.g. `https://download939.mediafire.com/...`)
/// found inside an `href` attribute, regardless of where or in what order they appear.
static CDN_DOWNLOAD_LINK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(https://download\d+\.mediafire\.com/[^"\s]+)"#).unwrap()
});

/// Attempts to extract a download link from an HTML string.
///
/// First looks for a section of HTML between:
///     aria-label="Download file"
/// and:
///     id="downloadButton"
///
/// If that layout is not found (for example on `?action=check` pages where the
/// attribute order differs), it falls back to searching the whole document for
/// a direct MediaFire CDN download link (`https://download<digits>.mediafire.com/...`).
///
/// Returns `Some(String)` with the download link if one can be extracted,
/// otherwise `None`.
pub fn try_extract_link_from_normal_html(html: &str) -> Option<String> {
    if let Some(s) = html.split("aria-label=\"Download file\"").nth(1) {
        if let Some(s) = s.split("id=\"downloadButton\"").nth(0) {
            let link = s.trim().replace("href=", "").replace("\"", "");
            // A valid extraction is a bare URL: no markup or whitespace left over.
            if link.starts_with("http") && !link.contains(['>', ' ', '\t', '\n']) {
                return Some(link);
            }
        }
    }

    CDN_DOWNLOAD_LINK.captures(html).map(|c| c[1].to_string())
}

/// Attempts to extract a security token and password from a malware-detected mediafire HTML string.
///
/// This function extracts two values from the provided HTML:
///
/// 1. A password value located between:
///        `{pass: '`
///    and the next single quote `'`.
///
/// 2. A security token located inside the attribute:
///        `data-security-token="..."`
///
/// Returns:
/// - `Some((String, String))` containing:
///     - The extracted security token
///     - The extracted password
/// - `None` if:
///     - Either pattern is not found,
///     - The expected delimiters are missing,
///     - The HTML does not match the assumed structure.
pub fn try_extract_security_token_from_malware_html(html: &String) -> Option<(String, String)> {
    if let Some(s) = html.split("{pass: '").nth(1) {
        if let Some(pass) = s.split("'").nth(0) {
            if let Some(s) = html.split("data-security-token=\"").nth(2) {
                if let Some(security_token) = s.split("\"").nth(0) {
                    return Some((security_token.to_string(), pass.to_string()));
                }
            }
        }
    }
    None
}

/// Attempts to extract the `ukey` value from the `Set-Cookie` header.
///
/// Returns:
/// - `Some(String)` containing the extracted `ukey` value if found and valid.
/// - `None` if:
///   - The `SET_COOKIE` header is missing,
///   - The header cannot be converted to a valid string,
///   - The cookie format does not match the expected structure.
pub fn extract_ukey(headers: &HeaderMap) -> Option<String> {
    if let Some(cookies) = headers.get(SET_COOKIE) {
        if let Some(s) = cookies.to_str().ok()?.split("; ").nth(0) {
            return Some(s.replace("ukey=", ""));
        }
    }
    None
}

#[cfg(test)]
mod test {
    use super::try_extract_link_from_normal_html;

    const CDN_LINK: &str = "https://download939.mediafire.com/3x2lgmo8aw9/t9n6mnuf9a0t3u9/file.rar";

    #[test]
    fn standard_layout() {
        let html = r#"<a class="input popsok" aria-label="Download file" href="https://download939.mediafire.com/3x2lgmo8aw9/t9n6mnuf9a0t3u9/file.rar" id="downloadButton" rel="nofollow">Download</a>"#;
        assert_eq!(
            try_extract_link_from_normal_html(html),
            Some(CDN_LINK.to_string())
        );
    }

    #[test]
    fn reversed_attribute_order() {
        let html = r#"<a id="downloadButton" aria-label="Download file" href="https://download939.mediafire.com/3x2lgmo8aw9/t9n6mnuf9a0t3u9/file.rar">Download</a>"#;
        assert_eq!(
            try_extract_link_from_normal_html(html),
            Some(CDN_LINK.to_string())
        );
    }

    #[test]
    fn cdn_link_anywhere_fallback() {
        let html = r#"<html><body><div class="whatever"><a href="https://download939.mediafire.com/3x2lgmo8aw9/t9n6mnuf9a0t3u9/file.rar">Download (1.93GB)</a></div></body></html>"#;
        assert_eq!(
            try_extract_link_from_normal_html(html),
            Some(CDN_LINK.to_string())
        );
    }

    #[test]
    fn no_link_returns_none() {
        let html = r#"<html><body><p>No downloads here</p></body></html>"#;
        assert_eq!(try_extract_link_from_normal_html(html), None);
    }
}
