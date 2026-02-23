use reqwest::header::{HeaderMap, SET_COOKIE};

/// Attempts to extract a download link from an HTML string.
///
/// Looks for a section of HTML between:
///     aria-label="Download file"
/// and:
///     id="downloadButton"
///
/// If found, it cleans the extracted substring and returns it as `Some(String)`.
/// Otherwise, returns `None`.
pub fn try_extract_link_from_normal_html(html: &String) -> Option<String> {
    if let Some(s) = html.split("aria-label=\"Download file\"").nth(1) {
        if let Some(s) = s.split("id=\"downloadButton\"").nth(0) {
            return Some(s.trim().replace("href=", "").replace("\"", ""));
        }
    }
    None
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
