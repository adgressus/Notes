use std::env;
use std::fmt;
use std::sync::Mutex;
use std::time::Instant;

// ─── Error type ────────────────────────────────────────────────

pub enum UtilError {
    NotConfigured(String), // Environment variable or other configuration missing
    TokenError(String), // Error obtaining token (network, parsing, etc.)
}

impl fmt::Display for UtilError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UtilError::NotConfigured(msg) => write!(f, "not configured: {msg}"),
            UtilError::TokenError(msg) => write!(f, "token error: {msg}"),
        }
    }
}

// ─── Token cache ───────────────────────────────────────────────

struct CachedToken {
    token: String,
    acquired_at: Instant,
    expires_in: u64,
}

static TOKEN_CACHE: Mutex<Option<CachedToken>> = Mutex::new(None);

pub fn get_storage_token() -> Result<String, UtilError> {
    {
        let cache = TOKEN_CACHE.lock()
            .map_err(|e| UtilError::NotConfigured(format!("lock failed: {e}")))?;
        if let Some(cached) = cache.as_ref() {
            let elapsed = cached.acquired_at.elapsed().as_secs();
            if elapsed + 300 < cached.expires_in {
                return Ok(cached.token.clone());
            }
        }
    }

    let token_info = get_fresh_token()?;

    if let Ok(mut cache) = TOKEN_CACHE.lock() {
        *cache = Some(token_info);
    }

    TOKEN_CACHE
        .lock()
        .map_err(|e| UtilError::NotConfigured(format!("lock failed: {e}")))?
        .as_ref()
        .map(|t| t.token.clone())
        .ok_or_else(|| UtilError::NotConfigured("token cache empty after store".into()))
}

fn get_fresh_token() -> Result<CachedToken, UtilError> {
    let identity_endpoint = env::var("IDENTITY_ENDPOINT").ok();
    let identity_header = env::var("IDENTITY_HEADER").ok();

    let body = match (identity_endpoint, identity_header) {
        (Some(endpoint), Some(header)) => {
            let url = format!(
                "{}?api-version=2019-08-01&resource=https://storage.azure.com/",
                endpoint
            );
            let resp = ureq::get(&url)
                .header("X-IDENTITY-HEADER", &header)
                .call()
                .map_err(|e| UtilError::TokenError(format!("identity request: {e}")))?;
            resp.into_body().read_to_string()
                .map_err(|e| UtilError::TokenError(format!("identity response: {e}")))?
        }
        _ => {
            let output = std::process::Command::new("az")
                .args(["account", "get-access-token", "--resource",
                       "https://storage.azure.com/", "--output", "json"])
                .output()
                .map_err(|e| UtilError::NotConfigured(format!("az cli: {e}")))?;
            if !output.status.success() {
                return Err(UtilError::NotConfigured("az cli returned non-zero".into()));
            }
            String::from_utf8(output.stdout)
                .map_err(|e| UtilError::TokenError(format!("az cli output: {e}")))?
        }
    };

    let token = extract_json_string(&body, "access_token")
        .ok_or_else(|| UtilError::TokenError("missing access_token".into()))?;
    let expires_in = extract_json_string(&body, "expires_in")
        .or_else(|| extract_json_string(&body, "expires_on").map(|_| "3600".to_string()))
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3600);

    Ok(CachedToken {
        token,
        acquired_at: Instant::now(),
        expires_in,
    })
}

// ─── Shared helpers ────────────────────────────────────────────

pub fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!(r#""{}":"#, key);
    let start = json.find(&pattern)? + pattern.len();
    let rest = json[start..].trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    let rest = &rest[1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}
