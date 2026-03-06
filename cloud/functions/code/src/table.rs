use std::env;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use log::{debug, warn};

// ─── Error type ────────────────────────────────────────────────

pub enum TableError {
    NotFound, // Row does not exist in table
    Conflict, // Row already exists in table
    NotConfigured(String), // Environment variable or other configuration missing
    ConnectionError(String), // Network or other error before receiving response
    BadResponse(String), // Response received but invalid or malformed
    HttpError(u16), // Unexpected HTTP status code (other than 404 or 409)
}

impl fmt::Display for TableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TableError::NotFound => write!(f, "not found"),
            TableError::Conflict => write!(f, "conflict"),
            TableError::NotConfigured(msg) => write!(f, "not configured: {msg}"),
            TableError::ConnectionError(msg) => write!(f, "connection error: {msg}"),
            TableError::BadResponse(msg) => write!(f, "bad response: {msg}"),
            TableError::HttpError(code) => write!(f, "HTTP {code}"),
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

fn get_access_token() -> Result<String, TableError> {
    {
        let cache = TOKEN_CACHE.lock()
            .map_err(|e| TableError::NotConfigured(format!("lock failed: {e}")))?;
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
        .map_err(|e| TableError::NotConfigured(format!("lock failed: {e}")))?
        .as_ref()
        .map(|t| t.token.clone())
        .ok_or_else(|| TableError::NotConfigured("token cache empty after store".into()))
}

fn get_fresh_token() -> Result<CachedToken, TableError> {
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
                .map_err(|e| TableError::ConnectionError(format!("identity request: {e}")))?;
            resp.into_body().read_to_string()
                .map_err(|e| TableError::BadResponse(format!("identity response: {e}")))?
        }
        _ => {
            let output = std::process::Command::new("az")
                .args(["account", "get-access-token", "--resource",
                       "https://storage.azure.com/", "--output", "json"])
                .output()
                .map_err(|e| TableError::NotConfigured(format!("az cli: {e}")))?;
            if !output.status.success() {
                return Err(TableError::NotConfigured("az cli returned non-zero".into()));
            }
            String::from_utf8(output.stdout)
                .map_err(|e| TableError::BadResponse(format!("az cli output: {e}")))?
        }
    };

    let token = extract_json_string(&body, "access_token")
        .ok_or_else(|| TableError::BadResponse("missing access_token".into()))?;
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

fn extract_json_string(json: &str, key: &str) -> Option<String> {
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

// ─── Internal helpers ──────────────────────────────────────────

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

fn account() -> Result<String, TableError> {
    env::var("STORAGE_ACCOUNT_NAME")
        .map_err(|_| TableError::NotConfigured("STORAGE_ACCOUNT_NAME not set".into()))
}

fn entity_url(account: &str, table: &str, partition_key: &str, row_key: &str) -> String {
    format!(
        "https://{}.table.core.windows.net/{}(PartitionKey='{}',RowKey='{}')",
        account, table, partition_key, row_key
    )
}

fn classify_error(e: ureq::Error) -> TableError {
    match e {
        ureq::Error::StatusCode(404) => TableError::NotFound,
        ureq::Error::StatusCode(409) => TableError::Conflict,
        ureq::Error::StatusCode(code) => TableError::HttpError(code),
        ureq::Error::Io(ref io_err) => {
            TableError::ConnectionError(format!("{io_err}"))
        }
        ureq::Error::HostNotFound => {
            TableError::ConnectionError("host not found".into())
        }
        ureq::Error::ConnectionFailed => {
            TableError::ConnectionError("connection failed".into())
        }
        ureq::Error::Timeout(kind) => {
            TableError::ConnectionError(format!("timeout: {kind:?}"))
        }
        ureq::Error::Protocol(ref proto_err) => {
            TableError::BadResponse(format!("{proto_err}"))
        }
        other => TableError::ConnectionError(format!("{other}")),
    }
}

fn is_expired(body: &str) -> bool {
    extract_json_string(body, "expires_at")
        .and_then(|s| s.parse::<u64>().ok())
        .is_some_and(|exp| now_epoch_secs() >= exp)
}

fn best_effort_delete(url: &str, token: &str, table: &str, partition_key: &str, row_key: &str) {
    match ureq::delete(url)
        .header("Authorization", &format!("Bearer {}", token))
        .header("If-Match", "*")
        .header("x-ms-version", "2019-02-02")
        .call()
    {
        Ok(_) => debug!("Deleted {table}[{partition_key}, {row_key}]"),
        Err(e) => warn!("Failed to delete {table}[{partition_key}, {row_key}]: {e}"),
    }
}

// ─── Public API ────────────────────────────────────────────────

/// Expose the cached access token for use by other storage operations (e.g. blob).
pub fn get_storage_token() -> Result<String, TableError> {
    get_access_token()
}

/// Read a single entity from a table. Returns NotFound if the row is expired.
pub fn get(
    table: &str,
    partition_key: &str,
    row_key: &str,
) -> Result<String, TableError> {
    let account = account()?;
    let token = get_access_token()?;
    let url = entity_url(&account, table, partition_key, row_key);

    let resp = ureq::get(&url)
        .header("Authorization", &format!("Bearer {}", token))
        .header("Accept", "application/json;odata=nometadata")
        .header("x-ms-version", "2019-02-02")
        .call()
        .map_err(classify_error)?;

    let body = resp.into_body()
        .read_to_string()
        .map_err(|e| TableError::BadResponse(format!("read body: {e}")))?;

    if is_expired(&body) {
        best_effort_delete(&url, &token, table, partition_key, row_key);
        return Err(TableError::NotFound);
    }

    Ok(body)
}

/// Read then delete an entity. Returns NotFound if the row is expired.
/// Delete failure is logged but not fatal.
pub fn take(
    table: &str,
    partition_key: &str,
    row_key: &str,
) -> Result<String, TableError> {
    let account = account()?;
    let token = get_access_token()?;
    let url = entity_url(&account, table, partition_key, row_key);

    let resp = ureq::get(&url)
        .header("Authorization", &format!("Bearer {}", token))
        .header("Accept", "application/json;odata=nometadata")
        .header("x-ms-version", "2019-02-02")
        .call()
        .map_err(classify_error)?;

    let body = resp
        .into_body()
        .read_to_string()
        .map_err(|e| TableError::BadResponse(format!("read body: {e}")))?;

    best_effort_delete(&url, &token, table, partition_key, row_key);

    if is_expired(&body) {
        return Err(TableError::NotFound);
    }

    Ok(body)
}

/// Insert a new entity into a table. Automatically adds PartitionKey, RowKey,
/// and created_at. If `expiry_secs` is Some, also adds expires_at.
pub fn insert(
    table: &str,
    partition_key: &str,
    row_key: &str,
    fields: &str,
    expiry_secs: Option<u64>,
) -> Result<(), TableError> {
    let account = account()?;
    let token = get_access_token()?;
    let now = now_epoch_secs();

    let expiry_field = match expiry_secs {
        Some(secs) => format!(r#", "expires_at": "{}""#, now + secs),
        None => String::new(),
    };

    let extra = if fields.is_empty() {
        String::new()
    } else {
        format!(", {fields}")
    };

    let body = format!(
        r#"{{"PartitionKey": "{partition_key}", "RowKey": "{row_key}", "created_at": "{now}"{expiry_field}{extra}}}"#
    );

    let url = format!("https://{}.table.core.windows.net/{}", account, table);

    ureq::post(&url)
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json;odata=nometadata")
        .header("x-ms-version", "2019-02-02")
        .header("Prefer", "return-no-content")
        .send(body.as_bytes())
        .map_err(classify_error)?;

    Ok(())
}