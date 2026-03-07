use std::env;
use std::fmt;
use std::time::Duration;

use log::{debug, warn};

use crate::util;

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
    util::extract_json_string(body, "expires_at")
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

/// Read a single entity from a table. Returns NotFound if the row is expired.
pub fn get(
    table: &str,
    partition_key: &str,
    row_key: &str,
) -> Result<String, TableError> {
    let account = account()?;
    let token = util::get_storage_token()
        .map_err(|e| TableError::NotConfigured(format!("{e}")))?;
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
    let token = util::get_storage_token()
        .map_err(|e| TableError::NotConfigured(format!("{e}")))?;
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
    let token = util::get_storage_token()
        .map_err(|e| TableError::NotConfigured(format!("{e}")))?;
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