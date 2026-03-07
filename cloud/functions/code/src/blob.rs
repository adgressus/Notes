use std::env;
use std::fmt;
use std::time::Duration;

use base64::Engine;
use hmac::{Hmac, Mac};
use log::{info, debug};
use sha2::Sha256;

use crate::util;

// ─── Error type ────────────────────────────────────────────────

pub enum BlobError {
    NotConfigured(String), // Environment variable or other configuration missing
    DelegationError(String), // Error obtaining user delegation key or generating SAS token
    ContainerCreateFailed(String),  // Error creating container (other than already exists)
}

impl fmt::Display for BlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlobError::NotConfigured(msg) => write!(f, "not configured: {msg}"),
            BlobError::DelegationError(msg) => write!(f, "delegation error: {msg}"),
            BlobError::ContainerCreateFailed(msg) => write!(f, "container create failed: {msg}"),
        }
    }
}

// ─── Internal types ────────────────────────────────────────────

struct UserDelegationKey {
    signed_oid: String,
    signed_tid: String,
    signed_start: String,
    signed_expiry: String,
    signed_service: String,
    signed_version: String,
    value: String,
}

// ─── Internal helpers ──────────────────────────────────────────

fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].to_string())
}

fn is_leap_year(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let mut y = 1970;
    let mut remaining = days;
    loop {
        let diy = if is_leap_year(y) { 366 } else { 365 };
        if remaining < diy {
            break;
        }
        remaining -= diy;
        y += 1;
    }
    let dim = if is_leap_year(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut m = 0;
    for &d in &dim {
        if remaining < d {
            break;
        }
        remaining -= d;
        m += 1;
    }
    (y, m + 1, remaining + 1)
}

fn format_iso8601(epoch_secs: u64) -> String {
    let days = epoch_secs / 86400;
    let time = epoch_secs % 86400;
    let (year, month, day) = days_to_ymd(days);
    let hours = time / 3600;
    let minutes = (time % 3600) / 60;
    let seconds = time % 60;
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

/// Obtain a user delegation key from Azure Blob Storage.
fn get_user_delegation_key(account: &str, token: &str) -> Result<UserDelegationKey, BlobError> {
    let now = now_secs();
    let start = format_iso8601(now);
    let expiry = format_iso8601(now + 3600);

    let url = format!(
        "https://{}.blob.core.windows.net/?restype=service&comp=userdelegationkey",
        account
    );
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <KeyInfo>\
         <Start>{start}</Start>\
         <Expiry>{expiry}</Expiry>\
         </KeyInfo>"
    );

    let resp = ureq::post(&url)
        .header("Authorization", &format!("Bearer {}", token))
        .header("x-ms-version", "2022-11-02")
        .header("Content-Type", "application/xml")
        .send(body.as_bytes())
        .map_err(|e| BlobError::DelegationError(format!("user delegation key: {e}")))?;

    let resp_body = resp.into_body().read_to_string()
        .map_err(|e| BlobError::DelegationError(format!("user delegation key body: {e}")))?;
    info!("User delegation key obtained");

    Ok(UserDelegationKey {
        signed_oid: extract_xml_value(&resp_body, "SignedOid")
            .ok_or_else(|| BlobError::DelegationError("missing SignedOid".into()))?,
        signed_tid: extract_xml_value(&resp_body, "SignedTid")
            .ok_or_else(|| BlobError::DelegationError("missing SignedTid".into()))?,
        signed_start: extract_xml_value(&resp_body, "SignedStart")
            .ok_or_else(|| BlobError::DelegationError("missing SignedStart".into()))?,
        signed_expiry: extract_xml_value(&resp_body, "SignedExpiry")
            .ok_or_else(|| BlobError::DelegationError("missing SignedExpiry".into()))?,
        signed_service: extract_xml_value(&resp_body, "SignedService")
            .ok_or_else(|| BlobError::DelegationError("missing SignedService".into()))?,
        signed_version: extract_xml_value(&resp_body, "SignedVersion")
            .ok_or_else(|| BlobError::DelegationError("missing SignedVersion".into()))?,
        value: extract_xml_value(&resp_body, "Value")
            .ok_or_else(|| BlobError::DelegationError("missing Value".into()))?,
    })
}

/// Ensure a blob container exists, creating it if necessary.
fn ensure_container(account: &str, token: &str, container: &str) -> Result<(), BlobError> {
    let url = format!(
        "https://{}.blob.core.windows.net/{}?restype=container",
        account, container
    );
    match ureq::put(&url)
        .header("Authorization", &format!("Bearer {}", token))
        .header("x-ms-version", "2022-11-02")
        .send(&[] as &[u8])
    {
        Ok(_) => {
            info!("Container created: {container}");
            Ok(())
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("409") {
                debug!("Container already exists: {container}");
                Ok(())
            } else {
                Err(BlobError::ContainerCreateFailed(format!("{container}: {e}")))
            }
        }
    }
}

/// Generate a user-delegation SAS token for a blob container.
fn generate_container_sas(
    account: &str,
    container: &str,
    key: &UserDelegationKey,
    permissions: &str,
    expiry_secs: u64,
) -> Result<String, BlobError> {
    let now = now_secs();

    let start = format_iso8601(now);
    let expiry = format_iso8601(now + expiry_secs);
    let version = "2022-11-02";
    let resource = "c";
    let canonical = format!("/blob/{}/{}", account, container);

    // String-to-sign for user delegation SAS (version 2020-12-06+)
    let string_to_sign = [
        permissions,
        &start,
        &expiry,
        &canonical,
        &key.signed_oid,
        &key.signed_tid,
        &key.signed_start,
        &key.signed_expiry,
        &key.signed_service,
        &key.signed_version,
        "", // signedAuthorizedUserObjectId
        "", // signedUnauthorizedUserObjectId
        "", // signedCorrelationId
        "", // signedIP
        "https",
        version,
        resource,
        "", // signedSnapshotTime
        "", // signedEncryptionScope
        "", // rscc
        "", // rscd
        "", // rsce
        "", // rscl
        "", // rsct
    ]
    .join("\n");

    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&key.value)
        .map_err(|e| BlobError::DelegationError(format!("decode delegation key: {e}")))?;

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(&key_bytes)
        .map_err(|e| BlobError::DelegationError(format!("HMAC init: {e}")))?;
    mac.update(string_to_sign.as_bytes());
    let signature = base64::engine::general_purpose::STANDARD
        .encode(mac.finalize().into_bytes());

    Ok(format!(
        "sv={}&sr={}&sp={}&st={}&se={}&spr=https&skoid={}&sktid={}&skt={}&ske={}&sks={}&skv={}&sig={}",
        version,
        resource,
        permissions,
        url_encode(&start),
        url_encode(&expiry),
        url_encode(&key.signed_oid),
        url_encode(&key.signed_tid),
        url_encode(&key.signed_start),
        url_encode(&key.signed_expiry),
        url_encode(&key.signed_service),
        url_encode(&key.signed_version),
        url_encode(&signature),
    ))
}

// ─── Public API ────────────────────────────────────────────────

/// Generate a SAS URL for a blob container. Ensures the container exists,
/// obtains a user delegation key, and returns a full URL with a 1-hour SAS token.
pub fn get_container_url(container: &str) -> Result<String, BlobError> {
    let account = env::var("USER_STORAGE_ACCOUNT_NAME")
        .map_err(|_| BlobError::NotConfigured("USER_STORAGE_ACCOUNT_NAME not set".into()))?;

    let token = util::get_storage_token()
        .map_err(|e| BlobError::NotConfigured(format!("{e}")))?;

    ensure_container(&account, &token, container)?;

    let delegation_key = get_user_delegation_key(&account, &token)?;

    let sas_token = generate_container_sas(
        &account, container, &delegation_key, "racwdl", 3600,
    )?;

    Ok(format!(
        "https://{}.blob.core.windows.net/{}?{}",
        account, container, sas_token
    ))
}
