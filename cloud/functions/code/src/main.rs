use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use log::{info, warn, error, LevelFilter, Log, Metadata, Record};
use rand::RngExt;
use serde::Deserialize;
use sha2::Sha256;

struct CachedToken {
    token: String,
    acquired_at: Instant,
    expires_in: u64,
}

static TOKEN_CACHE: Mutex<Option<CachedToken>> = Mutex::new(None);
static JWKS_CACHE: Mutex<Option<CachedJwks>> = Mutex::new(None);

#[derive(Deserialize)]
struct Claims {
    nonce: Option<String>,
    sub: Option<String>,
}

#[derive(Clone, Deserialize)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
}

#[derive(Clone, Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

struct CachedJwks {
    keys: Vec<Jwk>,
    fetched_at: Instant,
}

struct UserDelegationKey {
    signed_oid: String,
    signed_tid: String,
    signed_start: String,
    signed_expiry: String,
    signed_service: String,
    signed_version: String,
    value: String,
}

struct ConsoleLogger;

impl Log for ConsoleLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            eprintln!("[{}] {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: ConsoleLogger = ConsoleLogger;

fn generate_nonce() -> String {
    let mut rng = rand::rng();
    (0..32)
        .map(|_| format!("{:02x}", rng.random::<u8>()))
        .collect()
}

fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!(r#""{}":"#, key);
    let start = json.find(&pattern)? + pattern.len();
    let rest = &json[start..];
    // skip whitespace
    let rest = rest.trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    let rest = &rest[1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Acquire a Managed Identity token for Azure Storage.
/// On Azure Functions, uses IDENTITY_ENDPOINT + IDENTITY_HEADER.
/// Locally, falls back to `az account get-access-token`.
fn get_access_token() -> Option<String> {
    // Check cache first
    {
        let cache = TOKEN_CACHE.lock().ok()?;
        if let Some(cached) = cache.as_ref() {
            // Refresh if within 5 minutes of expiry
            let elapsed = cached.acquired_at.elapsed().as_secs();
            if elapsed + 300 < cached.expires_in {
                return Some(cached.token.clone());
            }
        }
    }

    let token_info = get_fresh_token()?;

    // Cache it
    if let Ok(mut cache) = TOKEN_CACHE.lock() {
        *cache = Some(token_info);
    }

    TOKEN_CACHE
        .lock()
        .ok()
        .and_then(|c| c.as_ref().map(|t| t.token.clone()))
}

fn get_fresh_token() -> Option<CachedToken> {
    let identity_endpoint = env::var("IDENTITY_ENDPOINT").ok();
    let identity_header = env::var("IDENTITY_HEADER").ok();

    let body = match (identity_endpoint, identity_header) {
        (Some(endpoint), Some(header)) => {
            // Running on Azure Functions
            let url = format!(
                "{}?api-version=2019-08-01&resource=https://storage.azure.com/",
                endpoint
            );
            let resp = ureq::get(&url)
                .header("X-IDENTITY-HEADER", &header)
                .call()
                .ok()?;
            resp.into_body().read_to_string().ok()?
        }
        _ => {
            // Local dev — try Azure CLI
            //track("No Managed Identity available, trying az cli...", SEV_INFO);
            let output = std::process::Command::new("az")
                .args([
                    "account",
                    "get-access-token",
                    "--resource",
                    "https://storage.azure.com/",
                    "--output",
                    "json",
                ])
                .output()
                .ok()?;
            if !output.status.success() {
                return None;
            }
            String::from_utf8(output.stdout).ok()?
        }
    };

    let token = extract_json_string(&body, "access_token")?;
    let expires_in = extract_json_string(&body, "expires_in")
        .or_else(|| extract_json_string(&body, "expires_on").map(|_| "3600".to_string()))
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3600);

    Some(CachedToken {
        token,
        acquired_at: Instant::now(),
        expires_in,
    })
}

/// Check whether a 6-digit linking code exists and has not expired.
/// Returns the user_id from the linking code row if valid.
fn validate_link_code(code: &str, account: &str, token: &str) -> Option<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();

    let url = format!(
        "https://{}.table.core.windows.net/linkingcodes(PartitionKey='link_code',RowKey='{}')",
        account, code
    );

    let resp = match ureq::get(&url)
        .header("Authorization", &format!("Bearer {}", token))
        .header("Accept", "application/json;odata=nometadata")
        .header("x-ms-version", "2019-02-02")
        .call()
    {
        Ok(r) => r,
        Err(e) => {
            info!("Link code lookup failed for '{code}': {e}");
            return None;
        }
    };

    let body = match resp.into_body().read_to_string() {
        Ok(b) => b,
        Err(_) => return None,
    };

    // expires_at is stored as Edm.Int64; the JSON value may be a string or number
    let expires_at: u64 = extract_json_string(&body, "expires_at")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if expires_at <= now {
        info!("Link code '{code}' has expired");
        return None;
    }

    let user_id = match extract_json_string(&body, "user_id") {
        Some(id) => id,
        None => {
            warn!("Link code '{code}' missing user_id");
            return None;
        }
    };

    info!("Link code '{code}' is valid, user_id: {user_id}");
    Some(user_id)
}

/// Store a nonce in Azure Table Storage with a 5-minute expiry.
fn store_nonce(nonce: &str, linking_session: bool, user_id: &str) {
    let account = match env::var("STORAGE_ACCOUNT_NAME") {
        Ok(a) => a,
        Err(_) => {
            warn!("STORAGE_ACCOUNT_NAME not set, skipping nonce storage");
            return;
        }
    };

    let token = match get_access_token() {
        Some(t) => t,
        None => {
            error!("Could not acquire access token, skipping nonce storage");
            return;
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0));
    let created_at = now.as_secs();
    let expires_at = created_at + 300; // 5 minutes

    let url = format!("https://{}.table.core.windows.net/nonces", account);
    let body = format!(
        r#"{{"PartitionKey": "nonce", "RowKey": "{nonce}", "user_id": "{user_id}", "linking_session": {linking_session}, "created_at": "{created_at}", "expires_at": "{expires_at}"}}"#
    );

    match ureq::post(&url)
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json;odata=nometadata")
        .header("x-ms-version", "2019-02-02")
        .header("Prefer", "return-no-content")
        .send(body.as_bytes())
    {
        Ok(_) => info!("Nonce stored: {nonce}"),
        Err(e) => error!("Failed to store nonce: {e}"),
    }
}


/// Fetch Microsoft's JWKS signing keys, cached for 1 hour.
fn get_jwks(tenant_id: &str) -> Option<Vec<Jwk>> {
    // Check cache (refresh every hour)
    {
        let cache = JWKS_CACHE.lock().ok()?;
        if let Some(cached) = cache.as_ref() {
            if cached.fetched_at.elapsed().as_secs() < 3600 {
                return Some(cached.keys.clone());
            }
        }
    }

    let url = format!(
        "https://login.microsoftonline.com/{}/discovery/v2.0/keys",
        tenant_id
    );
    info!("Fetching JWKS from {url}");

    let resp = ureq::get(&url).call().ok()?;
    let body = resp.into_body().read_to_string().ok()?;
    let jwks: JwksResponse = serde_json::from_str(&body).ok()?;

    if let Ok(mut cache) = JWKS_CACHE.lock() {
        *cache = Some(CachedJwks {
            keys: jwks.keys.clone(),
            fetched_at: Instant::now(),
        });
    }

    Some(jwks.keys)
}

/// Validate a JWT from Microsoft Entra ID.
/// Returns the claims if valid, or an error message.
fn validate_jwt(jwt: &str) -> Result<Claims, String> {
    let tenant_id = env::var("AZURE_TENANT_ID")
        .map_err(|_| "AZURE_TENANT_ID not set".to_string())?;
    let client_id = env::var("AZURE_CLIENT_ID")
        .map_err(|_| "AZURE_CLIENT_ID not set".to_string())?;

    // Decode header to find which key was used
    let header = decode_header(jwt)
        .map_err(|e| format!("Invalid JWT header: {e}"))?;
    let kid = header.kid
        .ok_or_else(|| "JWT missing kid in header".to_string())?;

    // Fetch JWKS and find matching key
    let keys = get_jwks(&tenant_id)
        .ok_or_else(|| "Failed to fetch JWKS".to_string())?;
    let jwk = keys.iter().find(|k| k.kid == kid)
        .ok_or_else(|| format!("No matching key for kid: {kid}"))?;

    let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
        .map_err(|e| format!("Invalid RSA key: {e}"))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[&client_id]);
    validation.set_issuer(&[
        format!("https://login.microsoftonline.com/{}/v2.0", tenant_id)
    ]);

    let token_data = decode::<Claims>(jwt, &decoding_key, &validation)
        .map_err(|e| format!("JWT validation failed: {e}"))?;

    Ok(token_data.claims)
}

fn get_nonce(query: &str) -> (&'static str, String) {
    let nonce = generate_nonce();

    // Check for a link_code query parameter (6 digits)
    let link_code = query
        .split('&')
        .filter_map(|p| p.strip_prefix("link_code="))
        .next()
        .filter(|c| c.len() == 6 && c.chars().all(|ch| ch.is_ascii_digit()));

    let link_user_id = if let Some(code) = link_code {
        let account = env::var("STORAGE_ACCOUNT_NAME").unwrap_or_default();
        match get_access_token() {
            Some(token) => validate_link_code(code, &account, &token),
            None => {
                error!("Could not acquire token to validate link code");
                None
            }
        }
    } else {
        None
    };

    let linking_session = link_user_id.is_some();
    let user_id = link_user_id.as_deref().unwrap_or("");
    store_nonce(&nonce, linking_session, user_id);
    ("200 OK", nonce)
}

fn get_token(jwt: &str) -> (&'static str, String) {
    info!("get_token called, JWT length: {}", jwt.len());

    let jwt = jwt.trim();
    if jwt.is_empty() {
        warn!("get_token: empty body");
        return ("400 Bad Request", "missing token".to_string());
    }

    // Validate the JWT signature and claims
    let claims = match validate_jwt(jwt) {
        Ok(c) => c,
        Err(e) => {
            warn!("JWT validation failed: {e}");
            return ("401 Unauthorized", "unauthorized".to_string());
        }
    };

    let nonce = match claims.nonce {
        Some(n) => n,
        None => {
            warn!("JWT missing nonce claim");
            return ("400 Bad Request", "bad request".to_string());
        }
    };

    info!("Token requested with nonce: {nonce}, sub: {:?}", claims.sub);

    // Verify the nonce exists in Table Storage
    let account = match env::var("STORAGE_ACCOUNT_NAME") {
        Ok(a) => a,
        Err(_) => {
            error!("STORAGE_ACCOUNT_NAME not set");
            return ("500 Internal Server Error", "internal error".to_string());
        }
    };

    let token = match get_access_token() {
        Some(t) => t,
        None => {
            error!("Could not acquire access token for nonce lookup");
            return ("500 Internal Server Error", "internal error".to_string());
        }
    };

    let url = format!(
        "https://{}.table.core.windows.net/nonces(PartitionKey='nonce',RowKey='{}')",
        account, nonce
    );

    // Fetch the nonce row to check expiry
    let nonce_body = match ureq::get(&url)
        .header("Authorization", &format!("Bearer {}", token))
        .header("Accept", "application/json;odata=nometadata")
        .header("x-ms-version", "2019-02-02")
        .call()
    {
        Ok(resp) => match resp.into_body().read_to_string() {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to read nonce response: {e}");
                return ("500 Internal Server Error", "internal error".to_string());
            }
        },
        Err(e) => {
            warn!("Nonce not found in storage: {e}");
            return ("401 Unauthorized", "invalid nonce".to_string());
        }
    };

    // Delete the nonce now that it's been used
    match ureq::delete(&url)
        .header("Authorization", &format!("Bearer {}", token))
        .header("If-Match", "*")
        .header("x-ms-version", "2019-02-02")
        .call()
    {
        Ok(_) => info!("Nonce deleted: {nonce}"),
        Err(e) => warn!("Failed to delete nonce: {e}"),
    }

    // Check if the nonce is expired
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();

    let expires_at = match extract_json_string(&nonce_body, "expires_at")
        .and_then(|s| s.parse::<u64>().ok())
    {
        Some(e) => e,
        None => {
            warn!("Nonce row missing expires_at");
            return ("401 Unauthorized", "invalid nonce".to_string());
        }
    };

    if now >= expires_at {
        warn!("Nonce expired: {nonce}");
        return ("401 Unauthorized", "nonce expired".to_string());
    }

    info!("Nonce verified and not expired: {nonce}");

    let sub = match claims.sub {
        Some(s) => s,
        None => {
            warn!("JWT missing sub claim");
            return ("400 Bad Request", "missing sub".to_string());
        }
    };

    // Get user_id from the nonce row (non-empty means linking session)
    let nonce_user_id = extract_json_string(&nonce_body, "user_id")
        .unwrap_or_default();

    let user_id = if !nonce_user_id.is_empty() {
        // Linking session — insert a row into linkedaccounts
        let created_at = now;
        let link_body = format!(
            r#"{{"PartitionKey": "linked_accounts", "RowKey": "{sub}", "account_provider": "microsoft", "user_id": "{nonce_user_id}", "created_at": "{created_at}"}}"#
        );
        let link_url = format!("https://{}.table.core.windows.net/linkedaccounts", account);
        match ureq::post(&link_url)
            .header("Authorization", &format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json;odata=nometadata")
            .header("x-ms-version", "2019-02-02")
            .header("Prefer", "return-no-content")
            .send(link_body.as_bytes())
        {
            Ok(_) => info!("Linked account created: sub={sub}, user_id={nonce_user_id}"),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("409") {
                    warn!("Linked account already exists: sub={sub}");
                    return ("400 Bad Request", "account already linked".to_string());
                }
                error!("Failed to create linked account: {e}");
                return ("500 Internal Server Error", "internal error".to_string());
            }
        }
        nonce_user_id
    } else {
        // Not a linking session — look up user_id from linkedaccounts via sub
        let lookup_url = format!(
            "https://{}.table.core.windows.net/linkedaccounts(PartitionKey='linked_accounts',RowKey='{}')",
            account, sub
        );
        let lookup_body = match ureq::get(&lookup_url)
            .header("Authorization", &format!("Bearer {}", token))
            .header("Accept", "application/json;odata=nometadata")
            .header("x-ms-version", "2019-02-02")
            .call()
        {
            Ok(resp) => match resp.into_body().read_to_string() {
                Ok(b) => b,
                Err(e) => {
                    error!("Failed to read linked account response: {e}");
                    return ("500 Internal Server Error", "internal error".to_string());
                }
            },
            Err(e) => {
                warn!("No linked account found for sub={sub}: {e}");
                return ("401 Unauthorized", "account not linked".to_string());
            }
        };
        match extract_json_string(&lookup_body, "user_id") {
            Some(id) => id,
            None => {
                warn!("Linked account row missing user_id for sub={sub}");
                return ("500 Internal Server Error", "internal error".to_string());
            }
        }
    };

    // Generate a 128-char refresh token
    let mut rng = rand::rng();
    let refresh_token: String = (0..64)
        .map(|_| format!("{:02x}", rng.random::<u8>()))
        .collect();

    // Store session in Table Storage
    let session_url = format!("https://{}.table.core.windows.net/sessions", account);
    let expires_at = now + 86400; // 1 day
    let session_body = format!(
        r#"{{"PartitionKey": "sessions", "RowKey": "{refresh_token}", "user_id": "{user_id}", "created_at": "{now}", "expires_at": "{expires_at}"}}"#
    );

    match ureq::post(&session_url)
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json;odata=nometadata")
        .header("x-ms-version", "2019-02-02")
        .header("Prefer", "return-no-content")
        .send(session_body.as_bytes())
    {
        Ok(_) => info!("Session created for user {user_id}"),
        Err(e) => {
            error!("Failed to create session: {e}");
            return ("500 Internal Server Error", "internal error".to_string());
        }
    }

    ("200 OK", refresh_token)
}

// ─── SAS URL generation helpers ────────────────────────────────

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

/// Obtain a user delegation key from Azure Blob Storage.
fn get_user_delegation_key(account: &str, token: &str) -> Option<UserDelegationKey> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();
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

    let resp = match ureq::post(&url)
        .header("Authorization", &format!("Bearer {}", token))
        .header("x-ms-version", "2022-11-02")
        .header("Content-Type", "application/xml")
        .send(body.as_bytes())
    {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to get user delegation key: {e}");
            return None;
        }
    };

    let resp_body = resp.into_body().read_to_string().ok()?;
    info!("User delegation key obtained");

    Some(UserDelegationKey {
        signed_oid: extract_xml_value(&resp_body, "SignedOid")?,
        signed_tid: extract_xml_value(&resp_body, "SignedTid")?,
        signed_start: extract_xml_value(&resp_body, "SignedStart")?,
        signed_expiry: extract_xml_value(&resp_body, "SignedExpiry")?,
        signed_service: extract_xml_value(&resp_body, "SignedService")?,
        signed_version: extract_xml_value(&resp_body, "SignedVersion")?,
        value: extract_xml_value(&resp_body, "Value")?,
    })
}

/// Ensure a blob container exists, creating it if necessary.
fn ensure_user_container(account: &str, token: &str, container: &str) -> bool {
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
            true
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("409") {
                info!("Container already exists: {container}");
                true
            } else {
                error!("Failed to create container '{container}': {e}");
                false
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
) -> Option<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();

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
        .ok()?;

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(&key_bytes).ok()?;
    mac.update(string_to_sign.as_bytes());
    let signature = base64::engine::general_purpose::STANDARD
        .encode(mac.finalize().into_bytes());

    Some(format!(
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

fn get_url(body: &str) -> (&'static str, String) {
    let refresh_token = body.trim();
    if refresh_token.is_empty() {
        warn!("get_url: empty body");
        return ("400 Bad Request", "missing refresh token".to_string());
    }

    let account = match env::var("STORAGE_ACCOUNT_NAME") {
        Ok(a) => a,
        Err(_) => {
            error!("STORAGE_ACCOUNT_NAME not set");
            return ("500 Internal Server Error", "internal error".to_string());
        }
    };

    let user_account = match env::var("USER_STORAGE_ACCOUNT_NAME") {
        Ok(a) => a,
        Err(_) => {
            error!("USER_STORAGE_ACCOUNT_NAME not set");
            return ("500 Internal Server Error", "internal error".to_string());
        }
    };

    let token = match get_access_token() {
        Some(t) => t,
        None => {
            error!("Could not acquire access token");
            return ("500 Internal Server Error", "internal error".to_string());
        }
    };

    // Look up the session
    let url = format!(
        "https://{}.table.core.windows.net/sessions(PartitionKey='sessions',RowKey='{}')",
        account, refresh_token
    );

    let session_body = match ureq::get(&url)
        .header("Authorization", &format!("Bearer {}", token))
        .header("Accept", "application/json;odata=nometadata")
        .header("x-ms-version", "2019-02-02")
        .call()
    {
        Ok(resp) => match resp.into_body().read_to_string() {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to read session response: {e}");
                return ("500 Internal Server Error", "internal error".to_string());
            }
        },
        Err(e) => {
            warn!("Session not found: {e}");
            return ("401 Unauthorized", "invalid session".to_string());
        }
    };

    // Check expiry
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();

    let expires_at = match extract_json_string(&session_body, "expires_at")
        .and_then(|s| s.parse::<u64>().ok())
    {
        Some(e) => e,
        None => {
            warn!("Session row missing expires_at");
            return ("401 Unauthorized", "invalid session".to_string());
        }
    };

    if now >= expires_at {
        warn!("Session expired for token");
        return ("401 Unauthorized", "session expired".to_string());
    }

    let user_id = match extract_json_string(&session_body, "user_id") {
        Some(id) => id,
        None => {
            warn!("Session row missing user_id");
            return ("500 Internal Server Error", "internal error".to_string());
        }
    };

    // Delete the old session
    match ureq::delete(&url)
        .header("Authorization", &format!("Bearer {}", token))
        .header("If-Match", "*")
        .header("x-ms-version", "2019-02-02")
        .call()
    {
        Ok(_) => info!("Old session deleted"),
        Err(e) => warn!("Failed to delete old session: {e}"),
    }

    // Generate a new refresh token
    let mut rng = rand::rng();
    let new_refresh_token: String = (0..64)
        .map(|_| format!("{:02x}", rng.random::<u8>()))
        .collect();

    // Store new session
    let session_url = format!("https://{}.table.core.windows.net/sessions", account);
    let new_expires_at = now + 86400; // 1 day
    let new_session_body = format!(
        r#"{{"PartitionKey": "sessions", "RowKey": "{new_refresh_token}", "user_id": "{user_id}", "created_at": "{now}", "expires_at": "{new_expires_at}"}}"#
    );

    match ureq::post(&session_url)
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json;odata=nometadata")
        .header("x-ms-version", "2019-02-02")
        .header("Prefer", "return-no-content")
        .send(new_session_body.as_bytes())
    {
        Ok(_) => info!("New session created for user {user_id}"),
        Err(e) => {
            error!("Failed to create new session: {e}");
            return ("500 Internal Server Error", "internal error".to_string());
        }
    }

    // Generate SAS URL for user's blob container
    let container = user_id.to_lowercase();

    if !ensure_user_container(&user_account, &token, &container) {
        return ("500 Internal Server Error", "failed to create storage container".to_string());
    }

    let delegation_key = match get_user_delegation_key(&user_account, &token) {
        Some(k) => k,
        None => {
            error!("Failed to get user delegation key");
            return ("500 Internal Server Error", "internal error".to_string());
        }
    };

    let sas_token = match generate_container_sas(
        &user_account, &container, &delegation_key, "racwdl", 3600,
    ) {
        Some(s) => s,
        None => {
            error!("Failed to generate SAS token");
            return ("500 Internal Server Error", "internal error".to_string());
        }
    };

    let sas_url = format!(
        "https://{}.blob.core.windows.net/{}?{}",
        user_account, container, sas_token
    );

    let response_body = format!(
        r#"{{"refresh_token":"{new_refresh_token}","url":"{sas_url}"}}"#
    );
    ("200 OK", response_body)
}

fn main() {
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(LevelFilter::Info);

    let port: u16 = env::var("FUNCTIONS_CUSTOMHANDLER_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3000);

    info!("Starting custom handler on port {port}");
    let listener = TcpListener::bind(format!("127.0.0.1:{port}"))
        .expect("Failed to bind to port");

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };

        let mut reader = BufReader::new(&stream);
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).is_err() {
            continue;
        }

        // Parse headers to get Content-Length
        let mut content_length: usize = 0;
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
                break;
            }
            if let Some(val) = header.strip_prefix("Content-Length: ") {
                content_length = val.trim().parse().unwrap_or(0);
            }
        }

        // Read body if present
        let req_body = if content_length > 0 {
            let mut buf = vec![0u8; content_length];
            use std::io::Read;
            reader.read_exact(&mut buf).ok();
            String::from_utf8(buf).unwrap_or_default()
        } else {
            String::new()
        };

        info!("Request: {}", request_line.trim());
        if content_length > 0 {
            info!("Body ({content_length} bytes): {req_body}");
        }

        // Extract query string for GET requests
        let query = request_line
            .split_once('?')
            .and_then(|(_, rest)| rest.split_once(' '))
            .map(|(q, _)| q)
            .unwrap_or("");

        let (status, body) = if request_line.starts_with("GET /api/get_nonce") {
            get_nonce(query)
        } else if request_line.starts_with("POST /api/get_token") {
            get_token(&req_body)
        } else if request_line.starts_with("POST /api/get_url") {
            get_url(&req_body)
        } else {
            ("404 Not Found", "not found".to_string())
        };

        info!("Response: {status}");

        let content_type = if body.starts_with('{') {
            "application/json"
        } else {
            "text/plain"
        };

        let response = format!(
            "HTTP/1.1 {status}\r\n\
             Content-Type: {content_type}\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {body}",
            body.len()
        );

        let _ = stream.write_all(response.as_bytes());
    }
}