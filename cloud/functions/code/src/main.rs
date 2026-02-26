use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use log::{info, warn, error, LevelFilter, Log, Metadata, Record};
use rand::RngExt;
use serde::Deserialize;

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

/// Store a nonce in Azure Table Storage with a 5-minute expiry.
fn store_nonce(nonce: &str) {
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
        r#"{{"PartitionKey": "nonce", "RowKey": "{nonce}", "created_at": "{created_at}", "expires_at": "{expires_at}"}}"#
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

fn get_nonce() -> (&'static str, String) {
    let nonce = generate_nonce();
    store_nonce(&nonce);
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

    // Get user ID from the nonce row
    let user_id = match extract_json_string(&nonce_body, "user_id") {
        Some(id) => id,
        None => {
            warn!("Nonce row missing user_id");
            return ("400 Bad Request", "missing user id".to_string());
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

        let (status, body) = if request_line.starts_with("GET /api/get_nonce") {
            get_nonce()
        } else if request_line.starts_with("POST /api/get_token") {
            get_token(&req_body)
        } else {
            ("404 Not Found", "not found".to_string())
        };

        info!("Response: {status}");

        let response = format!(
            "HTTP/1.1 {status}\r\n\
             Content-Type: text/plain\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {body}",
            body.len()
        );

        let _ = stream.write_all(response.as_bytes());
    }
}