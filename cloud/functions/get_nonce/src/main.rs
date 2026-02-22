use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Mutex};
use std::time::{Duration, Instant};

use log::{info, warn, error, LevelFilter, Log, Metadata, Record};

use rand::RngExt;

struct CachedToken {
    token: String,
    acquired_at: Instant,
    expires_in: u64,
}

static TOKEN_CACHE: Mutex<Option<CachedToken>> = Mutex::new(None);

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
                //track(&format!("az cli failed: {}", String::from_utf8_lossy(&output.stderr)), SEV_ERROR);
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

        let reader = BufReader::new(&stream);
        let request_line = match reader.lines().next() {
            Some(Ok(line)) => line,
            _ => continue,
        };

        let (status, body) = if request_line.starts_with("GET /api/get_nonce") {
            let nonce = generate_nonce();
            store_nonce(&nonce);
            ("200 OK", nonce)
        } else {
            ("404 Not Found", "not found".to_string())
        };

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