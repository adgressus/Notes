mod blob;
mod jwt;
mod table;
mod util;

use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

use log::{info, warn, error, LevelFilter, Log, Metadata, Record};
use rand::RngExt;

use table::TableError;

struct ConsoleLogger;

impl Log for ConsoleLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            eprintln!("[{}] {}: {}", record.level(), record.module_path().unwrap_or("unknown"), record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: ConsoleLogger = ConsoleLogger;

fn random_hex(bytes: usize) -> String {
    let mut rng = rand::rng();
    (0..bytes)
        .map(|_| format!("{:02x}", rng.random::<u8>()))
        .collect()
}

// ─── Handlers ──────────────────────────────────────────────────

fn validate_link_code(code: &str) -> Option<String> {
    let body = match table::take("linkingcodes", "link_code", code) {
        Ok(b) => b,
        Err(e) => {
            info!("Link code lookup failed for '{code}': {e}");
            return None;
        }
    };

    let user_id = match util::extract_json_string(&body, "user_id") {
        Some(id) => id,
        None => {
            warn!("Link code '{code}' missing user_id");
            return None;
        }
    };

    info!("Link code '{code}' is valid, user_id: {user_id}");
    Some(user_id)
}

fn get_nonce(query: &str) -> (&'static str, String) {
    let nonce = random_hex(32);

    let raw_link_code = query
        .split('&')
        .filter_map(|p| p.strip_prefix("link_code="))
        .next();

    let link_user_id = if let Some(code) = raw_link_code {
        if code.len() != 6 || !code.chars().all(|ch| ch.is_ascii_digit()) {
            warn!("Malformed link code: {code}");
            return ("400 Bad Request", "invalid link code".to_string());
        }
        match validate_link_code(code) {
            Some(user_id) => Some(user_id),
            None => {
                return ("400 Bad Request", "invalid link code".to_string());
            }
        }
    } else {
        None
    };

    let linking_session = link_user_id.is_some();
    let user_id = link_user_id.as_deref().unwrap_or("");

    match table::insert(
        "nonces", "nonce", &nonce,
        &format!(r#""user_id": "{user_id}", "linking_session": {linking_session}"#),
        Some(300),
    ) {
        Ok(_) => info!("Nonce stored: {nonce}"),
        Err(e) => error!("Failed to store nonce: {e}"),
    }

    ("200 OK", nonce)
}

fn get_token(jwt: &str) -> (&'static str, String) {
    info!("get_token called, JWT length: {}", jwt.len());

    let jwt = jwt.trim();
    if jwt.is_empty() {
        warn!("get_token: empty body");
        return ("400 Bad Request", "missing token".to_string());
    }

    let claims = match jwt::validate(jwt) {
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

    let issuer = claims.iss.unwrap_or_default();
    info!("Token requested with nonce: {nonce}, sub: {:?}, iss: {issuer}", claims.sub);

    // Fetch and delete the nonce
    let nonce_body = match table::take("nonces", "nonce", &nonce) {
        Ok(b) => b,
        Err(TableError::NotFound) => {
            warn!("Nonce not found or expired: {nonce}");
            return ("401 Unauthorized", "unauthorized".to_string());
        }
        Err(e) => {
            error!("Nonce lookup failed: {e}");
            return ("500 Internal Server Error", "internal error".to_string());
        }
    };

    info!("Nonce verified: {nonce}");

    let sub = match claims.sub {
        Some(s) => s,
        None => {
            warn!("JWT missing sub claim");
            return ("400 Bad Request", "missing sub".to_string());
        }
    };

    // Resolve user_id: linking session or existing account lookup
    let nonce_user_id = util::extract_json_string(&nonce_body, "user_id")
        .unwrap_or_default();

    let user_id = if !nonce_user_id.is_empty() {
        // Linking session — create linked account
        let provider = jwt::issuer_to_provider(&issuer);
        match table::insert(
            "linkedaccounts", "linked_accounts", &sub,
            &format!(r#""account_provider": "{provider}", "user_id": "{nonce_user_id}""#),
            None,
        ) {
            Ok(_) => info!("Linked account created: sub={sub}, user_id={nonce_user_id}"),
            Err(TableError::Conflict) => {
                warn!("Linked account already exists: sub={sub}");
                return ("401 Unauthorized", "unauthorized".to_string());
            }
            Err(e) => {
                error!("Failed to create linked account: {e}");
                return ("500 Internal Server Error", "internal error".to_string());
            }
        }
        nonce_user_id
    } else {
        // Look up existing linked account
        let lookup_body = match table::get("linkedaccounts", "linked_accounts", &sub) {
            Ok(b) => b,
            Err(TableError::NotFound) => {
                warn!("No linked account for sub={sub}");
                return ("401 Unauthorized", "unauthorized".to_string());
            }
            Err(e) => {
                error!("Linked account lookup failed: {e}");
                return ("500 Internal Server Error", "internal error".to_string());
            }
        };
        match util::extract_json_string(&lookup_body, "user_id") {
            Some(id) => id,
            None => {
                warn!("Linked account row missing user_id for sub={sub}");
                return ("500 Internal Server Error", "internal error".to_string());
            }
        }
    };

    // Create session
    let refresh_token = random_hex(64);
    match table::insert(
        "sessions", "sessions", &refresh_token,
        &format!(r#""user_id": "{user_id}""#),
        Some(86400),
    ) {
        Ok(_) => info!("Session created for user {user_id}"),
        Err(e) => {
            error!("Failed to create session: {e}");
            return ("500 Internal Server Error", "internal error".to_string());
        }
    }

    ("200 OK", refresh_token)
}

fn get_url(body: &str) -> (&'static str, String) {
    let refresh_token = body.trim();
    if refresh_token.is_empty() {
        warn!("get_url: empty body");
        return ("400 Bad Request", "missing refresh token".to_string());
    }

    // Fetch and delete the old session
    let session_body = match table::take("sessions", "sessions", refresh_token) {
        Ok(b) => b,
        Err(TableError::NotFound) => {
            warn!("Session not found or expired");
            return ("401 Unauthorized", "invalid session".to_string());
        }
        Err(e) => {
            error!("Session lookup failed: {e}");
            return ("500 Internal Server Error", "internal error".to_string());
        }
    };

    let user_id = match util::extract_json_string(&session_body, "user_id") {
        Some(id) => id,
        None => {
            warn!("Session row missing user_id");
            return ("500 Internal Server Error", "internal error".to_string());
        }
    };

    // Create new session
    let new_refresh_token = random_hex(64);
    match table::insert(
        "sessions", "sessions", &new_refresh_token,
        &format!(r#""user_id": "{user_id}""#),
        Some(86400),
    ) {
        Ok(_) => info!("New session created for user {user_id}"),
        Err(e) => {
            error!("Failed to create new session: {e}");
            return ("500 Internal Server Error", "internal error".to_string());
        }
    }

    // Retrieve temporary URL for user's blob container
    let container = user_id.to_lowercase();

    let sas_url = match blob::get_container_url(&container) {
        Ok(url) => url,
        Err(e) => {
            error!("Failed to retrieve temporary URL: {e}");
            return ("500 Internal Server Error", "internal error".to_string());
        }
    };

    let response_body = format!(
        r#"{{"refresh_token":"{new_refresh_token}","url":"{sas_url}"}}"#
    );
    ("200 OK", response_body)
}

// ─── Router ────────────────────────────────────────────────────

fn main() {
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(LevelFilter::Debug);

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