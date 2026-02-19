use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::Rng;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

/// Azure AD / Entra ID OAuth2 endpoints
const AUTHORIZE_URL: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
const TOKEN_URL: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";

/// Default scopes for Microsoft login
const DEFAULT_SCOPES: &str = "openid offline_access";

/// Token response from Microsoft identity platform
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
}

/// Generates a cryptographically random PKCE code verifier (43-128 chars, URL-safe)
fn generate_code_verifier() -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    URL_SAFE_NO_PAD.encode(&bytes)
}

/// Derives the S256 code challenge from the verifier
fn generate_code_challenge(verifier: &str) -> String {
    let hash = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(&hash)
}

/// Performs the OAuth2 Authorization Code flow with PKCE (equivalent to MSAL loginPopup).
///
/// 1. Starts a local HTTP server on a random port
/// 2. Opens the system browser to Microsoft's authorize endpoint
/// 3. Waits for the redirect with the authorization code
/// 4. Exchanges the code for tokens
pub async fn login_with_microsoft() -> Result<TokenResponse, Box<dyn std::error::Error>> {
    //App name: public-microsoft-user-accounts-interface_notes
    let client_id = "397dc399-b9a1-4e0f-90e2-eb3a6a83147b";

    // Bind to a random available port on localhost
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let redirect_uri = format!("http://localhost:{}", port);
    println!("[Auth] Listening for redirect on {}", redirect_uri);

    // Generate PKCE code verifier and challenge
    let code_verifier = generate_code_verifier();
    let code_challenge = generate_code_challenge(&code_verifier);

    // Build the authorization URL
    let auth_url = format!(
        "{}?client_id={}&response_type=code&redirect_uri={}&response_mode=query\
         &scope={}&code_challenge={}&code_challenge_method=S256",
        AUTHORIZE_URL,
        percent_encode(&client_id),
        percent_encode(&redirect_uri),
        percent_encode(DEFAULT_SCOPES),
        percent_encode(&code_challenge),
    );

    println!("[Auth] Opening browser for Microsoft login...");
    open_browser(&auth_url)?;

    // Wait for the redirect (blocking)
    println!("[Auth] Waiting for authorization callback...");
    let auth_code = wait_for_auth_code(&listener)?;
    println!(
        "[Auth] Received authorization code: {}...",
        &auth_code[..10.min(auth_code.len())]
    );

    // Exchange authorization code for tokens
    println!("[Auth] Exchanging code for tokens...");
    let token = exchange_code_for_token(&client_id, &auth_code, &redirect_uri, &code_verifier).await?;

    // Verify and decode the id_token
    if let Some(ref id_token) = token.id_token {
        println!("[Auth] Verifying id_token signature with Microsoft's public keys...");
        match verify_and_decode_id_token(id_token, &client_id).await {
            Ok(claims) => {
                println!("[Auth] --- ID Token Claims (verified) ---");
                for (key, value) in claims.as_object().unwrap_or(&serde_json::Map::new()) {
                    println!("[Auth]   {} = {}", key, value);
                }
                println!("[Auth] --- End ID Token Claims ---");
            }
            Err(e) => {
                eprintln!("[Auth] WARNING: id_token verification failed: {}", e);
            }
        }
    }

    Ok(token)
}

/// Percent-encodes a string for use in URLs
fn percent_encode(s: &str) -> String {
    let mut out = String::new();
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

/// Opens the default browser on Windows using ShellExecuteW
fn open_browser(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    use windows::core::*;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::Foundation::HWND;

    let url_wide: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        ShellExecuteW(
            HWND::default(),
            w!("open"),
            PCWSTR(url_wide.as_ptr()),
            None,
            None,
            windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
        );
    }
    Ok(())
}

/// Waits for the OAuth2 redirect on the local listener and extracts the auth code
fn wait_for_auth_code(listener: &TcpListener) -> Result<String, Box<dyn std::error::Error>> {
    let (mut stream, _) = listener.accept()?;

    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    // Log the full request line
    println!("[Auth] Raw redirect request: {}", request_line.trim());

    // Read and log all headers
    loop {
        let mut header_line = String::new();
        reader.read_line(&mut header_line)?;
        if header_line.trim().is_empty() {
            break;
        }
        println!("[Auth] Header: {}", header_line.trim());
    }

    // Parse "GET /?code=...&state=... HTTP/1.1"
    let path = request_line
        .split_whitespace()
        .nth(1)
        .ok_or("Invalid HTTP request")?;

    // Log all query parameters
    if let Some(query) = path.split('?').nth(1) {
        println!("[Auth] --- Query parameters ---");
        for pair in query.split('&') {
            let mut parts = pair.splitn(2, '=');
            if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                println!("[Auth]   {} = {}", key, percent_decode(value));
            }
        }
        println!("[Auth] --- End query parameters ---");
    }

    // Check for error response
    if path.contains("error=") {
        let error_desc = extract_query_param(path, "error_description")
            .unwrap_or_else(|| {
                extract_query_param(path, "error").unwrap_or_else(|| "Unknown error".into())
            });

        let body = format!(
            "<html><body><h2>Authentication Failed</h2><p>{}</p>\
             <p>You can close this window.</p></body></html>",
            error_desc
        );
        send_http_response(&mut stream, &body)?;
        return Err(format!("Authorization denied: {}", error_desc).into());
    }

    // Extract the authorization code
    let code = extract_query_param(path, "code")
        .ok_or("No authorization code in redirect")?;

    let body = "<html><body><h2>Authentication Successful</h2>\
                <p>You can close this window and return to the application.</p></body></html>";
    send_http_response(&mut stream, body)?;

    Ok(code)
}

/// Sends a minimal HTTP 200 response
fn send_http_response(stream: &mut std::net::TcpStream, body: &str) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

/// Extracts a query parameter value from a URL path like /?key=value&...
fn extract_query_param(path: &str, param: &str) -> Option<String> {
    let query = path.split('?').nth(1)?;
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
            if key == param {
                return Some(percent_decode(value));
            }
        }
    }
    None
}

/// Decodes percent-encoded strings
fn percent_decode(s: &str) -> String {
    let mut result = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("00"),
                16,
            ) {
                result.push(byte);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            result.push(b' ');
            i += 1;
            continue;
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).to_string()
}

/// Exchanges the authorization code for tokens via the token endpoint
async fn exchange_code_for_token(
    client_id: &str,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<TokenResponse, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();

    let params = [
        ("client_id", client_id),
        ("scope", DEFAULT_SCOPES),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("grant_type", "authorization_code"),
        ("code_verifier", code_verifier),
    ];

    let response = client.post(TOKEN_URL).form(&params).send().await?;

    let status = response.status();
    let body_text = response.text().await?;
    println!("[Auth] Token response status: {}", status);
    println!("[Auth] Token response body: {}", body_text);

    if !status.is_success() {
        return Err(format!("Token exchange failed: {}", body_text).into());
    }

    let token: TokenResponse = serde_json::from_str(&body_text)?;
    Ok(token)
}

/// Microsoft's JWKS (JSON Web Key Set) endpoint
const JWKS_URL: &str = "https://login.microsoftonline.com/common/discovery/v2.0/keys";

/// A single JSON Web Key from the JWKS endpoint
#[derive(Debug, Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    n: String,
    e: String,
}

/// The JWKS response
#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

/// Fetches Microsoft's public keys, verifies the id_token signature, and returns the claims
async fn verify_and_decode_id_token(
    id_token: &str,
    client_id: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    // Decode the JWT header to get the key ID (kid)
    let header = jsonwebtoken::decode_header(id_token)?;
    let kid = header.kid.ok_or("id_token header missing 'kid'")?;
    println!("[Auth] id_token key ID (kid): {}", kid);

    // Fetch Microsoft's public keys
    let client = reqwest::Client::new();
    let jwks: JwksResponse = client.get(JWKS_URL).send().await?.json().await?;

    // Find the matching key
    let jwk = jwks.keys.iter().find(|k| k.kid == kid)
        .ok_or_else(|| format!("No matching key found for kid '{}'", kid))?;

    if jwk.kty != "RSA" {
        return Err(format!("Unsupported key type: {}", jwk.kty).into());
    }

    // Build the RSA public key for verification
    let decoding_key = jsonwebtoken::DecodingKey::from_rsa_components(&jwk.n, &jwk.e)?;

    // Set up validation: verify RS256 signature, audience, and expiry
    // We skip library issuer validation since Microsoft uses tenant-specific issuers
    // (e.g. https://login.microsoftonline.com/{tenant}/v2.0) and verify manually below
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[client_id]);

    // Decode and verify
    let token_data = jsonwebtoken::decode::<serde_json::Value>(
        id_token,
        &decoding_key,
        &validation,
    )?;

    // Manual issuer check: must start with Microsoft's base URL
    if let Some(iss) = token_data.claims.get("iss").and_then(|v| v.as_str()) {
        if !iss.starts_with("https://login.microsoftonline.com/") {
            return Err(format!("Invalid issuer: {}", iss).into());
        }
        println!("[Auth] Issuer verified: {}", iss);
    }

    Ok(token_data.claims)
}