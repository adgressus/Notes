use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::Instant;

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use log::info;
use serde::Deserialize;

static JWKS_CACHE: LazyLock<Mutex<HashMap<String, CachedJwks>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Deserialize)]
pub struct Claims {
    pub iss: Option<String>,
    pub nonce: Option<String>,
    pub sub: Option<String>,
}

#[derive(Deserialize)]
struct OidcConfig {
    jwks_uri: String,
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

/// Fetch JWKS signing keys for an OIDC issuer, cached for 1 hour.
fn get_jwks(issuer: &str) -> Option<Vec<Jwk>> {
    // Check cache (refresh every hour)
    {
        let cache = JWKS_CACHE.lock().ok()?;
        if let Some(cached) = cache.get(issuer) {
            if cached.fetched_at.elapsed().as_secs() < 3600 {
                return Some(cached.keys.clone());
            }
        }
    }

    // OIDC discovery
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    info!("Fetching OIDC config from {discovery_url}");

    let resp = ureq::get(&discovery_url).call().ok()?;
    let body = resp.into_body().read_to_string().ok()?;
    let config: OidcConfig = serde_json::from_str(&body).ok()?;

    info!("Fetching JWKS from {}", config.jwks_uri);
    let resp = ureq::get(&config.jwks_uri).call().ok()?;
    let body = resp.into_body().read_to_string().ok()?;
    let jwks: JwksResponse = serde_json::from_str(&body).ok()?;

    if let Ok(mut cache) = JWKS_CACHE.lock() {
        cache.insert(issuer.to_string(), CachedJwks {
            keys: jwks.keys.clone(),
            fetched_at: Instant::now(),
        });
    }

    Some(jwks.keys)
}

/// Extract the issuer from a JWT without verifying the signature.
fn extract_issuer(jwt: &str) -> Result<String, String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let payload = jwt.split('.').nth(1)
        .ok_or_else(|| "Invalid JWT format".to_string())?;
    let bytes = URL_SAFE_NO_PAD.decode(payload)
        .map_err(|e| format!("Failed to decode JWT payload: {e}"))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("Failed to parse JWT payload: {e}"))?;

    value["iss"].as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "JWT missing iss claim".to_string())
}

/// Derive a provider name from an issuer URL.
pub fn issuer_to_provider(issuer: &str) -> &str {
    issuer
        .strip_prefix("https://")
        .or_else(|| issuer.strip_prefix("http://"))
        .and_then(|s| s.split('/').next())
        .unwrap_or(issuer)
}

/// Validate a JWT from any OIDC-compliant provider.
/// Uses the token's `iss` claim for OIDC discovery.
pub fn validate(jwt: &str) -> Result<Claims, String> {
    // Decode header to find which key was used
    let header = decode_header(jwt)
        .map_err(|e| format!("Invalid JWT header: {e}"))?;
    let kid = header.kid
        .ok_or_else(|| "JWT missing kid in header".to_string())?;

    // Extract issuer from unverified payload
    let issuer = extract_issuer(jwt)?;

    // Fetch JWKS via OIDC discovery and find matching key
    let keys = get_jwks(&issuer)
        .ok_or_else(|| "Failed to fetch JWKS".to_string())?;
    let jwk = keys.iter().find(|k| k.kid == kid)
        .ok_or_else(|| format!("No matching key for kid: {kid}"))?;

    let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
        .map_err(|e| format!("Invalid RSA key: {e}"))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    validation.set_issuer(&[&issuer]);

    let token_data = decode::<Claims>(jwt, &decoding_key, &validation)
        .map_err(|e| format!("JWT validation failed: {e}"))?;

    Ok(token_data.claims)
}
