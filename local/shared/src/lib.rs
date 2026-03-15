pub mod auth;
pub mod blob;

/// Platform-specific credential storage (Keychain on macOS, Credential Manager on Windows).
pub trait CredentialStore {
    fn save(&self, token: &str);
    fn load(&self) -> Option<String>;
    fn delete(&self);
}

/// Platform-specific identity provider (Apple Sign In, Microsoft OAuth, etc.).
/// Returns the identity JWT on success.
pub trait IdentityProvider {
    fn login(&self, nonce: &str) -> Result<String, Box<dyn std::error::Error>>;
}

/// Successful login result containing the tokens needed for cloud operations.
pub struct LoginResult {
    pub refresh_token: String,
    pub container_sas_url: String,
}
