use crate::{CredentialStore, IdentityProvider, LoginResult};

#[derive(serde::Deserialize)]
struct GetUrlResponse {
    refresh_token: String,
    url: String,
}

pub struct AuthClient {
    auth_url: String,
}

impl AuthClient {
    pub fn new(auth_url: &str) -> Self {
        Self {
            auth_url: auth_url.trim_end_matches('/').to_string(),
        }
    }

    /// Fetches a nonce from the server, optionally with a link code for account linking.
    pub async fn fetch_nonce(&self, link_code: Option<&str>) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let url = match link_code {
            Some(code) => format!("{}/get_nonce?link_code={}", self.auth_url, code),
            None => format!("{}/get_nonce", self.auth_url),
        };

        let resp = reqwest::get(&url).await?;
        let nonce = resp.text().await?;
        Ok(nonce)
    }

    /// Exchanges an identity JWT (from Apple Sign In, Microsoft OAuth, etc.) for a refresh token.
    pub async fn exchange_token(&self, identity_jwt: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{}/get_token", self.auth_url))
            .body(identity_jwt.to_string())
            .send()
            .await?;

        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            return Err(format!("get_token failed ({}): {}", status, body).into());
        }

        Ok(body)
    }

    /// Exchanges a refresh token for a new refresh token and a container SAS URL.
    pub async fn get_url(&self, refresh_token: &str) -> Result<LoginResult, Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{}/get_url", self.auth_url))
            .body(refresh_token.to_string())
            .send()
            .await?;

        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            return Err(format!("get_url failed ({}): {}", status, body).into());
        }

        let parsed: GetUrlResponse = serde_json::from_str(&body)?;
        Ok(LoginResult {
            refresh_token: parsed.refresh_token,
            container_sas_url: parsed.url,
        })
    }

    /// Full login flow: fetch nonce → platform login → exchange token → get SAS URL.
    /// Retries from the beginning if any step after sign-in fails.
    pub async fn login(
        &self,
        provider: &dyn IdentityProvider,
        store: &dyn CredentialStore,
        link_code: Option<&str>,
    ) -> Option<LoginResult> {
        loop {
            let nonce = match self.fetch_nonce(link_code).await {
                Ok(n) => n,
                Err(_) => return None,
            };

            let identity_jwt = match provider.login(&nonce) {
                Ok(jwt) => jwt,
                Err(_) => return None,
            };

            let refresh_token = match self.exchange_token(&identity_jwt).await {
                Ok(t) => t,
                Err(_) => continue,
            };

            match self.get_url(&refresh_token).await {
                Ok(result) => {
                    store.save(&result.refresh_token);
                    return Some(result);
                }
                Err(_) => continue,
            }
        }
    }

    /// Attempts to restore a session from a saved refresh token.
    /// Returns None if no token is saved or the token is expired.
    pub async fn restore_session(&self, store: &dyn CredentialStore) -> Option<LoginResult> {
        let saved_token = store.load()?;
        match self.get_url(&saved_token).await {
            Ok(result) => {
                store.save(&result.refresh_token);
                Some(result)
            }
            Err(_) => {
                store.delete();
                None
            }
        }
    }
}
