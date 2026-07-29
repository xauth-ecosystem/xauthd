use crate::db::UserRepository;
use crate::config::Settings;
use rsa::RsaPrivateKey;
use std::sync::Arc;

pub struct OAuthService {
    repo: UserRepository,
    settings: Arc<Settings>,
    rsa_key: Arc<RsaPrivateKey>,
}

pub struct AuthorizationCodeClaims {
    pub username: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub nonce: String,
}

pub struct TokenRequest {
    pub grant_type: String,
    pub client_id: String,
    pub client_secret: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
}

pub struct IssuedToken {
    pub access_token: String,
    pub refresh_token: String,
    pub id_token: Option<String>,
    pub expires_in: usize,
    pub scopes: String,
}

pub enum TokenError {
    InvalidClient,
    InvalidGrant(String),
    InvalidRequest(String),
}

impl TokenError {
    pub fn code(&self) -> &'static str {
        match self {
            TokenError::InvalidClient => "invalid_client",
            TokenError::InvalidGrant(_) => "invalid_grant",
            TokenError::InvalidRequest(_) => "invalid_request",
        }
    }

    pub fn description(&self) -> String {
        match self {
            TokenError::InvalidClient => String::new(),
            TokenError::InvalidGrant(d) | TokenError::InvalidRequest(d) => d.clone(),
        }
    }
}

pub struct ValidationContext<'a> {
    pub pubkey: &'a rsa::RsaPublicKey,
}

impl OAuthService {
    pub fn new(
        repo: UserRepository,
        settings: Arc<Settings>,
        rsa_key: Arc<RsaPrivateKey>,
    ) -> Self {
        Self {
            repo,
            settings,
            rsa_key,
        }
    }

    pub async fn validate_client(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> bool {
        self.repo
            .validate_oauth_client(client_id, client_secret)
            .await
            .unwrap_or(false)
    }

    pub async fn exchange_authorization_code(
        &self,
        req: &TokenRequest,
    ) -> Result<IssuedToken, TokenError> {
        let code = req
            .code
            .as_ref()
            .ok_or_else(|| TokenError::InvalidRequest("Missing code".into()))?;
        let claims = crate::jwt::validate_jwt(code, &self.settings.jwt.secret)
            .map_err(|_| TokenError::InvalidGrant("Invalid code".into()))?;
        let data: serde_json::Value = serde_json::from_str(&claims.sub)
            .map_err(|_| TokenError::InvalidGrant("Malformed code payload".into()))?;

        let u = data["u"].as_str().unwrap_or_default();
        let c = data["c"].as_str().unwrap_or_default();
        let r = data["r"].as_str().unwrap_or_default();
        let s = data["s"].as_str().unwrap_or("").to_string();
        let cc = data["cc"].as_str().unwrap_or_default();
        let ccm = data["ccm"].as_str().unwrap_or_default();
        let n = data["n"].as_str().unwrap_or_default();
        let req_redirect_uri = req.redirect_uri.as_deref().unwrap_or_default();

        if c != req.client_id || r != req_redirect_uri {
            return Err(TokenError::InvalidGrant("Client mismatch".into()));
        }

        if !cc.is_empty() {
            let verifier = req
                .code_verifier
                .as_deref()
                .ok_or_else(|| TokenError::InvalidRequest("code_verifier required".into()))?;
            let ok = Self::verify_pkce(verifier, cc, ccm);
            if !ok {
                return Err(TokenError::InvalidGrant("Invalid code_verifier".into()));
            }
        }

        let user = self
            .repo
            .get_user_by_name(u)
            .await
            .map_err(|_| TokenError::InvalidGrant("User lookup failed".into()))?
            .ok_or_else(|| TokenError::InvalidGrant("User not found".into()))?;

        let issued = self.issue_tokens(u, &s, n).await?;
        self.repo
            .create_oauth_token(
                &req.client_id,
                user.id,
                &issued.access_token,
                Some(&issued.refresh_token),
                self.settings.jwt.access_token_ttl as i64,
                &issued.scopes,
            )
            .await
            .ok();

        Ok(issued)
    }

    pub async fn exchange_refresh_token(
        &self,
        req: &TokenRequest,
    ) -> Result<IssuedToken, TokenError> {
        let refresh = req
            .refresh_token
            .as_ref()
            .ok_or_else(|| TokenError::InvalidRequest("Missing refresh_token".into()))?;
        let claims = crate::jwt::validate_jwt(refresh, &self.settings.jwt.secret)
            .map_err(|_| TokenError::InvalidGrant("Invalid or expired refresh token".into()))?;

        if self
            .repo
            .is_token_blacklisted(&claims.jti)
            .await
            .unwrap_or(false)
        {
            return Err(TokenError::InvalidGrant(
                "Refresh token has been revoked".into(),
            ));
        }

        let existing = self
            .repo
            .get_oauth_token(refresh)
            .await
            .map_err(|_| TokenError::InvalidGrant("Token lookup failed".into()))?
            .ok_or_else(|| TokenError::InvalidGrant("Refresh token not found".into()))?;

        if existing.client_id != req.client_id {
            return Err(TokenError::InvalidGrant(
                "Refresh token was issued to another client".into(),
            ));
        }

        let username = claims.sub.clone();
        let user = self
            .repo
            .get_user_by_name(&username)
            .await
            .map_err(|_| TokenError::InvalidGrant("User lookup failed".into()))?
            .ok_or_else(|| TokenError::InvalidGrant("User not found".into()))?;

        let issued = self
            .issue_tokens(&username, &existing.scopes, "")
            .await?;

        self.repo.delete_oauth_token(refresh).await.ok();
        self.repo
            .create_oauth_token(
                &req.client_id,
                user.id,
                &issued.access_token,
                Some(&issued.refresh_token),
                self.settings.jwt.access_token_ttl as i64,
                &existing.scopes,
            )
            .await
            .ok();

        Ok(issued)
    }

    pub async fn revoke(&self, token: &str) {
        self.repo.delete_oauth_token(token).await.ok();
        if let Ok(claims) = crate::jwt::validate_jwt(token, &self.settings.jwt.secret) {
            self.repo
                .blacklist_token(&claims.jti, claims.exp as i64)
                .await
                .ok();
        }
    }

    async fn issue_tokens(
        &self,
        username: &str,
        scopes: &str,
        nonce: &str,
    ) -> Result<IssuedToken, TokenError> {
        let access_token = crate::jwt::generate_jwt(
            username,
            &self.settings.jwt.secret,
            self.settings.jwt.access_token_ttl,
        )
        .map_err(|_| TokenError::InvalidGrant("JWT generation failed".into()))?;
        let refresh_token = crate::jwt::generate_jwt(
            username,
            &self.settings.jwt.secret,
            self.settings.jwt.refresh_token_ttl,
        )
        .map_err(|_| TokenError::InvalidGrant("JWT generation failed".into()))?;

        let id_token = if scopes.split_whitespace().any(|s| s == "openid") {
            let nonce_opt = if nonce.is_empty() {
                None
            } else {
                Some(nonce.to_string())
            };
            Some(
                crate::jwt::generate_rs256_jwt(
                    username,
                    &self.rsa_key,
                    self.settings.jwt.access_token_ttl,
                    nonce_opt,
                )
                .map_err(|_| TokenError::InvalidGrant("ID token generation failed".into()))?,
            )
        } else {
            None
        };

        Ok(IssuedToken {
            access_token,
            refresh_token,
            id_token,
            expires_in: self.settings.jwt.access_token_ttl,
            scopes: scopes.to_string(),
        })
    }

    fn verify_pkce(verifier: &str, challenge: &str, method: &str) -> bool {
        if method == "S256" {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(verifier.as_bytes());
            let hash = hasher.finalize();
            let expected = URL_SAFE_NO_PAD.encode(hash);
            expected == challenge
        } else if method == "plain" || method == "plain_text" || method.is_empty() {
            verifier == challenge
        } else {
            false
        }
    }
}

