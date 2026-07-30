use jsonwebtoken::{
    decode, encode, errors::Error, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use rsa::{
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    traits::PublicKeyParts,
    RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub jti: String,
    pub exp: usize,
    pub iat: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct FlowClaims {
    pub sub: String,
    pub chain: String,
    pub step_index: usize,
    pub exp: usize,
}

/// Generates a short-lived HS256 token that tracks progress through a
/// multi-step auth flow (e.g. the `login` or `register` chains).
///
/// # Examples
///
/// ```
/// use xauth_core::services::jwt::generate_flow_token;
///
/// let token = generate_flow_token("alice", "login", 0, "secret", 600).unwrap();
/// assert!(!token.is_empty());
/// ```
pub fn generate_flow_token(
    username: &str,
    chain: &str,
    step_index: usize,
    secret: &str,
    expiration_seconds: usize,
) -> Result<String, Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let claims = FlowClaims {
        sub: username.to_owned(),
        chain: chain.to_owned(),
        step_index,
        exp: now + expiration_seconds,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
}

/// Validates a token produced by [`generate_flow_token`] and returns its claims.
///
/// Allows 60 seconds of clock leeway; returns an error if the token is expired,
/// malformed, or signed with a different secret.
///
/// # Examples
///
/// ```
/// use xauth_core::services::jwt::{generate_flow_token, validate_flow_token};
///
/// let token = generate_flow_token("alice", "login", 2, "secret", 600).unwrap();
/// let claims = validate_flow_token(&token, "secret").unwrap();
///
/// assert_eq!(claims.sub, "alice");
/// assert_eq!(claims.chain, "login");
/// assert_eq!(claims.step_index, 2);
/// ```
pub fn validate_flow_token(token: &str, secret: &str) -> Result<FlowClaims, Error> {
    let validation = Validation {
        leeway: 60,
        ..Default::default()
    };

    let token_data = decode::<FlowClaims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &validation,
    )?;

    Ok(token_data.claims)
}

/// Loads the RSA private key stored at `path` (PKCS#8 PEM), or generates a new
/// 2048-bit key and writes it to `path` if the file doesn't exist or can't be
/// parsed.
///
/// # Examples
///
/// Not run as a doctest since it reads and writes a real file on disk; the
/// snippet below is checked for compilation only.
///
/// ```no_run
/// use xauth_core::services::jwt::get_or_create_rsa_key;
///
/// let key = get_or_create_rsa_key("/var/lib/xauthd/rsa_key.pem");
/// ```
pub fn get_or_create_rsa_key(path: &str) -> RsaPrivateKey {
    if let Ok(pem) = fs::read_to_string(path) {
        if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(&pem) {
            return key;
        }
    }

    let mut rng = rand_core::OsRng;
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate a key");
    let pem = priv_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .expect("failed to encode key")
        .to_string();
    fs::write(path, pem).expect("failed to write key");
    priv_key
}

/// Builds a JWKS (JSON Web Key Set) document exposing the public half of
/// `priv_key`, suitable for serving at a `/jwks` discovery endpoint.
///
/// # Examples
///
/// ```
/// use rsa::RsaPrivateKey;
/// use xauth_core::services::jwt::get_jwks;
///
/// let mut rng = rand_core::OsRng;
/// let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
///
/// let jwks = get_jwks(&priv_key);
/// assert_eq!(jwks["keys"][0]["kty"], "RSA");
/// assert_eq!(jwks["keys"][0]["alg"], "RS256");
/// ```
pub fn get_jwks(priv_key: &RsaPrivateKey) -> serde_json::Value {
    let pub_key = RsaPublicKey::from(priv_key);
    let n = pub_key.n().to_bytes_be();
    let e = pub_key.e().to_bytes_be();

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    serde_json::json!({
        "keys": [
            {
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": "default",
                "n": URL_SAFE_NO_PAD.encode(n),
                "e": URL_SAFE_NO_PAD.encode(e)
            }
        ]
    })
}

/// Generates an HS256 JWT for `username`, valid for `expiration_seconds`.
///
/// Kept alongside [`generate_rs256_jwt`] for endpoints (like the OAuth
/// authorization code) that don't need asymmetric signing.
///
/// # Examples
///
/// ```
/// use xauth_core::services::jwt::generate_jwt;
///
/// let token = generate_jwt("alice", "secret", 3600).unwrap();
/// assert!(!token.is_empty());
/// ```
pub fn generate_jwt(
    username: &str,
    secret: &str,
    expiration_seconds: usize,
) -> Result<String, Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as usize;
    let jti = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_string();

    let claims = Claims {
        sub: username.to_owned(),
        jti,
        iat: now,
        exp: now + expiration_seconds,
        nonce: None,
    };

    // We still keep the HS256 function for compatibility with other endpoints (like auth code).
    let header = Header::default();
    encode(&header, &claims, &EncodingKey::from_secret(secret.as_ref()))
}

/// Generates an RS256-signed JWT for `username`, optionally embedding an OIDC
/// `nonce`, using the given RSA private key.
///
/// # Examples
///
/// ```
/// use rsa::RsaPrivateKey;
/// use xauth_core::services::jwt::generate_rs256_jwt;
///
/// let mut rng = rand_core::OsRng;
/// let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
///
/// let token = generate_rs256_jwt("alice", &priv_key, 3600, Some("nonce123".into())).unwrap();
/// assert!(!token.is_empty());
/// ```
pub fn generate_rs256_jwt(
    username: &str,
    priv_key: &RsaPrivateKey,
    expiration_seconds: usize,
    nonce: Option<String>,
) -> Result<String, Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as usize;
    let jti = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_string();

    let claims = Claims {
        sub: username.to_owned(),
        jti,
        iat: now,
        exp: now + expiration_seconds,
        nonce,
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("default".to_string());

    let pem = priv_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap()
        .to_string();
    let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();

    encode(&header, &claims, &encoding_key)
}

/// Validates an HS256 token produced by [`generate_jwt`] and returns its claims.
///
/// Allows 60 seconds of clock leeway; returns an error if the token is expired,
/// malformed, or signed with a different secret.
///
/// # Examples
///
/// ```
/// use xauth_core::services::jwt::{generate_jwt, validate_jwt};
///
/// let token = generate_jwt("alice", "secret", 3600).unwrap();
/// let claims = validate_jwt(&token, "secret").unwrap();
///
/// assert_eq!(claims.sub, "alice");
/// assert!(claims.nonce.is_none());
/// ```
pub fn validate_jwt(token: &str, secret: &str) -> Result<Claims, Error> {
    let validation = Validation {
        leeway: 60,
        ..Default::default()
    };

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &validation,
    )?;

    Ok(token_data.claims)
}
