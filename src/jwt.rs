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

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{Algorithm, DecodingKey, Validation};
    use std::fs;

    #[test]
    fn test_flow_token() {
        let secret = "test_secret";
        let token = generate_flow_token("player1", "login", 1, secret, 3600).unwrap();
        let claims = validate_flow_token(&token, secret).unwrap();

        assert_eq!(claims.sub, "player1");
        assert_eq!(claims.chain, "login");
        assert_eq!(claims.step_index, 1);
    }

    #[test]
    fn test_jwt_token() {
        let secret = "test_secret_jwt";
        let token = generate_jwt("player2", secret, 3600).unwrap();
        let claims = validate_jwt(&token, secret).unwrap();

        assert_eq!(claims.sub, "player2");
        assert!(claims.nonce.is_none());
    }

    #[test]
    fn test_rsa_key_and_rs256_jwt() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let temp_dir = std::env::temp_dir();
        let key_path = temp_dir.join("test_rsa_key.pem");
        let _ = fs::remove_file(&key_path);

        let priv_key = get_or_create_rsa_key(key_path.to_str().unwrap());
        let token =
            generate_rs256_jwt("player3", &priv_key, 3600, Some("my_nonce".to_string())).unwrap();

        let pub_key = RsaPublicKey::from(&priv_key);
        let n = URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be());

        let mut validation = Validation::new(Algorithm::RS256);
        validation.leeway = 60;

        let decoded = decode::<Claims>(
            &token,
            &DecodingKey::from_rsa_components(&n, &e).unwrap(),
            &validation,
        )
        .unwrap();

        assert_eq!(decoded.claims.sub, "player3");
        assert_eq!(decoded.claims.nonce, Some("my_nonce".to_string()));
        let _ = fs::remove_file(&key_path);
    }

    #[test]
    fn test_get_jwks() {
        let mut rng = rand_core::OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let jwks = get_jwks(&priv_key);

        let keys = jwks.get("keys").unwrap().as_array().unwrap();
        assert_eq!(keys.len(), 1);
        let key = &keys[0];
        assert_eq!(key.get("kty").unwrap().as_str().unwrap(), "RSA");
        assert_eq!(key.get("alg").unwrap().as_str().unwrap(), "RS256");
        assert_eq!(key.get("kid").unwrap().as_str().unwrap(), "default");
    }
}
