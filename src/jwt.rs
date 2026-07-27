use std::time::{SystemTime, UNIX_EPOCH};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, errors::Error, Algorithm};
use serde::{Deserialize, Serialize};
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{EncodePrivateKey, DecodePrivateKey}, traits::PublicKeyParts};
use std::fs;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub jti: String,
    pub exp: usize,
    pub iat: usize,
}

pub fn get_or_create_rsa_key() -> RsaPrivateKey {
    if let Ok(pem) = fs::read_to_string("private_key.pem") {
        if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(&pem) {
            return key;
        }
    }
    
    let mut rng = rand_core::OsRng;
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate a key");
    let pem = priv_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).expect("failed to encode key").to_string();
    fs::write("private_key.pem", pem).expect("failed to write key");
    priv_key
}

pub fn get_jwks(priv_key: &RsaPrivateKey) -> serde_json::Value {
    let pub_key = RsaPublicKey::from(priv_key);
    let n = pub_key.n().to_bytes_be();
    let e = pub_key.e().to_bytes_be();
    
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    
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

pub fn generate_jwt(username: &str, secret: &str, expiration_seconds: usize) -> Result<String, Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as usize;
    let jti = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().to_string();
        
    let claims = Claims {
        sub: username.to_owned(),
        jti,
        iat: now,
        exp: now + expiration_seconds,
    };
    
    // We still keep the HS256 function for compatibility with other endpoints (like auth code).
    let header = Header::default();
    encode(&header, &claims, &EncodingKey::from_secret(secret.as_ref()))
}

pub fn generate_rs256_jwt(username: &str, priv_key: &RsaPrivateKey, expiration_seconds: usize) -> Result<String, Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as usize;
    let jti = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().to_string();
        
    let claims = Claims {
        sub: username.to_owned(),
        jti,
        iat: now,
        exp: now + expiration_seconds,
    };
    
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("default".to_string());
    
    let pem = priv_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap().to_string();
    let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
    
    encode(&header, &claims, &encoding_key)
}

pub fn validate_jwt(token: &str, secret: &str) -> Result<Claims, Error> {
    let mut validation = Validation::default();
    validation.leeway = 60; // 1 minute leeway for clock skew
    
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &validation,
    )?;
    
    Ok(token_data.claims)
}
