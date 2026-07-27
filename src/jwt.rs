use std::time::{SystemTime, UNIX_EPOCH};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, errors::Error};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
}

pub fn generate_jwt(username: &str, secret: &str, expiration_seconds: usize) -> Result<String, Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as usize;
        
    let claims = Claims {
        sub: username.to_owned(),
        iat: now,
        exp: now + expiration_seconds,
    };
    
    let header = Header::default();
    encode(&header, &claims, &EncodingKey::from_secret(secret.as_ref()))
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
