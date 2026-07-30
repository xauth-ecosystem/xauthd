use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use rsa::{traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use xauth_core::services::jwt::{
    generate_flow_token, generate_jwt, generate_rs256_jwt, get_jwks, get_or_create_rsa_key,
    validate_flow_token, validate_jwt, Claims,
};

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
    let key_path = temp_dir.join(format!("test_rsa_key_{}.pem", uuid::Uuid::new_v4()));
    let _ = std::fs::remove_file(&key_path);

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
    let _ = std::fs::remove_file(&key_path);
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
