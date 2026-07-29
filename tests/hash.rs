use xauth_core::config::{
    Argon2idSettings, BcryptSettings, PasswordHashingOptions, PasswordHashingSettings,
};
use xauth_core::hash::{hash_password, verify_password};

fn get_bcrypt_settings() -> PasswordHashingSettings {
    PasswordHashingSettings {
        algorithm: "BCRYPT".to_string(),
        options: Some(PasswordHashingOptions {
            bcrypt: Some(BcryptSettings { cost: 4 }),
            argon2id: None,
        }),
    }
}

fn get_argon2_settings() -> PasswordHashingSettings {
    PasswordHashingSettings {
        algorithm: "ARGON2ID".to_string(),
        options: Some(PasswordHashingOptions {
            bcrypt: None,
            argon2id: Some(Argon2idSettings {
                memory_cost: 19456,
                time_cost: 2,
                threads: 1,
            }),
        }),
    }
}

#[test]
fn test_bcrypt_hash_and_verify() {
    let settings = get_bcrypt_settings();
    let password = "SuperSecretPassword123!";

    let hash = hash_password(password, &settings).unwrap();
    assert!(hash.starts_with("$2b$") || hash.starts_with("$2y$") || hash.starts_with("$2a$"));

    let is_valid = verify_password(password, &hash);
    assert!(is_valid, "Bcrypt verification failed for correct password");

    let is_invalid = verify_password("WrongPassword!", &hash);
    assert!(
        !is_invalid,
        "Bcrypt verification succeeded for wrong password"
    );
}

#[test]
fn test_argon2_hash_and_verify() {
    let settings = get_argon2_settings();
    let password = "AnotherSecretPassword456!";

    let hash = hash_password(password, &settings).unwrap();
    assert!(hash.starts_with("$argon2"));

    let is_valid = verify_password(password, &hash);
    assert!(is_valid, "Argon2 verification failed for correct password");

    let is_invalid = verify_password("WrongPassword!", &hash);
    assert!(
        !is_invalid,
        "Argon2 verification succeeded for wrong password"
    );
}
