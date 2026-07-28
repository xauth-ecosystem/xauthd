use crate::config::PasswordHashingSettings;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params,
};
use bcrypt::{hash as bcrypt_hash, verify as bcrypt_verify, DEFAULT_COST};

pub fn hash_password(password: &str, config: &PasswordHashingSettings) -> Result<String, String> {
    if config.algorithm.eq_ignore_ascii_case("BCRYPT") {
        let cost = config
            .options
            .as_ref()
            .and_then(|o| o.bcrypt.as_ref())
            .map(|b| b.cost)
            .unwrap_or(DEFAULT_COST);

        bcrypt_hash(password, cost).map_err(|e| format!("Bcrypt hashing error: {}", e))
    } else {
        // Default to Argon2id
        let salt = SaltString::generate(&mut OsRng);

        let argon2 =
            if let Some(Some(argon_opts)) = config.options.as_ref().map(|o| o.argon2id.as_ref()) {
                let params = Params::new(
                    argon_opts.memory_cost,
                    argon_opts.time_cost,
                    argon_opts.threads,
                    None,
                )
                .unwrap_or_default();
                Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
            } else {
                Argon2::default()
            };

        match argon2.hash_password(password.as_bytes(), &salt) {
            Ok(hash) => Ok(hash.to_string()),
            Err(e) => Err(format!("Argon2 hashing error: {}", e)),
        }
    }
}

pub fn verify_password(password: &str, expected_hash: &str) -> bool {
    if expected_hash.starts_with("$2y$")
        || expected_hash.starts_with("$2b$")
        || expected_hash.starts_with("$2a$")
    {
        bcrypt_verify(password, expected_hash).unwrap_or(false)
    } else {
        let parsed_hash = match PasswordHash::new(expected_hash) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let argon2 = Argon2::default();
        argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Argon2idSettings, BcryptSettings, PasswordHashingOptions, PasswordHashingSettings,
    };

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
}
