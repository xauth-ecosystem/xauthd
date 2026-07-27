use sqlx::{SqlitePool, Error, Row};

pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
}

pub struct UserRepository {
    pool: SqlitePool,
}

impl UserRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn get_user_by_name(&self, username: &str) -> Result<Option<User>, Error> {
        let row = sqlx::query("SELECT id, username, password_hash FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(r) => Ok(Some(User {
                id: r.try_get("id")?,
                username: r.try_get("username")?,
                password_hash: r.try_get("password_hash")?,
            })),
            None => Ok(None),
        }
    }

    pub async fn is_2fa_enabled(&self, user_id: i64) -> Result<bool, Error> {
        let row = sqlx::query("SELECT is_2fa_enabled FROM user_bindings WHERE user_id = ?")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
            
        Ok(row.map(|r| r.try_get("is_2fa_enabled").unwrap_or(false)).unwrap_or(false))
    }

    pub async fn create_user(&self, username: &str, hash: &str) -> Result<(), Error> {
        sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)")
            .bind(username)
            .bind(hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_last_login(&self, user_id: i64, ip: &str) -> Result<(), Error> {
        sqlx::query("UPDATE users SET last_login = CURRENT_TIMESTAMP, last_ip = ? WHERE id = ?")
            .bind(ip)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn increment_failed_attempts(&self, user_id: i64) -> Result<(), Error> {
        sqlx::query("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
