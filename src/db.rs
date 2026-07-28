use sea_orm::entity::prelude::*;
use sea_orm::{DatabaseConnection, Set, ActiveModelTrait};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    #[sea_orm(unique)]
    pub username: String,
    pub password_hash: String,
    pub last_ip: Option<String>,
    pub last_login: Option<i64>,
    pub failed_attempts: i32,
    pub last_failed_attempt: Option<i64>,
    pub is_banned: bool,
    pub must_change_password: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

pub mod token_blacklist {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "token_blacklist")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        #[sea_orm(unique)]
        pub token: String,
        pub expires_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod oauth_clients {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "oauth_clients")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        #[sea_orm(unique)]
        pub client_id: String,
        pub client_secret: String,
        pub redirect_uris: String,
        pub allowed_scopes: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod sessions {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "sessions")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub user_id: i64,
        #[sea_orm(unique)]
        pub session_token: String,
        pub ip_address: String,
        pub created_at: i64,
        pub expires_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "crate::db::Entity",
            from = "Column::UserId",
            to = "crate::db::Column::Id",
            on_update = "NoAction",
            on_delete = "Cascade"
        )]
        User,
    }

    impl Related<crate::db::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::User.def()
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod oauth_tokens {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "oauth_tokens")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub client_id: String,
        pub user_id: i64,
        #[sea_orm(unique)]
        pub access_token: String,
        #[sea_orm(unique)]
        pub refresh_token: Option<String>,
        pub expires_at: i64,
        pub scopes: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "crate::db::Entity",
            from = "Column::UserId",
            to = "crate::db::Column::Id",
            on_update = "NoAction",
            on_delete = "Cascade"
        )]
        User,
        #[sea_orm(
            belongs_to = "crate::db::oauth_clients::Entity",
            from = "Column::ClientId",
            to = "crate::db::oauth_clients::Column::ClientId",
            on_update = "NoAction",
            on_delete = "Cascade"
        )]
        OAuthClient,
    }

    impl Related<crate::db::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::User.def()
        }
    }

    impl Related<crate::db::oauth_clients::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::OAuthClient.def()
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

pub struct UserRepository {
    db: DatabaseConnection,
}

impl UserRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn get_user_by_name(&self, username: &str) -> Result<Option<Model>, DbErr> {
        Entity::find()
            .filter(Column::Username.eq(username))
            .one(&self.db)
            .await
    }

    pub async fn is_2fa_enabled(&self, _user_id: i64) -> Result<bool, DbErr> {
        Ok(false)
    }

    pub async fn create_user(&self, username: &str, hash: &str) -> Result<(), DbErr> {
        let new_user = ActiveModel {
            username: Set(username.to_owned()),
            password_hash: Set(hash.to_owned()),
            failed_attempts: Set(0),
            is_banned: Set(false),
            must_change_password: Set(false),
            ..Default::default()
        };
        new_user.insert(&self.db).await?;
        Ok(())
    }

    pub async fn update_last_login(&self, user_id: i64, ip: &str) -> Result<(), DbErr> {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let update = ActiveModel {
            id: Set(user_id),
            last_ip: Set(Some(ip.to_owned())),
            last_login: Set(Some(now)),
            ..Default::default()
        };
        update.update(&self.db).await?;
        Ok(())
    }

    pub async fn increment_failed_attempts(&self, user_id: i64) -> Result<(), DbErr> {
        if let Some(user) = Entity::find_by_id(user_id).one(&self.db).await? {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
            let mut active: ActiveModel = user.into();
            active.failed_attempts = Set(active.failed_attempts.clone().unwrap() + 1);
            active.last_failed_attempt = Set(Some(now));
            active.update(&self.db).await?;
        }
        Ok(())
    }

    pub async fn reset_failed_attempts(&self, user_id: i64) -> Result<(), DbErr> {
        let update = ActiveModel {
            id: Set(user_id),
            failed_attempts: Set(0),
            ..Default::default()
        };
        update.update(&self.db).await?;
        Ok(())
    }

    pub async fn set_must_change_password(&self, user_id: i64, val: bool) -> Result<(), DbErr> {
        let update = ActiveModel {
            id: Set(user_id),
            must_change_password: Set(val),
            ..Default::default()
        };
        update.update(&self.db).await?;
        Ok(())
    }

    pub async fn update_password(&self, user_id: i64, new_hash: &str) -> Result<(), DbErr> {
        let update = ActiveModel {
            id: Set(user_id),
            password_hash: Set(new_hash.to_owned()),
            failed_attempts: Set(0),
            ..Default::default()
        };
        update.update(&self.db).await?;
        Ok(())
    }

    pub async fn set_banned(&self, user_id: i64, val: bool) -> Result<(), DbErr> {
        let update = ActiveModel {
            id: Set(user_id),
            is_banned: Set(val),
            ..Default::default()
        };
        update.update(&self.db).await?;
        Ok(())
    }

    pub async fn blacklist_token(&self, token_jti: &str, expires_at: i64) -> Result<(), DbErr> {
        let new_blacklisted = token_blacklist::ActiveModel {
            token: Set(token_jti.to_owned()),
            expires_at: Set(expires_at),
            ..Default::default()
        };
        new_blacklisted.insert(&self.db).await.ok();
        Ok(())
    }

    pub async fn is_token_blacklisted(&self, token_jti: &str) -> Result<bool, DbErr> {
        let blacklisted = token_blacklist::Entity::find()
            .filter(token_blacklist::Column::Token.eq(token_jti))
            .one(&self.db)
            .await?;
        Ok(blacklisted.is_some())
    }

    pub async fn validate_oauth_client(&self, client_id: &str, client_secret: &str) -> Result<bool, DbErr> {
        let client = oauth_clients::Entity::find()
            .filter(oauth_clients::Column::ClientId.eq(client_id))
            .one(&self.db)
            .await?;
            
        if let Some(c) = client {
            // In a real app, client_secret might be hashed. For now, strict string comparison.
            Ok(c.client_secret == client_secret)
        } else {
            Ok(false)
        }
    }

    pub async fn get_oauth_client(&self, client_id: &str) -> Result<Option<oauth_clients::Model>, DbErr> {
        oauth_clients::Entity::find()
            .filter(oauth_clients::Column::ClientId.eq(client_id))
            .one(&self.db)
            .await
    }

    pub async fn create_oauth_client(&self, client_id: &str, client_secret: &str, redirect_uris: &str) -> Result<(), DbErr> {
        let new_client = oauth_clients::ActiveModel {
            client_id: Set(client_id.to_owned()),
            client_secret: Set(client_secret.to_owned()),
            redirect_uris: Set(redirect_uris.to_owned()),
            ..Default::default()
        };
        new_client.insert(&self.db).await?;
        Ok(())
    }

    pub async fn create_session(&self, user_id: i64, token: &str, ip: &str, expires_in_sec: i64) -> Result<(), DbErr> {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let new_session = sessions::ActiveModel {
            user_id: Set(user_id),
            session_token: Set(token.to_owned()),
            ip_address: Set(ip.to_owned()),
            created_at: Set(now),
            expires_at: Set(now + expires_in_sec),
            ..Default::default()
        };
        new_session.insert(&self.db).await?;
        Ok(())
    }

    pub async fn get_session(&self, token: &str) -> Result<Option<sessions::Model>, DbErr> {
        sessions::Entity::find()
            .filter(sessions::Column::SessionToken.eq(token))
            .one(&self.db)
            .await
    }

    pub async fn delete_session(&self, token: &str) -> Result<(), DbErr> {
        if let Some(session) = self.get_session(token).await? {
            sessions::Entity::delete_by_id(session.id).exec(&self.db).await?;
        }
        Ok(())
    }

    pub async fn create_oauth_token(&self, client_id: &str, user_id: i64, access_token: &str, refresh_token: Option<&str>, expires_in_sec: i64, scopes: &str) -> Result<(), DbErr> {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let new_token = oauth_tokens::ActiveModel {
            client_id: Set(client_id.to_owned()),
            user_id: Set(user_id),
            access_token: Set(access_token.to_owned()),
            refresh_token: Set(refresh_token.map(|s| s.to_owned())),
            expires_at: Set(now + expires_in_sec),
            scopes: Set(scopes.to_owned()),
            ..Default::default()
        };
        new_token.insert(&self.db).await?;
        Ok(())
    }

    pub async fn get_oauth_token(&self, token: &str) -> Result<Option<oauth_tokens::Model>, DbErr> {
        oauth_tokens::Entity::find()
            .filter(
                sea_orm::Condition::any()
                    .add(oauth_tokens::Column::AccessToken.eq(token))
                    .add(oauth_tokens::Column::RefreshToken.eq(token))
            )
            .one(&self.db)
            .await
    }

    pub async fn delete_oauth_token(&self, token: &str) -> Result<(), DbErr> {
        if let Some(model) = self.get_oauth_token(token).await? {
            oauth_tokens::Entity::delete_by_id(model.id).exec(&self.db).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{Database, Schema, ConnectionTrait};

    async fn setup_test_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        let builder = db.get_database_backend();
        let schema = Schema::new(builder);
        
        let stmt = schema.create_table_from_entity(oauth_clients::Entity);
        db.execute(builder.build(&stmt)).await.unwrap();
        
        db
    }

    #[tokio::test]
    async fn test_create_and_get_oauth_client() {
        let db = setup_test_db().await;
        let repo = UserRepository::new(db);

        // Test creating client
        let result = repo.create_oauth_client("client_123", "secret_456", "http://localhost/callback").await;
        assert!(result.is_ok(), "Failed to create OAuth client");
        
        // Test fetching client
        let client = repo.get_oauth_client("client_123").await.unwrap();
        assert!(client.is_some(), "Client not found");
        
        let client = client.unwrap();
        assert_eq!(client.client_id, "client_123");
        assert_eq!(client.client_secret, "secret_456");
        assert_eq!(client.redirect_uris, "http://localhost/callback");
    }
    
    #[tokio::test]
    async fn test_validate_oauth_client() {
        let db = setup_test_db().await;
        let repo = UserRepository::new(db);

        repo.create_oauth_client("client_123", "secret_456", "http://localhost/callback").await.unwrap();
        
        let is_valid = repo.validate_oauth_client("client_123", "secret_456").await.unwrap();
        assert!(is_valid, "Valid credentials should return true");
        
        let is_invalid = repo.validate_oauth_client("client_123", "wrong_secret").await.unwrap();
        assert!(!is_invalid, "Invalid credentials should return false");
        
        let is_non_existent = repo.validate_oauth_client("non_existent", "secret_456").await.unwrap();
        assert!(!is_non_existent, "Non-existent client should return false");
    }
}
