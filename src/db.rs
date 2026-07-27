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
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

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
            let mut active: ActiveModel = user.into();
            active.failed_attempts = Set(active.failed_attempts.clone().unwrap() + 1);
            active.update(&self.db).await?;
        }
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
}
