use sea_orm::entity::prelude::*;
use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};

use crate::db::entities::oauth_clients as oc_entities;
use crate::db::entities::oauth_tokens as ot_entities;
use crate::db::entities::sessions as s_entities;
use crate::db::entities::users::{ActiveModel, Column, Entity, Model};
use crate::db::repositories::blacklist::BlacklistRepository;
use crate::db::repositories::oauth_client::OAuthClientRepository;
use crate::db::repositories::oauth_token::OAuthTokenRepository;
use crate::db::repositories::session::SessionRepository;

pub struct UserRepository {
    db: DatabaseConnection,
    sessions: SessionRepository,
    oauth_clients: OAuthClientRepository,
    oauth_tokens: OAuthTokenRepository,
    blacklist: BlacklistRepository,
}

impl UserRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        let sessions = SessionRepository::new(db.clone());
        let oauth_clients = OAuthClientRepository::new(db.clone());
        let oauth_tokens = OAuthTokenRepository::new(db.clone());
        let blacklist = BlacklistRepository::new(db.clone());
        Self {
            db,
            sessions,
            oauth_clients,
            oauth_tokens,
            blacklist,
        }
    }

    pub fn db(&self) -> &DatabaseConnection {
        &self.db
    }

    pub fn sessions(&self) -> &SessionRepository {
        &self.sessions
    }

    pub fn oauth_clients(&self) -> &OAuthClientRepository {
        &self.oauth_clients
    }

    pub fn oauth_tokens(&self) -> &OAuthTokenRepository {
        &self.oauth_tokens
    }

    pub fn blacklist(&self) -> &BlacklistRepository {
        &self.blacklist
    }

    pub async fn get_user_by_name(&self, username: &str) -> Result<Option<Model>, DbErr> {
        Entity::find()
            .filter(Column::Username.eq(username))
            .one(&self.db)
            .await
    }

    pub async fn is_2fa_enabled(&self, user_id: i64) -> Result<bool, DbErr> {
        let user = Entity::find_by_id(user_id).one(&self.db).await?;
        Ok(user.map(|u| u.totp_secret.is_some()).unwrap_or(false))
    }

    pub async fn set_totp_secret(&self, user_id: i64, secret: &str) -> Result<(), DbErr> {
        let update = ActiveModel {
            id: Set(user_id),
            totp_secret: Set(Some(secret.to_owned())),
            ..Default::default()
        };
        update.update(&self.db).await?;
        Ok(())
    }

    pub async fn create_user(&self, username: &str, hash: &str) -> Result<i64, DbErr> {
        let new_user = ActiveModel {
            username: Set(username.to_owned()),
            password_hash: Set(hash.to_owned()),
            failed_attempts: Set(0),
            is_banned: Set(false),
            must_change_password: Set(false),
            ..Default::default()
        };
        let result = new_user.insert(&self.db).await?;
        Ok(result.id)
    }

    pub async fn update_last_login(&self, user_id: i64, ip: &str) -> Result<(), DbErr> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
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
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
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
        self.blacklist.add(token_jti, expires_at).await
    }

    pub async fn is_token_blacklisted(&self, token_jti: &str) -> Result<bool, DbErr> {
        self.blacklist.is_blacklisted(token_jti).await
    }

    pub async fn validate_oauth_client(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<bool, DbErr> {
        self.oauth_clients.validate(client_id, client_secret).await
    }

    pub async fn get_oauth_client(
        &self,
        client_id: &str,
    ) -> Result<Option<oc_entities::Model>, DbErr> {
        self.oauth_clients.get(client_id).await
    }

    pub async fn create_oauth_client(
        &self,
        client_id: &str,
        client_secret: &str,
        redirect_uris: &str,
    ) -> Result<(), DbErr> {
        self.oauth_clients
            .create(client_id, client_secret, redirect_uris)
            .await
    }

    pub async fn create_session(
        &self,
        user_id: i64,
        token: &str,
        ip: &str,
        expires_in_sec: i64,
    ) -> Result<(), DbErr> {
        self.sessions.create(user_id, token, ip, expires_in_sec).await
    }

    pub async fn get_session(&self, token: &str) -> Result<Option<s_entities::Model>, DbErr> {
        self.sessions.get(token).await
    }

    pub async fn delete_session(&self, token: &str) -> Result<(), DbErr> {
        self.sessions.delete(token).await
    }

    pub async fn create_oauth_token(
        &self,
        client_id: &str,
        user_id: i64,
        access_token: &str,
        refresh_token: Option<&str>,
        expires_in_sec: i64,
        scopes: &str,
    ) -> Result<(), DbErr> {
        self.oauth_tokens
            .create(client_id, user_id, access_token, refresh_token, expires_in_sec, scopes)
            .await
    }

    pub async fn get_oauth_token(
        &self,
        token: &str,
    ) -> Result<Option<ot_entities::Model>, DbErr> {
        self.oauth_tokens.get(token).await
    }

    pub async fn delete_oauth_token(&self, token: &str) -> Result<(), DbErr> {
        self.oauth_tokens.delete(token).await
    }
}
