use sea_orm::entity::prelude::*;
use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};

use crate::db::entities::users::{ActiveModel, Column, Entity, Model};

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

    pub async fn get_user_by_id(&self, user_id: i64) -> Result<Option<Model>, DbErr> {
        Entity::find_by_id(user_id).one(&self.db).await
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
}
