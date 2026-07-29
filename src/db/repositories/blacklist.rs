use sea_orm::entity::prelude::*;
use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};

use crate::db::entities::token_blacklist::{ActiveModel, Column, Entity};

pub struct BlacklistRepository {
    db: DatabaseConnection,
}

impl BlacklistRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn add(&self, token_jti: &str, expires_at: i64) -> Result<(), DbErr> {
        let new_blacklisted = ActiveModel {
            token: Set(token_jti.to_owned()),
            expires_at: Set(expires_at),
            ..Default::default()
        };
        new_blacklisted.insert(&self.db).await.ok();
        Ok(())
    }

    pub async fn is_blacklisted(&self, token_jti: &str) -> Result<bool, DbErr> {
        let blacklisted = Entity::find()
            .filter(Column::Token.eq(token_jti))
            .one(&self.db)
            .await?;
        Ok(blacklisted.is_some())
    }
}
