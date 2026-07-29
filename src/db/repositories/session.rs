use sea_orm::entity::prelude::*;
use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};

use crate::db::entities::sessions::{ActiveModel, Column, Entity, Model};

pub struct SessionRepository {
    db: DatabaseConnection,
}

impl SessionRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn create(
        &self,
        user_id: i64,
        token: &str,
        ip: &str,
        expires_in_sec: i64,
    ) -> Result<(), DbErr> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let new_session = ActiveModel {
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

    pub async fn get(&self, token: &str) -> Result<Option<Model>, DbErr> {
        Entity::find()
            .filter(Column::SessionToken.eq(token))
            .one(&self.db)
            .await
    }

    pub async fn delete(&self, token: &str) -> Result<(), DbErr> {
        if let Some(session) = self.get(token).await? {
            Entity::delete_by_id(session.id).exec(&self.db).await?;
        }
        Ok(())
    }
}
