use sea_orm::entity::prelude::*;
use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};

use crate::db::entities::oauth_tokens::{ActiveModel, Column, Entity, Model};

pub struct OAuthTokenRepository {
    db: DatabaseConnection,
}

impl OAuthTokenRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn create(
        &self,
        client_id: &str,
        user_id: i64,
        access_token: &str,
        refresh_token: Option<&str>,
        expires_in_sec: i64,
        scopes: &str,
    ) -> Result<(), DbErr> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let new_token = ActiveModel {
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

    pub async fn get(&self, token: &str) -> Result<Option<Model>, DbErr> {
        Entity::find()
            .filter(
                sea_orm::Condition::any()
                    .add(Column::AccessToken.eq(token))
                    .add(Column::RefreshToken.eq(token)),
            )
            .one(&self.db)
            .await
    }

    pub async fn delete(&self, token: &str) -> Result<(), DbErr> {
        if let Some(model) = self.get(token).await? {
            Entity::delete_by_id(model.id).exec(&self.db).await?;
        }
        Ok(())
    }
}
