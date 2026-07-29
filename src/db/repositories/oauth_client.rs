use sea_orm::entity::prelude::*;
use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};

use crate::db::entities::oauth_clients::{ActiveModel, Column, Entity, Model};

pub struct OAuthClientRepository {
    db: DatabaseConnection,
}

impl OAuthClientRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn get(&self, client_id: &str) -> Result<Option<Model>, DbErr> {
        Entity::find()
            .filter(Column::ClientId.eq(client_id))
            .one(&self.db)
            .await
    }

    pub async fn validate(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<bool, DbErr> {
        match self.get(client_id).await? {
            Some(c) => Ok(c.client_secret == client_secret),
            None => Ok(false),
        }
    }

    pub async fn create(
        &self,
        client_id: &str,
        client_secret: &str,
        redirect_uris: &str,
    ) -> Result<(), DbErr> {
        let new_client = ActiveModel {
            client_id: Set(client_id.to_owned()),
            client_secret: Set(client_secret.to_owned()),
            redirect_uris: Set(redirect_uris.to_owned()),
            ..Default::default()
        };
        new_client.insert(&self.db).await?;
        Ok(())
    }
}
