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
        belongs_to = "crate::db::entities::users::Entity",
        from = "Column::UserId",
        to = "crate::db::entities::users::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    User,
    #[sea_orm(
        belongs_to = "crate::db::entities::oauth_clients::Entity",
        from = "Column::ClientId",
        to = "crate::db::entities::oauth_clients::Column::ClientId",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    OAuthClient,
}

impl Related<crate::db::entities::users::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl Related<crate::db::entities::oauth_clients::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::OAuthClient.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
