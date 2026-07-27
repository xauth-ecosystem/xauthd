use sea_orm_migration::prelude::*;
use super::m20260727_000001_create_user_table::Users;
use super::m20260727_000003_create_oauth_clients::OAuthClients;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(OAuthTokens::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(OAuthTokens::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(OAuthTokens::ClientId).string().not_null())
                    .col(ColumnDef::new(OAuthTokens::UserId).big_integer().not_null())
                    .col(ColumnDef::new(OAuthTokens::AccessToken).string().not_null().unique_key())
                    .col(ColumnDef::new(OAuthTokens::RefreshToken).string().unique_key())
                    .col(ColumnDef::new(OAuthTokens::ExpiresAt).big_integer().not_null())
                    .col(ColumnDef::new(OAuthTokens::Scopes).string().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-oauth_tokens-client_id")
                            .from(OAuthTokens::Table, OAuthTokens::ClientId)
                            .to(OAuthClients::Table, OAuthClients::ClientId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-oauth_tokens-user_id")
                            .from(OAuthTokens::Table, OAuthTokens::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(OAuthTokens::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum OAuthTokens {
    Table,
    Id,
    ClientId,
    UserId,
    AccessToken,
    RefreshToken,
    ExpiresAt,
    Scopes,
}
