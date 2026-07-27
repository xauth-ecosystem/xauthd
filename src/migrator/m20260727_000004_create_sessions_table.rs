use sea_orm_migration::prelude::*;
use super::m20260727_000001_create_user_table::Users;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Sessions::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Sessions::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Sessions::UserId).big_integer().not_null())
                    .col(ColumnDef::new(Sessions::SessionToken).string().not_null().unique_key())
                    .col(ColumnDef::new(Sessions::IpAddress).string().not_null())
                    .col(ColumnDef::new(Sessions::CreatedAt).big_integer().not_null())
                    .col(ColumnDef::new(Sessions::ExpiresAt).big_integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-sessions-user_id")
                            .from(Sessions::Table, Sessions::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Sessions::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum Sessions {
    Table,
    Id,
    UserId,
    SessionToken,
    IpAddress,
    CreatedAt,
    ExpiresAt,
}
