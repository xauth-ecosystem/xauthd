use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(OAuthClients::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(OAuthClients::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(OAuthClients::ClientId).string().not_null().unique_key())
                    .col(ColumnDef::new(OAuthClients::ClientSecret).string().not_null())
                    .col(ColumnDef::new(OAuthClients::RedirectUris).string().not_null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(OAuthClients::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum OAuthClients {
    Table,
    Id,
    ClientId,
    ClientSecret,
    RedirectUris,
}
