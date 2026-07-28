use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(TokenBlacklist::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(TokenBlacklist::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(TokenBlacklist::Token)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(TokenBlacklist::ExpiresAt)
                            .big_integer()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(TokenBlacklist::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum TokenBlacklist {
    Table,
    Id,
    Token,
    ExpiresAt,
}
