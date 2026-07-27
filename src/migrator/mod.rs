use sea_orm_migration::prelude::*;

mod m20260727_000001_create_user_table;
mod m20260727_000002_create_token_blacklist;
mod m20260727_000003_create_oauth_clients;
mod m20260727_000004_create_sessions_table;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260727_000001_create_user_table::Migration),
            Box::new(m20260727_000002_create_token_blacklist::Migration),
            Box::new(m20260727_000003_create_oauth_clients::Migration),
            Box::new(m20260727_000004_create_sessions_table::Migration),
        ]
    }
}
