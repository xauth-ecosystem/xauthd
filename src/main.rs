use dotenvy::dotenv;
use sea_orm::Database;
use std::env;
use std::net::SocketAddr;
use tonic::transport::Server;
use tracing::info;

mod db;
mod grpc_service;
mod hash;
mod jwt;
mod migrator;

pub mod xauth_v1 {
    tonic::include_proto!("xauth.v1");
}

use crate::grpc_service::XAuthCoreService;
use crate::xauth_v1::auth_service_server::AuthServiceServer;
use crate::migrator::Migrator;
use sea_orm_migration::MigratorTrait;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    dotenv().ok();

    info!("Starting XAuth Core Daemon...");

    let db_url = env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://data.sqlite?mode=rwc".to_string());
    
    // Connect to Postgres, MySQL or SQLite using SeaORM
    let db = Database::connect(&db_url).await?;

    info!("Applying database migrations...");
    Migrator::up(&db, None).await?;
    info!("Migrations applied successfully.");

    let auth_service = XAuthCoreService::new(db);

    let addr: SocketAddr = "0.0.0.0:50051".parse()?;
    
    info!("gRPC server listening on {}", addr);

    Server::builder()
        .add_service(AuthServiceServer::new(auth_service))
        .serve(addr)
        .await?;

    Ok(())
}
