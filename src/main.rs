use dotenvy::dotenv;
use sea_orm::Database;
use std::env;
use std::net::SocketAddr;
use tonic::transport::Server;
use tracing::info;

pub mod config;
mod db;
mod grpc_service;
mod hash;
mod jwt;
mod migrator;
mod web;

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

    // Load configuration (xauthd.toml + environment variables)
    let settings = config::Settings::new().unwrap_or_else(|err| {
        // If there's an error and it's missing url, let's provide a default fallback here just in case
        tracing::error!("Failed to load configuration: {}. Falling back to default SQLite...", err);
        config::Settings {
            database: config::DatabaseSettings {
                url: "sqlite://data.sqlite?mode=rwc".to_string()
            }
        }
    });

    let db_url = if settings.database.url.is_empty() {
        "sqlite://data.sqlite?mode=rwc".to_string()
    } else {
        settings.database.url.clone()
    };

    // Connect to Postgres, MySQL or SQLite using SeaORM
    let db = Database::connect(&db_url).await?;

    info!("Applying database migrations...");
    Migrator::up(&db, None).await?;
    info!("Migrations applied successfully.");

    let core_service = XAuthCoreService::new(db.clone());

    let addr: SocketAddr = "0.0.0.0:50051".parse()?;
    
    info!("XAuth Core gRPC listening on {}", addr);

    let grpc_server = Server::builder()
        .add_service(AuthServiceServer::new(core_service))
        .serve(addr);
        
    let web_app = crate::web::router(db.clone());
    let web_listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    info!("XAuth Web Dashboard listening on 0.0.0.0:8080");
    
    let web_server = axum::serve(web_listener, web_app);
    
    let (grpc_res, web_res) = tokio::join!(grpc_server, web_server);
    grpc_res?;
    web_res.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

    Ok(())
}
