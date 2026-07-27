use sea_orm::Database;
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
    info!("Starting XAuth Core Daemon...");

    // Load configuration (xauthd.toml)
    let settings = config::Settings::new().unwrap_or_else(|err| {
        tracing::error!("Failed to load configuration: {}. Please check your xauthd.toml.", err);
        std::process::exit(1);
    });

    // Connect to Postgres, MySQL or SQLite using SeaORM
    let db = Database::connect(&settings.database.url).await?;

    info!("Applying database migrations...");
    Migrator::up(&db, None).await?;
    info!("Migrations applied successfully.");

    let core_service = XAuthCoreService::new(db.clone());

    let addr: SocketAddr = settings.network.grpc_address.parse()?;
    
    info!("XAuth Core gRPC listening on {}", addr);

    let grpc_server = Server::builder()
        .add_service(AuthServiceServer::new(core_service))
        .serve(addr);
        
    let web_app = crate::web::router(db.clone());
    let web_listener = tokio::net::TcpListener::bind(&settings.network.web_address).await?;
    info!("XAuth Web Dashboard listening on {}", settings.network.web_address);
    
    let web_server = axum::serve(web_listener, web_app);
    
    let (grpc_res, web_res) = tokio::join!(grpc_server, web_server);
    grpc_res?;
    web_res.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

    Ok(())
}
