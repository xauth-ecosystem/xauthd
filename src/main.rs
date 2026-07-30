use clap::Parser;
use sea_orm::Database;
use sea_orm_migration::MigratorTrait;
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::transport::Server;
use tracing::info;
use xauth_core::cli::{Cli, Commands};
use xauth_core::migrator::Migrator;
use xauth_core::transport::grpc::XAuthCoreService;
use xauth_core::xauth_v1::auth_service_server::AuthServiceServer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if let Commands::Start { daemon } = &cli.command {
        if *daemon {
            let stdout = std::fs::File::create("xauthd.out")?;
            let stderr = std::fs::File::create("xauthd.err")?;

            let daemonize = daemonize::Daemonize::new()
                .working_directory(std::env::current_dir()?)
                .stdout(stdout)
                .stderr(stderr);

            match daemonize.start() {
                Ok(_) => println!("Successfully daemonized! Running in background."),
                Err(e) => {
                    eprintln!("Error daemonizing: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }

    tracing_subscriber::fmt::init();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match &cli.command {
        Commands::Start { .. } => {
            info!("Starting XAuth Core Daemon...");

            let settings = xauth_core::config::Settings::new().unwrap_or_else(|err| {
                tracing::error!(
                    "Failed to load configuration: {}. Please check your xauthd.toml.",
                    err
                );
                std::process::exit(1);
            });

            let db = Database::connect(&settings.database.url).await?;

            info!("Applying database migrations...");
            Migrator::up(&db, None).await?;
            info!("Migrations applied successfully.");

            let settings_arc = Arc::new(settings.clone());
            let rsa_key = Arc::new(xauth_core::services::jwt::get_or_create_rsa_key(
                &settings_arc.jwt.rsa_private_key_path,
            ));
            let core_service = XAuthCoreService::new(db.clone(), settings_arc.clone(), rsa_key);

            let grpc_clients = core_service.clients.clone();
            let pending_scopes = core_service.pending_scope_requests.clone();

            let addr: SocketAddr = settings.network.grpc_address.parse()?;
            info!("XAuth Core gRPC listening on {}", addr);

            let grpc_server = Server::builder()
                .add_service(AuthServiceServer::new(core_service))
                .serve(addr);

            let web_app = xauth_core::transport::web::router(
                db.clone(),
                settings_arc,
                grpc_clients,
                pending_scopes,
            );

            let web_listener = tokio::net::TcpListener::bind(&settings.network.web_address).await?;
            info!(
                "XAuth Web Dashboard listening on {}",
                settings.network.web_address
            );

            let web_server = axum::serve(
                web_listener,
                web_app.into_make_service_with_connect_info::<SocketAddr>(),
            );

            let (grpc_res, web_res) = tokio::join!(grpc_server, web_server);
            grpc_res?;
            web_res.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        }
        Commands::Migrate => {
            let settings = xauth_core::config::Settings::new()?;
            let db = Database::connect(&settings.database.url).await?;
            info!("Applying database migrations...");
            Migrator::up(&db, None).await?;
            info!("Migrations applied successfully.");
        }
        Commands::ConfigCheck => match xauth_core::config::Settings::new() {
            Ok(_) => info!("Configuration syntax is valid."),
            Err(e) => tracing::error!("Configuration error: {}", e),
        },
        Commands::Admin { admin_cmd } => {
            let settings = xauth_core::config::Settings::new()?;
            let db = Database::connect(&settings.database.url).await?;
            xauth_core::cli::admin::run(admin_cmd, db).await?;
        }
    }

    Ok(())
}
