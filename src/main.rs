use sea_orm::Database;
use sea_orm_migration::MigratorTrait;
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::transport::Server;
use tracing::info;
use xauth_core::grpc_service::XAuthCoreService;
use xauth_core::migrator::Migrator;
use xauth_core::xauth_v1::auth_service_server::AuthServiceServer;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Starts the XAuth Core Daemon (gRPC and Web servers)
    Start {
        #[arg(short, long)]
        daemon: bool,
    },
    /// Manually applies database migrations
    Migrate,
    /// Checks the xauthd.toml configuration for errors
    ConfigCheck,
    /// Administrative commands
    Admin {
        #[command(subcommand)]
        admin_cmd: AdminCommands,
    },
}

#[derive(Subcommand)]
enum AdminCommands {
    /// Resets a player's password
    ResetPassword {
        username: String,
        new_password: String,
    },
    /// Unbans a player
    Unban { username: String },
    /// Creates a new OAuth2 Client
    CreateOauthClient {
        #[arg(long)]
        name: String,
        #[arg(long)]
        redirect_uri: String,
    },
}

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
            let rsa_key = Arc::new(xauth_core::jwt::get_or_create_rsa_key(
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

            let web_app =
                xauth_core::web::router(db.clone(), settings_arc, grpc_clients, pending_scopes);

            let web_listener = tokio::net::TcpListener::bind(&settings.network.web_address).await?;
            info!(
                "XAuth Web Dashboard listening on {}",
                settings.network.web_address
            );

            let web_server = axum::serve(web_listener, web_app);

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
            let repo = xauth_core::db::UserRepository::new(db);

            match admin_cmd {
                AdminCommands::ResetPassword {
                    username,
                    new_password,
                } => {
                    if let Some(user) = repo.get_user_by_name(username).await? {
                        let hash = xauth_core::hash::hash_password(
                            new_password,
                            &settings.password_hashing,
                        )
                        .unwrap();
                        repo.update_password(user.id, &hash).await?;
                        info!("Password reset successfully for user '{}'.", username);
                    } else {
                        tracing::error!("User '{}' not found.", username);
                    }
                }
                AdminCommands::Unban { username } => {
                    if let Some(user) = repo.get_user_by_name(username).await? {
                        repo.set_banned(user.id, false).await?;
                        repo.reset_failed_attempts(user.id).await?;
                        info!("User '{}' has been unbanned.", username);
                    } else {
                        tracing::error!("User '{}' not found.", username);
                    }
                }
                AdminCommands::CreateOauthClient { name, redirect_uri } => {
                    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
                    use rand::Rng;

                    let mut id_bytes = [0u8; 16];
                    let mut secret_bytes = [0u8; 32];
                    rand::rng().fill_bytes(&mut id_bytes);
                    rand::rng().fill_bytes(&mut secret_bytes);

                    let client_id = URL_SAFE_NO_PAD.encode(id_bytes);
                    let client_secret = URL_SAFE_NO_PAD.encode(secret_bytes);

                    repo.create_oauth_client(&client_id, &client_secret, redirect_uri)
                        .await?;

                    println!("OAuth2 Client '{}' created successfully!", name);
                    println!("Client ID: {}", client_id);
                    println!("Client Secret: {}", client_secret);
                    println!("Redirect URI: {}", redirect_uri);
                    println!("Keep the Client Secret safe. It cannot be recovered.");
                }
            }
        }
    }

    Ok(())
}
