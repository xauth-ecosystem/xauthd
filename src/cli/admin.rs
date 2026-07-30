use clap::Subcommand;
use sea_orm::DatabaseConnection;

#[derive(Subcommand)]
pub enum AdminCommands {
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

pub async fn run(admin_cmd: &AdminCommands, db: DatabaseConnection) -> Result<(), Box<dyn std::error::Error>> {
    let settings = crate::config::Settings::new()?;
    let repo = crate::db::UserRepository::new(db);

    match admin_cmd {
        AdminCommands::ResetPassword { username, new_password } => {
            if let Some(user) = repo.get_user_by_name(username).await? {
                let hash = crate::hash::hash_password(new_password, &settings.password_hashing).unwrap();
                repo.update_password(user.id, &hash).await?;
                tracing::info!("Password reset successfully for user '{}'.", username);
            } else {
                tracing::error!("User '{}' not found.", username);
            }
        }
        AdminCommands::Unban { username } => {
            if let Some(user) = repo.get_user_by_name(username).await? {
                repo.set_banned(user.id, false).await?;
                repo.reset_failed_attempts(user.id).await?;
                tracing::info!("User '{}' has been unbanned.", username);
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

            repo.create_oauth_client(&client_id, &client_secret, redirect_uri).await?;

            println!("OAuth2 Client '{}' created successfully!", name);
            println!("Client ID: {}", client_id);
            println!("Client Secret: {}", client_secret);
            println!("Redirect URI: {}", redirect_uri);
            println!("Keep the Client Secret safe. It cannot be recovered.");
        }
    }

    Ok(())
}
