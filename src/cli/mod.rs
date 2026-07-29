pub mod admin;

use clap::{Parser, Subcommand};
use admin::AdminCommands;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
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
