pub mod cli;
pub mod config;
pub mod db;
pub mod hash;
pub mod jwt;
pub mod migrator;
pub mod services;
pub mod transport;

pub mod xauth_v1 {
    tonic::include_proto!("xauth.v1");
}
