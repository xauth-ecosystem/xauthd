pub mod config;
pub mod db;
pub mod grpc_service;
pub mod hash;
pub mod jwt;
pub mod migrator;
pub mod services;
pub mod web;

pub mod xauth_v1 {
    tonic::include_proto!("xauth.v1");
}
