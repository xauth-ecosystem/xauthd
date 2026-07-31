pub mod local;
pub mod redis;

use crate::xauth_v1::CoreCommand;

#[tonic::async_trait]
pub trait MessageBus: Send + Sync + 'static {
    /// Broadcasts a command to all connected Minecraft servers
    async fn broadcast(&self, cmd: CoreCommand) -> Result<(), String>;
}
