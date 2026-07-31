use super::MessageBus;
use crate::transport::grpc::ClientSender;
use crate::xauth_v1::CoreCommand;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct LocalBus {
    clients: Arc<RwLock<HashMap<String, ClientSender>>>,
}

impl LocalBus {
    pub fn new(clients: Arc<RwLock<HashMap<String, ClientSender>>>) -> Self {
        Self { clients }
    }
}

#[tonic::async_trait]
impl MessageBus for LocalBus {
    async fn broadcast(&self, cmd: CoreCommand) -> Result<(), String> {
        let clients_guard = self.clients.read().await;
        for tx in clients_guard.values() {
            // We ignore errors here since if a client disconnected, 
            // the streaming layer handles removing it.
            let _ = tx.send(Ok(cmd.clone())).await;
        }
        Ok(())
    }
}
