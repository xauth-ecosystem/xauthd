use super::MessageBus;
use crate::transport::grpc::ClientSender;
use crate::xauth_v1::CoreCommand;
use fred::prelude::*;
use prost::Message;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct RedisBus {
    client: RedisClient,
}

impl RedisBus {
    pub async fn new(
        url: &str,
        clients: Arc<RwLock<HashMap<String, ClientSender>>>,
    ) -> Result<Self, String> {
        let config = RedisConfig::from_url(url).map_err(|e| e.to_string())?;
        let client = RedisClient::new(config, None, None, None);
        let _ = client.connect();
        client.wait_for_connect().await.map_err(|e| e.to_string())?;

        let sub_client = client.clone();
        let clients_clone = clients.clone();

        tokio::spawn(async move {
            let _ = sub_client.subscribe("xauthd:commands").await;
            let mut pubsub_stream = sub_client.on_message();

            while let Ok(msg) = pubsub_stream.recv().await {
                if let Some(bytes) = msg.value.as_bytes() {
                    if let Ok(cmd) = CoreCommand::decode(bytes) {
                        let clients_guard = clients_clone.read().await;
                        for tx in clients_guard.values() {
                            let _ = tx.send(Ok(cmd.clone())).await;
                        }
                    }
                }
            }
        });

        Ok(Self { client })
    }
}

#[tonic::async_trait]
impl MessageBus for RedisBus {
    async fn broadcast(&self, cmd: CoreCommand) -> Result<(), String> {
        let mut buf = Vec::new();
        cmd.encode(&mut buf);
        self.client
            .publish("xauthd:commands", buf)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}
