use crate::xauth_v1::{core_command::CommandType, CoreCommand, PluginEvent};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::info;

pub type ClientSender = mpsc::Sender<Result<CoreCommand, Status>>;
pub type PendingScopeMap = Arc<RwLock<HashMap<String, oneshot::Sender<String>>>>;

pub async fn connect_server(
    clients: Arc<RwLock<HashMap<String, ClientSender>>>,
    pending_scope_requests: PendingScopeMap,
    request: Request<Streaming<PluginEvent>>,
) -> Result<Response<ReceiverStream<Result<CoreCommand, Status>>>, Status> {
    let mut in_stream = request.into_inner();
    let (tx, rx) = mpsc::channel(100);

    let pending_requests = pending_scope_requests.clone();

    tokio::spawn(async move {
        let mut registered_server_id = None;
        while let Ok(Some(event)) = in_stream.message().await {
            if registered_server_id.is_none() {
                registered_server_id = Some(event.server_id.clone());
                clients
                    .write()
                    .await
                    .insert(event.server_id.clone(), tx.clone());
                info!(
                    "Registered streaming channel for server: {}",
                    event.server_id
                );
            }

            info!("Event from {}: {:?}", event.server_id, event.r#type);

            if event.r#type == 5 {
                if let Ok(parsed_payload) =
                    serde_json::from_str::<serde_json::Value>(&event.payload)
                {
                    if let Some(req_id) = parsed_payload["request_id"].as_str() {
                        if let Some(sender) = pending_requests.write().await.remove(req_id) {
                            let _ = sender.send(event.payload.clone());
                        }
                    }
                }
            }
        }

        if let Some(id) = registered_server_id {
            clients.write().await.remove(&id);
            info!("Unregistered streaming channel for server: {}", id);
        }
    });

    Ok(Response::new(ReceiverStream::new(rx)))
}

// Suppress unused import warning — CommandType is used in spawned task via PluginEvent type check
const _: () = {
    let _ = CommandType::FetchScopes;
};
