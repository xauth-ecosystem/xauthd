use axum::{
    extract::State,
    response::IntoResponse,
    Json,
};
use crate::db::UserRepository;
use crate::xauth_v1::{core_command::CommandType, CoreCommand};
use tokio::sync::oneshot;
use super::state::AppState;

pub async fn user_get(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let repo = UserRepository::new(state.db.clone());

    if let Some(auth_header) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                if let Ok(claims) = crate::jwt::validate_jwt(token, &state.settings.jwt.secret) {
                    if !repo
                        .is_token_blacklisted(&claims.jti)
                        .await
                        .unwrap_or(false)
                    {
                        // 1. Get the original token from DB to find out which scopes were granted
                        let oauth_token = repo.get_oauth_token(token).await.ok().flatten();
                        let granted_scopes = oauth_token.map(|t| t.scopes).unwrap_or_default();

                        let custom_scopes: Vec<&str> = granted_scopes
                            .split_whitespace()
                            .filter(|s| *s != "openid" && *s != "profile")
                            .collect();

                        let mut custom_data = serde_json::Map::new();

                        // 2. If there are custom scopes, ask the game servers via gRPC
                        if !custom_scopes.is_empty() {
                            let request_id = format!(
                                "{}-{}",
                                claims.sub,
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_millis()
                            );
                            let (tx, rx) = oneshot::channel();

                            state
                                .pending_scope_requests
                                .write()
                                .await
                                .insert(request_id.clone(), tx);

                            let payload = serde_json::json!({
                                "request_id": request_id,
                                "scopes": custom_scopes
                            })
                            .to_string();

                            let cmd = CoreCommand {
                                r#type: CommandType::FetchScopes as i32,
                                target_username: claims.sub.clone(),
                                payload,
                            };

                            let clients_guard = state.grpc_clients.read().await;

                            // Broadcast to all connected Minecraft servers
                            for client in clients_guard.values() {
                                let _ = client.send(Ok(cmd.clone())).await;
                            }

                            let has_clients = !clients_guard.is_empty();
                            drop(clients_guard); // Release lock before waiting

                            if has_clients {
                                // Wait for the first Minecraft server to reply (timeout 3s)
                                if let Ok(Ok(payload_str)) =
                                    tokio::time::timeout(std::time::Duration::from_secs(3), rx)
                                        .await
                                {
                                    if let Ok(parsed) =
                                        serde_json::from_str::<serde_json::Value>(&payload_str)
                                    {
                                        if let Some(data_obj) =
                                            parsed.get("data").and_then(|d| d.as_object())
                                        {
                                            custom_data = data_obj.clone();
                                        }
                                    }
                                }
                                // Cleanup if timed out
                                state
                                    .pending_scope_requests
                                    .write()
                                    .await
                                    .remove(&request_id);
                            }
                        }

                        // 3. Build final response
                        let mut response_json = serde_json::json!({
                            "sub": claims.sub.clone(),
                            "preferred_username": claims.sub.clone(),
                            "name": claims.sub
                        });

                        if let Some(obj) = response_json.as_object_mut() {
                            for (k, v) in custom_data {
                                obj.insert(k, v);
                            }
                        }

                        return (axum::http::StatusCode::OK, Json(response_json)).into_response();
                    }
                }
            }
        }
    }
    (
        axum::http::StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error": "invalid_token"})),
    )
        .into_response()
}
