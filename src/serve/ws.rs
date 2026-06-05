//! WebSocket event stream for job updates.

use std::sync::Arc;

use axum::{
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};

use super::app::ServeApp;

pub async fn ws_events(
    ws: WebSocketUpgrade,
    State(app): State<Arc<ServeApp>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_events(socket, app))
}

async fn handle_events(mut socket: WebSocket, app: Arc<ServeApp>) {
    let mut rx = app.job_events.subscribe();
    loop {
        match rx.recv().await {
            Ok(job) => {
                let text = match serde_json::to_string(&job) {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                if socket.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                continue;
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}
