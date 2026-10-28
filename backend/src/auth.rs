//! Session auth: a random cookie token checked against an in-memory set.
use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::state::AppState;

pub fn cookie_token(headers: &HeaderMap) -> Option<String> {
    headers.get(header::COOKIE)?.to_str().ok()?.split(';').find_map(|kv| {
        let (k, v) = kv.trim().split_once('=')?;
        (k == "metsec_session").then(|| v.to_string())
    })
}

pub fn authed(state: &AppState, headers: &HeaderMap) -> bool {
    match cookie_token(headers) {
        Some(t) => state.sessions.lock().unwrap().contains(&t),
        None => false,
    }
}

#[derive(Deserialize)]
pub struct Login {
    user: String,
    password: String,
}

pub async fn login(State(state): State<Arc<AppState>>, Json(b): Json<Login>) -> Response {
    let user = std::env::var("METSEC_WEB_USER").unwrap_or_else(|_| "admin".into());
    let pass = std::env::var("METSEC_WEB_PASS").unwrap_or_else(|_| "metsec".into());
    if b.user == user && b.password == pass {
        let token = uuid::Uuid::new_v4().simple().to_string();
        state.sessions.lock().unwrap().insert(token.clone());
        let cookie = format!("metsec_session={token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=86400");
        ([(header::SET_COOKIE, cookie)], Json(json!({"ok": true}))).into_response()
    } else {
        (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid credentials"}))).into_response()
    }
}

pub async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(t) = cookie_token(&headers) {
        state.sessions.lock().unwrap().remove(&t);
    }
    Json(json!({"ok": true})).into_response()
}
