//! Serve reports and screenshots (plain files on disk), proxy knowledge/transcribe.
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path as AxPath, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::authed;
use crate::bridge::bridge_json;
use crate::state::{root, AppState};

#[derive(Deserialize)]
pub struct KQuery {
    q: Option<String>,
}

pub async fn api_knowledge(State(state): State<Arc<AppState>>, headers: HeaderMap, Query(q): Query<KQuery>) -> Response {
    if !authed(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let query = q.q.unwrap_or_default();
    if query.trim().is_empty() {
        return Json(json!({"hits": []})).into_response();
    }
    Json(bridge_json(&["knowledge", &query], None).await).into_response()
}

pub async fn api_transcribe(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    if !authed(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(bridge_json(&["transcribe"], Some(body)).await).into_response()
}

fn valid_report(name: &str) -> bool {
    name.starts_with("metsec-report-")
        && name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_')
}

pub async fn api_reports(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !authed(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let mut rows = vec![];
    let mut dirs: Vec<_> = std::fs::read_dir(root())
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| valid_report(n))
        .collect();
    dirs.sort();
    dirs.reverse();
    for name in dirs {
        let f = root().join(&name).join("findings.json");
        let Ok(text) = std::fs::read_to_string(&f) else { continue };
        let Ok(data) = serde_json::from_str::<Value>(&text) else { continue };
        let meta = data.get("meta").cloned().unwrap_or(json!({}));
        rows.push(json!({
            "name": name,
            "target": meta.get("target").and_then(Value::as_str).unwrap_or("?"),
            "date": meta.get("date").and_then(Value::as_str).unwrap_or(""),
            "cvss": meta.get("overall_cvss").cloned().unwrap_or(json!(0)),
            "count": data.get("findings").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0),
            "has_html": root().join(&name).join("report.html").exists(),
        }));
    }
    Json(json!({"reports": rows})).into_response()
}

pub async fn api_report(State(state): State<Arc<AppState>>, headers: HeaderMap, AxPath(name): AxPath<String>) -> Response {
    if !authed(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !valid_report(&name) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match std::fs::read_to_string(root().join(&name).join("findings.json")) {
        Ok(text) => ([(header::CONTENT_TYPE, "application/json")], text).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

pub async fn report_html(State(state): State<Arc<AppState>>, headers: HeaderMap, AxPath(name): AxPath<String>) -> Response {
    if !authed(&state, &headers) || !valid_report(&name) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match std::fs::read_to_string(root().join(&name).join("report.html")) {
        Ok(html) => ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

pub async fn report_pdf(State(state): State<Arc<AppState>>, headers: HeaderMap, AxPath(name): AxPath<String>) -> Response {
    if !authed(&state, &headers) || !valid_report(&name) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let res = bridge_json(&["pdf", &name], None).await;
    let Some(path) = res.get("path").and_then(Value::as_str) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    match std::fs::read(path) {
        Ok(bytes) => (
            [
                (header::CONTENT_TYPE, "application/pdf".to_string()),
                (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}.pdf\"")),
            ],
            bytes,
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub async fn shot(State(state): State<Arc<AppState>>, headers: HeaderMap, AxPath(id): AxPath<String>) -> Response {
    if !authed(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !id.chars().all(|c| c.is_alphanumeric()) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match std::fs::read(root().join(".metsec_cache/shots").join(format!("{id}.png"))) {
        Ok(bytes) => ([(header::CONTENT_TYPE, "image/png")], bytes).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}
