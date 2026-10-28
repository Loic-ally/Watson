//! Chat classification + scan streaming (SSE fed from the Python bridge).
use std::process::Stdio;
use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{sse::Event, IntoResponse, Response, Sse},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::auth::authed;
use crate::bridge::{bridge, bridge_json};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct ChatMsg {
    message: String,
}

pub async fn api_chat(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(b): Json<ChatMsg>) -> Response {
    if !authed(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let msg = b.message.trim().to_string();
    if msg.is_empty() {
        return Json(json!({"type": "error", "text": "empty"})).into_response();
    }
    if state.run.lock().unwrap().active {
        return Json(json!({"type": "error", "text": "a scan is already running — wait for it to finish"}))
            .into_response();
    }
    let verdict = bridge_json(&["classify", &msg], None).await;
    match verdict.get("type").and_then(Value::as_str) {
        Some("scan") => {
            let target = verdict.get("target").and_then(Value::as_str).unwrap_or("?").to_string();
            let mode = verdict.get("mode").and_then(Value::as_str).unwrap_or("prod").to_string();
            let exploit = verdict.get("exploit").and_then(Value::as_bool).unwrap_or(false);
            let rid = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
            start_scan(state.clone(), rid.clone(), verdict.clone());
            let text = format!(
                "🚀 Launching {mode} scan on {target}{} — watch it below.",
                if exploit { " (exploit ON)" } else { "" }
            );
            Json(json!({"type": "scan", "rid": rid, "text": text})).into_response()
        }
        _ => {
            let text = verdict.get("text").and_then(Value::as_str).unwrap_or("(no reply)");
            Json(json!({"type": "reply", "text": text})).into_response()
        }
    }
}

/// Spawn the scan bridge, stream its NDJSON into the run buffer + broadcast.
fn start_scan(state: Arc<AppState>, rid: String, verdict: Value) {
    {
        let mut r = state.run.lock().unwrap();
        r.active = true;
        r.events.clear();
        r.info = Some(json!({
            "id": rid,
            "target": verdict.get("target").cloned().unwrap_or(Value::Null),
            "mode": verdict.get("mode").cloned().unwrap_or(Value::Null),
            "status": "running",
            "report": Value::Null,
        }));
    }
    tokio::spawn(async move {
        let params = json!({
            "target": verdict.get("target").cloned().unwrap_or(Value::Null),
            "mode": verdict.get("mode").cloned().unwrap_or(json!("prod")),
            "exploit": verdict.get("exploit").cloned().unwrap_or(json!(false)),
            "budget": verdict.get("budget").cloned().unwrap_or(json!(40)),
            "authorized_by": "operator",
        })
        .to_string();
        let mut child = match bridge().arg("scan").arg(params).stdout(Stdio::piped()).spawn() {
            Ok(c) => c,
            Err(e) => {
                finish_run(&state, None, Some(format!("spawn failed: {e}")));
                return;
            }
        };
        let stdout = child.stdout.take().expect("piped");
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let ev: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if ev.get("type").and_then(Value::as_str) == Some("done") {
                let report = ev.get("report").and_then(Value::as_str).map(String::from);
                let err = ev.get("error").and_then(Value::as_str).map(String::from);
                push_event(&state, ev);
                finish_run(&state, report, err);
                break;
            }
            push_event(&state, ev);
        }
        let _ = child.wait().await;
        // guard: process ended without an explicit done event
        if state.run.lock().unwrap().active {
            finish_run(&state, None, Some("scan ended unexpectedly".into()));
        }
    });
}

fn push_event(state: &AppState, ev: Value) {
    state.run.lock().unwrap().events.push(ev.clone());
    let _ = state.tx.send(ev);
}

fn finish_run(state: &AppState, report: Option<String>, err: Option<String>) {
    let mut r = state.run.lock().unwrap();
    r.active = false;
    if let Some(info) = r.info.as_mut() {
        info["status"] = json!(if err.is_some() { "error" } else { "done" });
        info["report"] = json!(report);
        if let Some(e) = err {
            info["error"] = json!(e);
        }
    }
}

pub async fn api_status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !authed(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let r = state.run.lock().unwrap();
    Json(json!({"active": r.active, "run": r.info})).into_response()
}

pub async fn stream(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !authed(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let backlog = state.run.lock().unwrap().events.clone();
    let mut rx = state.tx.subscribe();
    let s = async_stream::stream! {
        for ev in backlog {
            yield Ok::<Event, std::convert::Infallible>(Event::default().data(ev.to_string()));
        }
        while let Ok(ev) = rx.recv().await {
            yield Ok(Event::default().data(ev.to_string()));
        }
    };
    Sse::new(s).keep_alive(axum::response::sse::KeepAlive::default()).into_response()
}
