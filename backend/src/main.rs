//! Watson backend — thin Axum server.
//!
//! Owns HTTP, session auth, SSE and static serving. Delegates the four
//! Python-only jobs (classify a chat message, run a scan, search the RAG index,
//! transcribe audio) to `python -m watson.bridge`. Reports and screenshots are
//! plain files on disk, served directly. Agent code is untouched.
//!
//! Env: WATSON_WEB_USER / WATSON_WEB_PASS (login, default admin/watson),
//!      WATSON_PYTHON (python for the bridge), WATSON_ROOT (project dir),
//!      WATSON_PORT (default 8787).

mod auth;
mod bridge;
mod files;
mod scan;
mod state;

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use axum::{routing::{get, post}, Router};
use tokio::sync::broadcast;

use state::{root, AppState, RunState};

#[tokio::main]
async fn main() {
    let (tx, _) = broadcast::channel(2048);
    let state = Arc::new(AppState {
        sessions: Mutex::new(HashSet::new()),
        run: Mutex::new(RunState { active: false, events: vec![], info: None, pid: None }),
        tx,
    });

    let app = Router::new()
        .route("/api/login", post(auth::login))
        .route("/api/logout", post(auth::logout))
        .route("/api/chat", post(scan::api_chat))
        .route("/api/stop", post(scan::api_stop))
        .route("/api/status", get(scan::api_status))
        .route("/stream", get(scan::stream))
        .route("/api/knowledge", get(files::api_knowledge))
        .route("/api/transcribe", post(files::api_transcribe))
        .route("/api/reports", get(files::api_reports))
        .route("/api/report/:name", get(files::api_report))
        .route("/api/report/:name/html", get(files::report_html))
        .route("/api/report/:name/pdf", get(files::report_pdf))
        .route("/shot/:id", get(files::shot))
        .fallback_service(tower_http::services::ServeDir::new(root().join("frontend/dist")))
        .with_state(state);

    let port: u16 = std::env::var("WATSON_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8787);
    let addr = format!("127.0.0.1:{port}");
    let user = std::env::var("WATSON_WEB_USER").unwrap_or_else(|_| "admin".into());
    if std::env::var("WATSON_WEB_PASS").unwrap_or_else(|_| "watson".into()) == "watson" {
        eprintln!("⚠️  default web password 'watson' — set WATSON_WEB_PASS to change it");
    }
    println!("  🌐  Watson backend: http://{addr}   (login: {user})");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
