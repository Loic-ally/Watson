//! Shared server state and project-root resolution.
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Mutex;

use serde_json::Value;
use tokio::sync::broadcast;

pub struct RunState {
    pub active: bool,
    pub events: Vec<Value>, // backlog for late SSE subscribers
    pub info: Option<Value>, // {id,target,mode,status,report}
    pub pid: Option<u32>,   // PID of the running scan bridge, for a graceful stop
}

pub struct AppState {
    pub sessions: Mutex<HashSet<String>>,
    pub run: Mutex<RunState>,
    pub tx: broadcast::Sender<Value>,
}

/// Project directory. Defaults to this crate's parent (resolved at build time) so
/// the binary spawns the bridge correctly from any cwd; override with WATSON_ROOT.
pub fn root() -> PathBuf {
    if let Ok(r) = std::env::var("WATSON_ROOT") {
        return PathBuf::from(r);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(".."))
}
