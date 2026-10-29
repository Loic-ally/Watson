//! Spawns `python -m watson.bridge` for the four Python-only jobs.
use std::process::Stdio;

use axum::body::Bytes;
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::state::root;

fn python() -> String {
    if let Ok(p) = std::env::var("WATSON_PYTHON") {
        return p;
    }
    let venv = root().join(".venv/bin/python");
    if venv.exists() {
        return venv.to_string_lossy().into_owned();
    }
    "python3".into()
}

/// A `python -m watson.bridge` command rooted at the project dir.
pub fn bridge() -> Command {
    let mut c = Command::new(python());
    c.arg("-m").arg("watson.bridge").current_dir(root());
    c
}

/// Run a one-shot bridge command, returning the last stdout line parsed as JSON.
pub async fn bridge_json(args: &[&str], stdin: Option<Bytes>) -> Value {
    let mut cmd = bridge();
    for a in args {
        cmd.arg(a);
    }
    cmd.stdout(Stdio::piped());
    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return json!({"error": format!("spawn failed: {e}")}),
    };
    if let (Some(bytes), Some(mut si)) = (stdin, child.stdin.take()) {
        let _ = si.write_all(&bytes).await;
        drop(si);
    }
    let out = match child.wait_with_output().await {
        Ok(o) => o,
        Err(e) => return json!({"error": format!("wait failed: {e}")}),
    };
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .rev()
        .find_map(|l| serde_json::from_str::<Value>(l.trim()).ok())
        .unwrap_or_else(|| json!({"error": "no json from bridge"}))
}
